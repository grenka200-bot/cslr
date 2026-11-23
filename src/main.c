#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stribog.h"
#include "kuznyechik.h"
#include "rsa.h"
#include "storage.h"

static void print_usage(const char *prog)
{
    printf("Использование:\n"
           "  1) Регистрация (2FA: создаёт запись в БД и зашифрованный файл ключей):\n"
           "     %s --register --login <имя> --password <пароль> [--keyfile <assets/user.key>] [--db <assets/cslr_db.json>]\n\n"
           "  2) Отправка сообщения (шифрование + ЭЦП отправителя):\n"
           "     %s --login <имя> --password <пароль> [--keyfile <файл>] --send [--to <получатель>] (--kuznyechik | --rsa) --msg \"<текст>\"\n\n"
           "  3) Получение и расшифровка входящих сообщений + проверка ЭЦП:\n"
           "     %s --login <имя> --password <пароль> [--keyfile <файл>] --get --msg\n",
           prog, prog, prog);
}

int main(int argc, char **argv)
{
    int mode_register = 0;
    int mode_send     = 0;
    int mode_get      = 0;
    int algo_kuz      = 0;
    int algo_rsa      = 0;
    int flag_msg      = 0;

    const char *login    = NULL;
    const char *password = NULL;
    const char *to_user  = NULL;
    const char *msg_text = NULL;
    const char *db_path  = "assets/cslr_db.json";
    const char *keyfile  = NULL;
    char default_keyfile[512];

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--register") == 0) {
            mode_register = 1;
        } else if (strcmp(argv[i], "--send") == 0) {
            mode_send = 1;
        } else if (strcmp(argv[i], "--get") == 0) {
            mode_get = 1;
        } else if (strcmp(argv[i], "--kuznyechik") == 0 || strcmp(argv[i], "--kuz") == 0) {
            algo_kuz = 1;
        } else if (strcmp(argv[i], "--rsa") == 0) {
            algo_rsa = 1;
        } else if (strcmp(argv[i], "--login") == 0 && i + 1 < argc) {
            login = argv[++i];
        } else if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
            password = argv[++i];
        } else if (strcmp(argv[i], "--to") == 0 && i + 1 < argc) {
            to_user = argv[++i];
        } else if (strcmp(argv[i], "--keyfile") == 0 && i + 1 < argc) {
            keyfile = argv[++i];
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "--msg") == 0) {
            flag_msg = 1;
            if (i + 1 < argc && strncmp(argv[i + 1], "--", 2) != 0) {
                msg_text = argv[++i];
            }
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "[ошибка] Неизвестный аргумент: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!login || !password) {
        fprintf(stderr, "[ошибка] Необходимо указать --login и --password.\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Если --keyfile не передан явно, используем assets/<login>.key по умолчанию */
    if (!keyfile) {
        snprintf(default_keyfile, sizeof(default_keyfile), "assets/%s.key", login);
        keyfile = default_keyfile;
    }

    /* ==================== 1. РЕГИСТРАЦИЯ ==================== */
    if (mode_register) {
        printf("[1/3] Генерация ключа Кузнечик (256 бит)...\n");
        uint8_t kuz_key[CSLR_KUZNYECHIK_KEY_SIZE];
        if (cslr_kuznyechik_keygen(kuz_key) != 0) {
            fprintf(stderr, "[ошибка] Не удалось сгенерировать ключ Кузнечика.\n");
            return 1;
        }

        printf("[2/3] Генерация пары ключей RSA-32768 для шифрования (ожидайте)...\n");
        fflush(stdout);
       struct cslr_rsa_pub_key enc_pub;
        struct cslr_rsa_priv_key enc_priv;
        if (cslr_rsa_keygen(&enc_pub, &enc_priv) != 0) {
            fprintf(stderr, "[ошибка] Не удалось сгенерировать ключи шифрования RSA.\n");
            return 1;
        }

        printf("[3/3] Генерация пары ключей RSA-32768 для ЭЦП (ожидайте)...\n");
        fflush(stdout);
        struct cslr_rsa_pub_key sign_pub;
        struct cslr_rsa_priv_key sign_priv;
        if (cslr_rsa_keygen(&sign_pub, &sign_priv) != 0) {
            fprintf(stderr, "[ошибка] Не удалось сгенерировать ключи ЭЦП RSA.\n");
            return 1;
        }

        if (cslr_db_register_user(db_path, keyfile, login, password,
                                  &enc_pub, &enc_priv, &sign_pub, &sign_priv, kuz_key) != 0) {
            return 1;
        }

        printf("[OK] Пользователь '%s' зарегистрирован!\n"
               "     Публичные данные сохранены в: %s\n"
               "     Зашифрованный контейнер 2FA: %s\n",
               login, db_path, keyfile);
        return 0;
    }

    /* Для --send и --get требуется 2FA */
    struct cslr_user_public me_pub;
    struct cslr_user_secrets me_secrets;
    if (cslr_db_auth_2fa(db_path, keyfile, login, password, &me_pub, &me_secrets) != 0) {
        return 1;
    }

    /* ==================== 2. ОТПРАВКА СООБЩЕНИЯ ==================== */
    if (mode_send) {
        if (!msg_text || !flag_msg) {
            fprintf(stderr, "[ошибка] Для --send укажите текст через --msg \"<текст>\".\n");
            return 1;
        }
        if (!algo_kuz && !algo_rsa) {
            fprintf(stderr, "[ошибка] Укажите алгоритм шифрования: --kuznyechik или --rsa.\n");
            return 1;
        }

        const char *recipient = to_user ? to_user : login;
        struct cslr_user_public to_pub;
        if (cslr_db_get_public_user(db_path, recipient, &to_pub) != 0) {
            fprintf(stderr, "[ошибка] Получатель '%s' не найден в БД.\n", recipient);
            return 1;
        }

        size_t msg_len = strlen(msg_text);
        uint8_t *ct = NULL;
        size_t ct_len = 0;
        const char *algo_name = NULL;

        if (algo_kuz) {
            algo_name = "kuznyechik";
            size_t max_ct = ((msg_len + 15) / 16) * 16 + 16;
            ct = (uint8_t *)malloc(max_ct);
            if (!ct || cslr_kuznyechik_encrypt(me_pub.kuz_key, (const uint8_t *)msg_text, msg_len, ct, &ct_len) != 0) {
                fprintf(stderr, "[ошибка] Ошибка шифрования Кузнечиком.\n");
                free(ct);
                return 1;
            }
        } else {
            algo_name = "rsa";
            size_t blocks = (msg_len == 0) ? 1 : ((msg_len + CSLR_RSA_KEY_BYTES - 1) / CSLR_RSA_KEY_BYTES);
            size_t max_ct = blocks * CSLR_RSA_KEY_BYTES;
            ct = (uint8_t *)malloc(max_ct);
            if (!ct || cslr_rsa_encrypt(&to_pub.enc_pub, (const uint8_t *)msg_text, msg_len, ct, &ct_len) != 0) {
                fprintf(stderr, "[ошибка] Ошибка шифрования RSA.\n");
                free(ct);
                return 1;
            }
        }

        /* Вычисляем ЭЦП: Streebog-512(msg) -> подпись закрытым ключом отправителя */
        uint8_t msg_hash[CSLR_STREEBOG_512_DIGEST_SIZE];
        uint8_t padded_hash[CSLR_RSA_KEY_BYTES] = {0};
        uint8_t signature[CSLR_RSA_KEY_BYTES];
        size_t sig_len = 0;

        cslr_streebog_512((const uint8_t *)msg_text, msg_len, msg_hash);
        memcpy(padded_hash + (CSLR_RSA_KEY_BYTES - CSLR_STREEBOG_512_DIGEST_SIZE),
        msg_hash, CSLR_STREEBOG_512_DIGEST_SIZE);
        if (cslr_rsa_decrypt(&me_secrets.sign_priv, padded_hash, CSLR_RSA_KEY_BYTES,
                             signature, &sig_len) != 0) {
            fprintf(stderr, "[ошибка] Не удалось сформировать ЭЦП.\n");
            free(ct);
            return 1;
        }

        int rc = cslr_db_push_message(db_path, recipient, login, algo_name, ct, ct_len, signature, sig_len);
        free(ct);
        if (rc != 0) return 1;

        printf("[OK] Сообщение от '%s' -> '%s' зашифровано (%s), подписано ЭЦП и сохранено в БД.\n",
               login, recipient, algo_name);
        return 0;
    }

    /* ==================== 3. ЧТЕНИЕ СООБЩЕНИЙ ==================== */
    if (mode_get) {
        return cslr_db_read_inbox(db_path, login, &me_secrets) == 0 ? 0 : 1;
    }

    fprintf(stderr, "[ошибка] Укажите одно из действий: --register, --send или --get.\n");
    print_usage(argv[0]);
    return 1;
}
 
