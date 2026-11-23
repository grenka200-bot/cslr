#include "storage.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cslr_bytes_to_hex(const uint8_t *src, size_t len, char *dst_hex)
{
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        dst_hex[i * 2]     = hex_chars[(src[i] >> 4) & 0x0F];
        dst_hex[i * 2 + 1] = hex_chars[src[i] & 0x0F];
    }
    dst_hex[len * 2] = '\0';
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int cslr_hex_to_bytes(const char *src_hex, uint8_t *dst, size_t expected_len)
{
    if (!src_hex || !dst) return -1;
    if (strlen(src_hex) != expected_len * 2) return -1;
    for (size_t i = 0; i < expected_len; i++) {
        int hi = hex_val(src_hex[i * 2]);
        int lo = hex_val(src_hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        dst[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static char *read_text_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

static int write_text_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t len = strlen(text);
    int rc = (fwrite(text, 1, len, f) == len) ? 0 : -1;
    fclose(f);
    return rc;
}

static cJSON *load_or_init_db(const char *db_path)
{
    char *raw = read_text_file(db_path);
    if (!raw) {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "users", cJSON_CreateArray());
        return root;
    }
    cJSON *root = cJSON_Parse(raw);
    free(raw);
    if (!root) return NULL;
    if (!cJSON_GetObjectItem(root, "users")) {
        cJSON_AddItemToObject(root, "users", cJSON_CreateArray());
    }
    return root;
}

static int save_db(const char *db_path, cJSON *root)
{
    char *printed = cJSON_Print(root);
    if (!printed) return -1;
    int rc = write_text_file(db_path, printed);
    free(printed);
    return rc;
}

static int save_encrypted_keyfile(const char *keyfile_path,
                                const uint8_t kuz_key[CSLR_KUZNYECHIK_KEY_SIZE],
                                const struct cslr_user_secrets *secrets)
{
    const size_t plain_len = CSLR_CONTAINER_MAGIC_LEN + sizeof(struct cslr_user_secrets);
    uint8_t *plain = (uint8_t *)malloc(plain_len);
    uint8_t *cipher = (uint8_t *)malloc(plain_len + CSLR_KUZNYECHIK_BLOCK_SIZE);
    if (!plain || !cipher) {
        free(plain); free(cipher);
        return -1;
    }

    memcpy(plain, CSLR_CONTAINER_MAGIC, CSLR_CONTAINER_MAGIC_LEN);
    memcpy(plain + CSLR_CONTAINER_MAGIC_LEN, secrets, sizeof(struct cslr_user_secrets));

    size_t ct_len = 0;
    if (cslr_kuznyechik_encrypt(kuz_key, plain, plain_len, cipher, &ct_len) != 0) {
        free(plain); free(cipher);
        return -1;
    }

    FILE *f = fopen(keyfile_path, "wb");
    int rc = -1;
    if (f) {
        if (fwrite(cipher, 1, ct_len, f) == ct_len) rc = 0;
        fclose(f);
    }

    memset(plain, 0, plain_len);
    free(plain);
    free(cipher);
    return rc;
}

static int load_encrypted_keyfile(const char *keyfile_path,
                                const uint8_t kuz_key[CSLR_KUZNYECHIK_KEY_SIZE],
                                struct cslr_user_secrets *secrets_out)
{
    FILE *f = fopen(keyfile_path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    const size_t expected_plain = CSLR_CONTAINER_MAGIC_LEN + sizeof(struct cslr_user_secrets);
    if (sz < (long)expected_plain || (sz % CSLR_KUZNYECHIK_BLOCK_SIZE) != 0) {
        fclose(f);
        return -1;
    }

    uint8_t *cipher = (uint8_t *)malloc((size_t)sz);
    uint8_t *plain  = (uint8_t *)malloc((size_t)sz);
    if (!cipher || !plain) {
        free(cipher); free(plain); fclose(f);
        return -1;
    }

    if (fread(cipher, 1, (size_t)sz, f) != (size_t)sz) {
        free(cipher); free(plain); fclose(f);
        return -1;
    }
    fclose(f);

    if (cslr_kuznyechik_decrypt(kuz_key, cipher, (size_t)sz, plain) != 0) {
        free(cipher); free(plain);
        return -1;
    }

    if (memcmp(plain, CSLR_CONTAINER_MAGIC, CSLR_CONTAINER_MAGIC_LEN) != 0) {
        memset(plain, 0, (size_t)sz);
        free(cipher); free(plain);
        return -1;
    }

    memcpy(secrets_out, plain + CSLR_CONTAINER_MAGIC_LEN, sizeof(struct cslr_user_secrets));
    memset(plain, 0, (size_t)sz);
    free(cipher);
    free(plain);
    return 0;
}

static void add_hex_field(cJSON *obj, const char *name, const uint8_t *data, size_t len)
{
    char *hex = (char *)malloc(len * 2 + 1);
    if (!hex) return;
    cslr_bytes_to_hex(data, len, hex);
    cJSON_AddStringToObject(obj, name, hex);
    free(hex);
}

static int parse_user_json(const cJSON *u, struct cslr_user_public *out)
{
    const cJSON *j_login = cJSON_GetObjectItem(u, "login");
    const cJSON *j_phash = cJSON_GetObjectItem(u, "password_hash");
    const cJSON *j_kuz   = cJSON_GetObjectItem(u, "kuz_key");
    const cJSON *j_en    = cJSON_GetObjectItem(u, "enc_pub_n");
    const cJSON *j_ee    = cJSON_GetObjectItem(u, "enc_pub_e");
    const cJSON *j_sn    = cJSON_GetObjectItem(u, "sign_pub_n");
    const cJSON *j_se    = cJSON_GetObjectItem(u, "sign_pub_e");

    if (!cJSON_IsString(j_login) || !cJSON_IsString(j_phash) || !cJSON_IsString(j_kuz) ||
        !cJSON_IsString(j_en) || !cJSON_IsString(j_ee) ||
        !cJSON_IsString(j_sn) || !cJSON_IsString(j_se)) {
        return -1;
    }

    strncpy(out->login, j_login->valuestring, sizeof(out->login) - 1);
    out->login[sizeof(out->login) - 1] = '\0';

    if (cslr_hex_to_bytes(j_phash->valuestring, out->password_hash, CSLR_STREEBOG_512_DIGEST_SIZE) != 0) return -1;
    if (cslr_hex_to_bytes(j_kuz->valuestring, out->kuz_key, CSLR_KUZNYECHIK_KEY_SIZE) != 0) return -1;
    if (cslr_hex_to_bytes(j_en->valuestring, out->enc_pub.n, CSLR_RSA_KEY_BYTES) != 0) return -1;
    if (cslr_hex_to_bytes(j_ee->valuestring, out->enc_pub.e, CSLR_RSA_KEY_BYTES) != 0) return -1;
    if (cslr_hex_to_bytes(j_sn->valuestring, out->sign_pub.n, CSLR_RSA_KEY_BYTES) != 0) return -1;
    if (cslr_hex_to_bytes(j_se->valuestring, out->sign_pub.e, CSLR_RSA_KEY_BYTES) != 0) return -1;

    return 0;
}

int cslr_db_register_user(const char *db_path,
                          const char *keyfile_path,
                          const char *login,
                          const char *password,
                          const struct cslr_rsa_pub_key *enc_pub,
                          const struct cslr_rsa_priv_key *enc_priv,
                          const struct cslr_rsa_pub_key *sign_pub,
                          const struct cslr_rsa_priv_key *sign_priv,
                          const uint8_t kuz_key[CSLR_KUZNYECHIK_KEY_SIZE])
{
    cJSON *root = load_or_init_db(db_path);
    if (!root) return -1;

    cJSON *users = cJSON_GetObjectItem(root, "users");
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, users) {
        cJSON *jl = cJSON_GetObjectItem(item, "login");
        if (cJSON_IsString(jl) && strcmp(jl->valuestring, login) == 0) {
            fprintf(stderr, "[ошибка] Пользователь '%s' уже существует в БД.\n", login);
            cJSON_Delete(root);
            return -1;
        }
    }

    uint8_t pass_hash[CSLR_STREEBOG_512_DIGEST_SIZE];
    if (cslr_streebog_512((const uint8_t *)password, strlen(password), pass_hash) != 0) {
        cJSON_Delete(root);
        return -1;
    }

    struct cslr_user_secrets secrets;
    secrets.enc_priv  = *enc_priv;
    secrets.sign_priv = *sign_priv;
    if (save_encrypted_keyfile(keyfile_path, pass_hash, &secrets) != 0) {
        fprintf(stderr, "[ошибка] Не удалось записать ключевой файл '%s'.\n", keyfile_path);
        cJSON_Delete(root);
        return -1;
    }

    cJSON *u = cJSON_CreateObject();
    cJSON_AddStringToObject(u, "login", login);
    add_hex_field(u, "password_hash", pass_hash, CSLR_STREEBOG_512_DIGEST_SIZE);
    add_hex_field(u, "kuz_key", kuz_key, CSLR_KUZNYECHIK_KEY_SIZE);
    add_hex_field(u, "enc_pub_n", enc_pub->n, CSLR_RSA_KEY_BYTES);
    add_hex_field(u, "enc_pub_e", enc_pub->e, CSLR_RSA_KEY_BYTES);
    add_hex_field(u, "sign_pub_n", sign_pub->n, CSLR_RSA_KEY_BYTES);
    add_hex_field(u, "sign_pub_e", sign_pub->e, CSLR_RSA_KEY_BYTES);
    cJSON_AddItemToObject(u, "inbox", cJSON_CreateArray());

    cJSON_AddItemToArray(users, u);

    int rc = save_db(db_path, root);
    cJSON_Delete(root);
    return rc;
}

int cslr_db_get_public_user(const char *db_path,
                            const char *login,
                            struct cslr_user_public *pub_out)
{
    cJSON *root = load_or_init_db(db_path);
    if (!root) return -1;

    cJSON *users = cJSON_GetObjectItem(root, "users");
    cJSON *item = NULL;
    int rc = -1;
    cJSON_ArrayForEach(item, users) {
        cJSON *jl = cJSON_GetObjectItem(item, "login");
        if (cJSON_IsString(jl) && strcmp(jl->valuestring, login) == 0) {
            rc = parse_user_json(item, pub_out);
            break;
        }
    }
    cJSON_Delete(root);
    return rc;
}

int cslr_db_auth_2fa(const char *db_path,
                     const char *keyfile_path,
                     const char *login,
                     const char *password,
                     struct cslr_user_public *pub_out,
                     struct cslr_user_secrets *secrets_out)
{
    if (cslr_db_get_public_user(db_path, login, pub_out) != 0) {
        fprintf(stderr, "[2FA] Пользователь '%s' не найден в БД.\n", login);
        return -1;
    }

    uint8_t pass_hash[CSLR_STREEBOG_512_DIGEST_SIZE];
    if (cslr_streebog_512((const uint8_t *)password, strlen(password), pass_hash) != 0) {
        return -1;
    }

    if (memcmp(pass_hash, pub_out->password_hash, CSLR_STREEBOG_512_DIGEST_SIZE) != 0) {
        fprintf(stderr, "[2FA ОШИБКА] Фактор 1 (пароль) неверен!\n");
        return -1;
    }

    if (load_encrypted_keyfile(keyfile_path, pass_hash, secrets_out) != 0) {
        fprintf(stderr, "[2FA ОШИБКА] Фактор 2 (ключевой файл '%s') отсутствует, повреждён или не подходит к паролю!\n",
                keyfile_path);
        return -1;
    }

    return 0;
}

int cslr_db_push_message(const char *db_path,
                         const char *to_login,
                         const char *from_login,
                         const char *algo,
                         const uint8_t *ciphertext, size_t ct_len,
                         const uint8_t *signature, size_t sig_len)
{
    cJSON *root = load_or_init_db(db_path);
    if (!root) return -1;

    cJSON *users = cJSON_GetObjectItem(root, "users");
    cJSON *target = NULL;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, users) {
        cJSON *jl = cJSON_GetObjectItem(item, "login");
        if (cJSON_IsString(jl) && strcmp(jl->valuestring, to_login) == 0) {
            target = item;
            break;
        }
    }

    if (!target) {
        fprintf(stderr, "[ошибка] Получатель '%s' не найден.\n", to_login);
        cJSON_Delete(root);
        return -1;
    }

    cJSON *inbox = cJSON_GetObjectItem(target, "inbox");
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddStringToObject(msg, "from", from_login);
    cJSON_AddStringToObject(msg, "algo", algo);
    add_hex_field(msg, "ciphertext", ciphertext, ct_len);
    add_hex_field(msg, "signature", signature, sig_len);

    cJSON_AddItemToArray(inbox, msg);

    int rc = save_db(db_path, root);
    cJSON_Delete(root);
    return rc;
}

int cslr_db_read_inbox(const char *db_path,
                       const char *login,
                       const struct cslr_user_secrets *secrets)
{
    cJSON *root = load_or_init_db(db_path);
    if (!root) return -1;

    cJSON *users = cJSON_GetObjectItem(root, "users");
    cJSON *target = NULL;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, users) {
        cJSON *jl = cJSON_GetObjectItem(item, "login");
        if (cJSON_IsString(jl) && strcmp(jl->valuestring, login) == 0) {
            target = item;
            break;
        }
    }

    if (!target) {
        cJSON_Delete(root);
        return -1;
    }

    cJSON *inbox = cJSON_GetObjectItem(target, "inbox");
    int count = cJSON_GetArraySize(inbox);
    printf("=== Входящие сообщения для '%s' (всего: %d) ===\n", login, count);

    int idx = 0;
    cJSON *m = NULL;
    cJSON_ArrayForEach(m, inbox) {
        idx++;
        const cJSON *j_from = cJSON_GetObjectItem(m, "from");
        const cJSON *j_algo = cJSON_GetObjectItem(m, "algo");
        const cJSON *j_ct   = cJSON_GetObjectItem(m, "ciphertext");
        const cJSON *j_sig  = cJSON_GetObjectItem(m, "signature");

        if (!cJSON_IsString(j_from) || !cJSON_IsString(j_algo) ||
            !cJSON_IsString(j_ct)   || !cJSON_IsString(j_sig)) {
            continue;
        }

        const char *from_login = j_from->valuestring;
        const char *algo       = j_algo->valuestring;
        const char *ct_hex     = j_ct->valuestring;
        const char *sig_hex    = j_sig->valuestring;

        size_t ct_len = strlen(ct_hex) / 2;
        uint8_t *ct   = (uint8_t *)malloc(ct_len);
        uint8_t *pt   = (uint8_t *)calloc(ct_len + 1, 1);
        uint8_t sig[CSLR_RSA_KEY_BYTES];

        if (!ct || !pt ||
            cslr_hex_to_bytes(ct_hex, ct, ct_len) != 0 ||
            cslr_hex_to_bytes(sig_hex, sig, CSLR_RSA_KEY_BYTES) != 0) {
            free(ct); free(pt);
            continue;
        }

        printf("\n[#%d] От: %s | Алгоритм: %s\n", idx, from_login, algo);
        printf("  Зашифрованный вид (HEX): %s\n", ct_hex);

        struct cslr_user_public sender_pub;
        int has_sender = (cslr_db_get_public_user(db_path, from_login, &sender_pub) == 0);

        char *plain_str = NULL;
        int dec_ok = 0;

        if (strcmp(algo, "kuznyechik") == 0) {
            if (has_sender && cslr_kuznyechik_decrypt(sender_pub.kuz_key, ct, ct_len, pt) == 0) {
                plain_str = (char *)pt;
                dec_ok = 1;
            }
        } else if (strcmp(algo, "rsa") == 0) {
            size_t out_len = 0;
            if (cslr_rsa_decrypt(&secrets->enc_priv, ct, ct_len, pt, &out_len) == 0) {
                size_t offset = 0;
                while (offset < out_len && pt[offset] == 0x00) {
                    offset++;
                }
                plain_str = (char *)(pt + offset);
                dec_ok = 1;
            }
        }

        if (dec_ok && plain_str) {
            printf("  Расшифровка:             \"%s\"\n", plain_str);

            if (has_sender) {
                uint8_t expected_hash[CSLR_STREEBOG_512_DIGEST_SIZE];
                uint8_t recovered_block[CSLR_RSA_KEY_BYTES];
                size_t rec_len = 0;

                cslr_streebog_512((const uint8_t *)plain_str, strlen(plain_str), expected_hash);
                if (cslr_rsa_encrypt(&sender_pub.sign_pub, sig, CSLR_RSA_KEY_BYTES,
                                     recovered_block, &rec_len) == 0 &&
                    rec_len == CSLR_RSA_KEY_BYTES &&
                    memcmp(expected_hash,
                           recovered_block + (CSLR_RSA_KEY_BYTES - CSLR_STREEBOG_512_DIGEST_SIZE),
                           CSLR_STREEBOG_512_DIGEST_SIZE) == 0) {
                    printf("  Проверка ЭЦП:            ВАЛИДНА (подпись '%s' подтверждена)\n", from_login);
                } else {
                    printf("  Проверка ЭЦП:            НЕВАЛИДНА! Внимание: подпись не совпадает!\n");
                }
            }
        } else {
            printf("  [ошибка расшифровки сообщения]\n");
        }

        free(ct);
        free(pt);
    }

    cJSON_Delete(root);
    return 0;
}

