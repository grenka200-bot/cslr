/**
 * @file main.c
 * @brief Центральная точка входа криптографической утилиты cslr.
 * @details Реализует парсинг CLI аргументов, авторизацию через INI и слепую маршрутизацию шифров.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "users.h"
#include "key_parser/key_struct.h"
#include "key_parser/key_pars_api.h"
#include "algo/kuznyechik.h"
#include "algo/rsa.h"

#define CSLR_MAX_CREDENTIAL_LEN 64

int main(int argc, char **argv) {
    bool force = false;
    bool encrypt = false;
    const char *key_path = NULL;
    const char *out_path = NULL;
    const char *message = NULL;

    struct parsed_key pkey = {0};

    /* 1. Побайтовый ручной парсинг CLI аргументов из argv */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--force") == 0) {
            force = true;
        } else if (strcmp(argv[i], "--encrypt") == 0) {
            encrypt = true;
        } else if (strcmp(argv[i], "--by") == 0) {
            if (i + 1 < argc) key_path = argv[++i];
        } else if (strcmp(argv[i], "--out") == 0) {
            if (i + 1 < argc) out_path = argv[++i];
        } else if (strcmp(argv[i], "--message") == 0) {
            if (i + 1 < argc) message = argv[++i];
        }
    }

    /* 2. Стадия авторизации пользователей (пропускается, если взведен --force) */
    if (!force) {
        char input_user[CSLR_MAX_CREDENTIAL_LEN] = {0};
        char input_pass[CSLR_MAX_CREDENTIAL_LEN] = {0};

        printf("Логин: ");
        if (scanf("%63s", input_user) != 1) {
            return -1;
        }
        printf("Пароль: ");
        if (scanf("%63s", input_pass) != 1) {
            return -1;
        }

        /* Вызов проверки через INI-парсер в users.c (0 - успех, -1 - ошибка) */
        if (cslr_authenticate_user(input_user, input_pass) != 0) {
            printf("Ошибка: Доступ запрещен.\n");
            return -1;
        }
        printf("Авторизация успешна. Добро пожаловать, %s!\n", input_user);
    }

    /* 3. Валидация контекста выполнения */
    if (!encrypt) {
        printf("Ошибка: Не указано действие (требуется флаг --encrypt).\n");
        return -1;
    }
    if (!key_path || !out_path || !message) {
        printf("Ошибка: Не все критические параметры утилиты указаны (--by, --out, --message).\n");
        return -1;
    }

    /* 4. Автоматическая загрузка и слепой парсинг бинарного DER-контейнера */
    if (cslr_load_and_parse_key(key_path, &pkey) != 0) {
        printf("Ошибка: Не удалось загрузить или десериализовать файл ключа.\n");
        return -1;
    }

    /* 5. Главный универсальный switch маршрутизации шифров (Слепое исполнение) */
    switch (pkey.type) {
        case KEY_TYPE_SYMMETRIC:
            /* Проверяем, принадлежит ли извлеченный OID Кузнечику */
            if (cslr_is_kuznyechik_oid(pkey.oid, pkey.oid_len) == 0) {
                printf("Обнаружен ключ алгоритма: ГОСТ Р 34.12-2015 «Кузнечик»\n");
                printf("Запуск поблочного шифрования ECB...\n");
                
                if (cslr_kuznyechik_ecb_encrypt(message, pkey.key_data.symmetric.secret_bytes, out_path) != 0) {
                    printf("Ошибка: Криптографический сбой при шифровании Кузнечиком.\n");
                    return -1;
                }
            } else {
                printf("Ошибка: Извлеченный �имметричный OID не поддерживается данной версией утилиты.\n");
                return -1;
            }
            break;

        case KEY_TYPE_ASYMMETRIC:
            /* Проверяем, принадлежит ли извлеченный OID алгоритму RSA */
            if (cslr_is_rsa_oid(pkey.oid, pkey.oid_len) == 0) {
                printf("Обнаружен ключ алгоритма: RSA (Поддержка диких ключей до 4096 байт)\n");
                printf("Запуск асимметричного BigInt шифрования...\n");

                if (cslr_rsa_encrypt(message, 
                                     pkey.key_data.asymmetric.n_modulus, pkey.key_data.asymmetric.n_len,
                                     pkey.key_data.asymmetric.e_exponent, pkey.key_data.asymmetric.e_len,
                                     out_path) != 0) {
                    printf("Ошибка: Криптографический сбой при шифровании RSA.\n");
                    return -1;
                }
            } else {
                printf("Ошибка: Извлеченный асимметричный OID не поддерживается данной версией утилиты.\n");
                return -1;
            }
            break;

        default:
            printf("Ошибка: Неизвестный или поврежденный тип криптосистемы в контейнере ключа.\n");
            return -1;
    }

    printf("Операция шифрования успешно завершена. Бинарный шифротекст сохранен в: %s\n", out_path);
    return 0;
}

