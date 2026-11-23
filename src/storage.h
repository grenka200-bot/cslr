#pragma once

#include <stddef.h>
#include <stdint.h>
#include "rsa.h"
#include "kuznyechik.h"
#include "stribog.h"

#define CSLR_CONTAINER_MAGIC "CSLR_OK!"
#define CSLR_CONTAINER_MAGIC_LEN 8

/** Расшифрованные секреты пользователя, загружаемые из *.key (2-й фактор) */
struct cslr_user_secrets {
    struct cslr_rsa_priv_key enc_priv;
    struct cslr_rsa_priv_key sign_priv;
};

/** Открытый профиль пользователя из cslr_db.json */
struct cslr_user_public {
    char login[128];
    uint8_t password_hash[CSLR_STREEBOG_512_DIGEST_SIZE];
    uint8_t kuz_key[CSLR_KUZNYECHIK_KEY_SIZE];
    struct cslr_rsa_pub_key enc_pub;
    struct cslr_rsa_pub_key sign_pub;
};

/** Вспомогательные функции HEX */
void cslr_bytes_to_hex(const uint8_t *src, size_t len, char *dst_hex);
int  cslr_hex_to_bytes(const char *src_hex, uint8_t *dst, size_t expected_len);

/**
 * Регистрация пользователя:
 * 1) Пишет открытые данные и kuz_key в db_path (JSON).
 * 2) Шифрует enc_priv и sign_priv Кузнечиком на ключе pass_hash[0..31]
 *    и сохраняет в keyfile_path.
 */
int cslr_db_register_user(const char *db_path,
                          const char *keyfile_path,
                          const char *login,
                          const char *password,
                          const struct cslr_rsa_pub_key *enc_pub,
                          const struct cslr_rsa_priv_key *enc_priv,
                          const struct cslr_rsa_pub_key *sign_pub,
                          const struct cslr_rsa_priv_key *sign_priv,
                          const uint8_t kuz_key[CSLR_KUZNYECHIK_KEY_SIZE]);

/**
 * Двухфакторная аутентификация (пароль + файл keyfile_path).
 * При успехе заполняет pub_out и secrets_out.
 */
int cslr_db_auth_2fa(const char *db_path,
                     const char *keyfile_path,
                     const char *login,
                     const char *password,
                     struct cslr_user_public *pub_out,
                     struct cslr_user_secrets *secrets_out);

/** Поиск открытого профиля любого пользователя в БД по логину */
int cslr_db_get_public_user(const char *db_path,
                            const char *login,
                            struct cslr_user_public *pub_out);

/** Добавление зашифрованного и подписанного сообщения в inbox получателя */
int cslr_db_push_message(const char *db_path,
                         const char *to_login,
                         const char *from_login,
                         const char *algo,
                         const uint8_t *ciphertext, size_t ct_len,
                         const uint8_t *signature, size_t sig_len);

/** Чтение и вывод всех входящих сообщений пользователя (с расшифровкой и проверкой ЭЦП) */
int cslr_db_read_inbox(const char *db_path,
                       const char *login,
                       const struct cslr_user_secrets *secrets);

