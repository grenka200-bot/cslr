#ifndef RSA_H
#define RSA_H

#include <stdint.h>
#include <stddef.h>

/**
 * @file rsa.h
 * @brief Интерфейс алгоритма RSA с поддержкой диких ключей до 4096 байт.
 */

/**
 * @brief Проверяет, принадлежит ли переданный OID алгоритму RSA.
 * @param[in] oid Массив байт извлеченного OID из структуры parsed_key.
 * @param[in] oid_len Длина извлеченного OID в байтах.
 * @return 0 если это RSA, -1 если другой алгоритм.
 */
int cslr_is_rsa_oid(const uint8_t *oid, size_t oid_len);

/**
 * @brief Шифрует сообщение открытым ключом RSA (n, e).
 * @details Математически реализует операцию C = M^e (mod n) для больших массивов байт.
 * @param[in] message Текстовое сообщение из консоли (null-terminated string).
 * @param[in] n_modulus Байт-массив модуля n (до 4096 байт).
 * @param[in] n_len Длина модуля n в байтах.
 * @param[in] e_exponent Байт-массив экспоненты e.
 * @param[in] e_len Длина экспоненты e в байтах.
 * @param[in] out_path Путь к выходному бинарному файлу на диске.
 * @return 0 при успехе, -1 при любой ошибке.
 */
int cslr_rsa_encrypt(const char *message, 
                     const uint8_t *n_modulus, size_t n_len,
                     const uint8_t *e_exponent, size_t e_len,
                     const char *out_path);

#endif /* RSA_H */

