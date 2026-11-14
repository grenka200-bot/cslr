#ifndef KUZNYECHIK_H
#define KUZNYECHIK_H

#include <stdint.h>
#include <stddef.h>

/**
 * @file kuznyechik.h
 * @brief Интерфейс симметричного шифра ГОСТ Р 34.12-2015 «Кузнечик» в режиме ECB.
 */

#define CSLR_KUZNYECHIK_BLOCK_SIZE 16

/**
 * @brief Проверяет, принадлежит ли переданный OID алгоритму Кузнечик.
 * @param[in] oid Массив байт извлеченного OID из структуры parsed_key.
 * @param[in] oid_len Длина извлеченного OID в байтах.
 * @return 0 если это Кузнечик, -1 если другой алгоритм.
 */
int cslr_is_kuznyechik_oid(const uint8_t *oid, size_t oid_len);

/**
 * @brief Шифрует строку в режиме ECB с автоматическим нулевым паддингом до 16 байт.
 * @details Результат поблочно записывается в бинарный файл по указанному пути.
 * @param[in] message Текстовое сообщение из консоли (null-terminated string).
 * @param[in] key_bytes Сырые 32 байта секретного ключа Кузнечика.
 * @param[in] out_path Путь к выходному бинарному файлу на диске.
 * @return 0 при успешном завершении, -1 при любой ошибке ввода-вывода или криптографии.
 */
int cslr_kuznyechik_ecb_encrypt(const char *message, const uint8_t *key_bytes, const char *out_path);

#endif /* KUZNYECHIK_H */

