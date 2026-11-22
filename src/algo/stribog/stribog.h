#pragma once
#include <stddef.h>
#include <stdint.h>

#define CSLR_STREEBOG_256_DIGEST_SIZE 32
#define CSLR_STREEBOG_512_DIGEST_SIZE 64

/**
 * @brief Вычисляет хеш-функцию Стрибог-512 (ГОСТ Р 34.11-2012).
 * @param[in]  data     Указатель на входные данные (может быть NULL при len == 0).
 * @param[in]  len      Длина данных в байтах.
 * @param[out] digest   Буфер размером 64 байта для записи хеша.
 * @return 0 при успехе, -1 при передаче NULL (кроме data при len == 0).
 */
int cslr_streebog_512(const uint8_t *data, size_t len, uint8_t digest[CSLR_STREEBOG_512_DIGEST_SIZE]);

