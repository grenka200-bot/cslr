#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * @file kuznyechik.h
 * @brief Интерфейс симметричного блочного шифра ГОСТ Р 34.12-2015 «Кузнечик» в режиме ECB.
 */

#define CSLR_KUZNYECHIK_BLOCK_SIZE 16
#define CSLR_KUZNYECHIK_KEY_SIZE   32

/**
 * @brief Генерирует криптографически стойкий мастер-ключ длиной 32 байта (256 бит).
 * @details Читает 32 байта из системного источника энтропии (/dev/urandom).
 * @param[out] key Буфер размером не менее 32 байт для записи сгенерированного ключа.
 * @return 0 при успешной генерации, -1 при ошибке чтения энтропии или передаче NULL.
 */
int cslr_kuznyechik_keygen(uint8_t key[CSLR_KUZNYECHIK_KEY_SIZE]);

/**
 * @brief Шифрует произвольный массив байт в режиме ECB с нулевым паддингом до 16 байт.
 * @details Выходной буфер out должен вмещать не менее ((in_len + 15) / 16) * 16 байт
 *          (минимум 16 байт, если in_len == 0).
 * @param[in] key Мастер-ключ длиной 32 байта.
 * @param[in] in Указатель на входные данные.
 * @param[in] in_len Длина входных данных в байтах.
 * @param[out] out Выходной буфер для записи шифртекста.
 * @param[out] out_len Указатель, куда будет записана итоговая длина шифртекста в байтах.
 * @return 0 при успешном шифровании, -1 при передаче некорректных указателей.
 */
int cslr_kuznyechik_encrypt(const uint8_t key[CSLR_KUZNYECHIK_KEY_SIZE],
                            const uint8_t *in, size_t in_len,
                            uint8_t *out, size_t *out_len);

/**
 * @brief Расшифровывает массив байт в режиме ECB.
 * @param[in] key Мастер-ключ длиной 32 байта.
 * @param[in] in Указатель на шифртекст (длина должна быть кратна 16 байтам и > 0).
 * @param[in] in_len Длина шифртекста в байтах.
 * @param[out] out Выходной буфер размером не менее in_len байт.
 * @return 0 при успешном расшифровании, -1 если in_len не кратна 16, равна 0 или переданы NULL-указатели.
 */
int cslr_kuznyechik_decrypt(const uint8_t key[CSLR_KUZNYECHIK_KEY_SIZE],
                            const uint8_t *in, size_t in_len,
                            uint8_t *out);

