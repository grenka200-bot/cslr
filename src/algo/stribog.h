#ifndef STRIBOG_H
#define STRIBOG_H

#include <stdint.h>
#include <stddef.h>

/**
 * @file stribog.h
 * @brief Интерфейс хэш-функции ГОСТ Р 34.11-2012 «Стрибог» с поддержкой соли.
 */

#define CSLR_STRIBOG_256_LEN 32

/**
 * @brief Вычисляет salted-хэш Стрибог-256 для авторизации пользователей.
 * @details Реализует безопасное сложение: Хэш = Стрибог(Пароль + Соль).
 * @param[in] password Текстовый пароль из консоли (null-terminated string).
 * @param[in] salt Массив байт случайной соли.
 * @param[in] salt_len Длина соли в байтах.
 * @param[out] out_hash Выходной буфер для хэша (обязан быть не менее 32 байт).
 * @return 0 при успешном вычислении, -1 при невалидных аргументах.
 */
int cslr_stribog_salted(const char *password, const uint8_t *salt, size_t salt_len, uint8_t *out_hash);

#endif /* STRIBOG_H */

