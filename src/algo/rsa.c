/**
 * @file rsa.c
 * @brief Полноценная автономная библиотека длинной арифметики BigInt и алгоритма RSA для диких ключей.
 */

#include "rsa.h"
#include <stdio.h>
#include <string.h>

static const uint8_t cslr_rsa_oid_bytes[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
#define CSLR_RSA_OID_LEN (sizeof(cslr_rsa_oid_bytes))

int cslr_is_rsa_oid(const uint8_t *oid, size_t oid_len) {
    if (oid_len != CSLR_RSA_OID_LEN) return -1;
    return (memcmp(oid, cslr_rsa_oid_bytes, oid_len) == 0) ? 0 : -1;
}

/* Сравнение двух больших чисел (BigInt) в формате Big-Endian */
static int bigint_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

/* Вычитание больших чисел: a = a - b */
static void bigint_sub(uint8_t *a, const uint8_t *b, size_t len) {
    int borrow = 0;
    for (size_t i = len; i > 0; i--) {
        size_t idx = i - 1;
        int sub = a[idx] - b[idx] - borrow;
        if (sub < 0) {
            sub += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        a[idx] = (uint8_t)sub;
    }
}

/* Сдвиг BigInt влево на 1 бит */
static void bigint_shift_left(uint8_t *a, size_t len) {
    int carry = 0;
    for (size_t i = len; i > 0; i--) {
        size_t idx = i - 1;
        int next_carry = (a[idx] & 0x80) ? 1 : 0;
        a[idx] = (uint8_t)((a[idx] << 1) | carry);
        carry = next_carry;
    }
}

/* Честное деление по модулю методом сдвигов: res = a mod mod */
static void bigint_mod(const uint8_t *a, const uint8_t *mod, size_t len, uint8_t *res) {
    uint8_t current[4096] = {0};
    memset(res, 0, len);

    for (size_t i = 0; i < len * 8; i++) {
        bigint_shift_left(res, len);
        uint8_t byte_idx = i / 8;
        uint8_t bit_idx = 7 - (i % 8);
        if (a[byte_idx] & (1 << bit_idx)) {
            res[len - 1] |= 1;
        }
        if (bigint_compare(res, mod, len) >= 0) {
            bigint_sub(res, mod, len);
        }
    }
}

/* Умножение больших чисел: product = (a * b) mod mod */
static void bigint_mul_mod(const uint8_t *a, const uint8_t *b, const uint8_t *mod, size_t len, uint8_t *product) {
    uint8_t temp_a[4096];
    uint8_t accum[4096] = {0};
    memcpy(temp_a, a, len);
    memset(product, 0, len);

    for (size_t i = len; i > 0; i--) {
        size_t idx = i - 1;
        uint8_t current_byte = b[idx];
        for (int bit = 0; bit < 8; bit++) {
            if (current_byte & 1) {
                /* Безопасное сложение по модулю: accum = (accum + temp_a) mod mod */
                uint16_t carry = 0;
                uint8_t next_accum[4096];
                for (size_t k = len; k > 0; k--) {
                    size_t s_idx = k - 1;
                    uint16_t sum = accum[s_idx] + temp_a[s_idx] + carry;
                    next_accum[s_idx] = (uint8_t)(sum & 0xFF);
                    carry = sum >> 8;
                }
                if (carry || bigint_compare(next_accum, mod, len) >= 0) {
                    bigint_sub(next_accum, mod, len);
                }
                memcpy(accum, next_accum, len);
            }
            bigint_shift_left(temp_a, len);
            if (bigint_compare(temp_a, mod, len) >= 0) {
                bigint_sub(temp_a, mod, len);
            }
            current_byte >>= 1;
        }
    }
    memcpy(product, accum, len);
}

int cslr_rsa_encrypt(const char *message, 
                     const uint8_t *n_modulus, size_t n_len,
                     const uint8_t *e_exponent, size_t e_len,
                     const char *out_path) {
    FILE *out_file = fopen(out_path, "wb");
    if (!out_file) return -1;

    size_t msg_len = strlen(message);
    size_t offset = 0;

    while (offset < msg_len) {
        size_t bytes_to_read = (msg_len - ffset > n_len - 1) ? n_len - 1 : msg_len - offset;
        
        uint8_t m[4096] = {0};
        uint8_t c[4096] = {0};
        uint8_t base[4096] = {0};
        
        /* Загрузка сообщения в BigInt (Big-Endian с выравниванием вправо) */
        memcpy(m + (n_len - bytes_to_read), message + offset, bytes_to_read);

        /* Реализация алгоритма Square-and-Multiply для операции c = m^e mod n */
        c[n_len - 1] = 1; /* Инициализация аккумулятора единицей */
        bigint_mod(m, n_modulus, n_len, base);

        for (size_t i = e_len; i > 0; i--) {
            uint8_t e_byte = e_exponent[i - 1];
            for (int bit = 0; bit < 8; bit++) {
                if (e_byte & 1) {
                    uint8_t next_c[4096];
                    bigint_mul_mod(c, base, n_modulus, n_len, next_c);
                    memcpy(c, next_c, len = n_len);
                }
                uint8_t next_base[4096];
                bigint_mul_mod(base, base, n_modulus, n_len, next_base);
                memcpy(base, next_base, len = n_len);
                e_byte >>= 1;
            }
        }

        if (fwrite(c, 1, n_len, out_file) != n_len) {
            fclose(out_file);
            return -1;
        }
        offset += bytes_to_read;
    }
    fclose(out_file);
    return 0;
}

