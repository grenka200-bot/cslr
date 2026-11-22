// Блочный шифр «Кузнечик» (ГОСТ Р 34.12-2015) в режиме ECB.
// Реализация на чистом C (C99), портирована из эталонной версии.
//
// Особенности:
//   - преобразования X, S, R, L и развёртка ключей — как в ГОСТ Р 34.12-2015;
//   - блоки обрабатываются как uint8_t[16], без алиасинга через uint64_t;
//   - режим ECB с нулевым паддингом до кратности 16 байтам;
//   - keygen читает 32 байта из /dev/urandom (Linux).

#include "kuznyechik.h"

#include <stdio.h>
#include <string.h>

#define KUZ_BLOCK 16
#define KUZ_KEY   32

/* ------------------------------------------------------------------ */
/*  Таблицы ГОСТ Р 34.12-2015                                         */
/* ------------------------------------------------------------------ */

/* Прямое нелинейное преобразование pi */
static const uint8_t Pi[256] = {
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
};

/* Обратное нелинейное преобразование pi^-1 */
static const uint8_t Pi_reverse[256] = {
    0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0, 0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
    0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18, 0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
    0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4, 0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
    0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9, 0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
    0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B, 0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
    0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F, 0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
    0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2, 0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
    0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11, 0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
    0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F, 0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
    0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1, 0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
    0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0, 0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
    0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D, 0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
    0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67, 0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
    0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88, 0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
    0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
    0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7, 0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74
};

/* Вектор линейного преобразования l */
static const uint8_t linear_vector[16] = {
    0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
    0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01
};

/* ------------------------------------------------------------------ */
/*  Преобразования                                                    */
/* ------------------------------------------------------------------ */

/* Умножение в GF(2^8) по модулю x^8 + x^7 + x^6 + x + 1 */
static uint8_t gf_mult(uint8_t a, uint8_t b)
{
    uint8_t c = 0;
    while (b) {
        if (b & 1)
            c ^= a;
        a = (uint8_t)((a << 1) ^ (a & 0x80 ? 0xC3 : 0x00));
        b >>= 1;
    }
    return c;
}

/* X: побайтовый XOR */
static void X(const uint8_t a[16], const uint8_t b[16], uint8_t c[16])
{
    for (int i = 0; i < 16; i++)
        c[i] = (uint8_t)(a[i] ^ b[i]);
}

/* S: нелинейная подстановка */
static void S(uint8_t block[16])
{
    for (int i = 0; i < 16; i++)
        block[i] = Pi[block[i]];
}

/* S^-1 */
static void S_reverse(uint8_t block[16])
{
    for (int i = 0; i < 16; i++)
        block[i] = Pi_reverse[block[i]];
}

/* R: один шаг линейного преобразования */
static void R(uint8_t block[16])
{
    uint8_t acc = block[15];
    for (int i = 14; i >= 0; i--) {
        block[i + 1] = block[i];
        acc ^= gf_mult(block[i], linear_vector[i]);
    }
    block[0] = acc;
}

/* R^-1 */
static void R_reverse(uint8_t block[16])
{
    uint8_t acc = block[0];
    for (int i = 0; i < 15; i++) {
        block[i] = block[i + 1];
        acc ^= gf_mult(block[i], linear_vector[i]);
    }
    block[15] = acc;
}

/* L: 16 итераций R */
static void L(uint8_t block[16])
{
    for (int i = 0; i < 16; i++)
        R(block);
}

/* L^-1: 16 итераций R^-1 */
static void L_reverse(uint8_t block[16])
{
    for (int i = 0; i < 16; i++)
        R_reverse(block);
}

/* ------------------------------------------------------------------ */
/*  Развёртка ключа                                                    */
/* ------------------------------------------------------------------ */

/* Генерирует 10 раундовых ключей по 16 байт из мастер-ключа 32 байта. */
static void gen_round_keys(const uint8_t key[32], uint8_t round_keys[10][16])
{
    /* Константы итераций C_1..C_32 */
    uint8_t cs[32][16] = {{0}};
    for (int i = 0; i < 32; i++) {
        cs[i][15] = (uint8_t)(i + 1);
        L(cs[i]);
    }

    /* Первые два раундовых ключа — половины мастер-ключа */
    memcpy(round_keys[0], key, 16);
    memcpy(round_keys[1], key + 16, 16);

    /* Две "половинки" сети Фейстеля */
    uint8_t k1[16], k2[16];
    memcpy(k1, key, 16);         /* старшая половина */
    memcpy(k2, key + 16, 16);    /* младшая половина */

    for (int i = 1; i <= 32; i++) {
        uint8_t t[16];
        X(k1, cs[i - 1], t);
        S(t);
        L(t);
        X(t, k2, t);

        memcpy(k2, k1, 16);
        memcpy(k1, t, 16);

        if ((i > 0) && (i % 8 == 0)) {
            memcpy(round_keys[(i >> 2)],     k1, 16);
            memcpy(round_keys[(i >> 2) + 1], k2, 16);
        }
    }

    /* Затираем промежуточные значения */
    volatile uint8_t *p1 = k1, *p2 = k2, *pc = &cs[0][0];
    for (int i = 0; i < 16; i++) { p1[i] = 0; p2[i] = 0; }
    for (int i = 0; i < 32 * 16; i++) pc[i] = 0;
}

/* ------------------------------------------------------------------ */
/*  Шифрование/расшифрование одного блока                              */
/* ------------------------------------------------------------------ */

static void encrypt_block(const uint8_t round_keys[10][16],
                          const uint8_t in[16], uint8_t out[16])
{
    uint8_t p[16];
    memcpy(p, in, 16);
    for (int i = 0; i < 10; i++) {
        X(p, round_keys[i], p);
        if (i < 9) {
            S(p);
            L(p);
        }
    }
    memcpy(out, p, 16);
}

static void decrypt_block(const uint8_t round_keys[10][16],
                          const uint8_t in[16], uint8_t out[16])
{
    uint8_t p[16];
    memcpy(p, in, 16);
    X(p, round_keys[9], p);
    for (int i = 8; i >= 0; i--) {
        L_reverse(p);
        S_reverse(p);
        X(p, round_keys[i], p);
    }
    memcpy(out, p, 16);
}

/* ------------------------------------------------------------------ */
/*  Публичный API                                                     */
/* ------------------------------------------------------------------ */

int cslr_kuznyechik_keygen(uint8_t key[CSLR_KUZNYECHIK_KEY_SIZE])
{
    if (key == NULL)
        return -1;

    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL)
        return -1;

    size_t got = fread(key, 1, CSLR_KUZNYECHIK_KEY_SIZE, f);
    fclose(f);

    return (got == CSLR_KUZNYECHIK_KEY_SIZE) ? 0 : -1;
}

int cslr_kuznyechik_encrypt(const uint8_t key[CSLR_KUZNYECHIK_KEY_SIZE],
                            const uint8_t *in, size_t in_len,
                            uint8_t *out, size_t *out_len)
{
    if (key == NULL || out == NULL || out_len == NULL)
        return -1;
    if (in == NULL && in_len != 0)
        return -1;

    /* Длина шифртекста с нулевым паддингом до 16 байт, минимум один блок. */
    size_t blocks = (in_len + 15) / 16;
    if (blocks == 0)
        blocks = 1;
    size_t total = blocks * 16;

    uint8_t round_keys[10][16];
    gen_round_keys(key, round_keys);

    uint8_t block[16];

    /* Полные блоки из входа */
    size_t full = in_len / 16;
    for (size_t i = 0; i < full; i++) {
        encrypt_block(round_keys, in + i * 16, out + i * 16);
    }

    /* Хвост (или полностью нулевой блок при in_len == 0) */
    size_t tail = in_len - full * 16;
    memset(block, 0, 16);
    if (tail > 0)
        memcpy(block, in + full * 16, tail);
    encrypt_block(round_keys, block, out + full * 16);

    /* Затираем раундовые ключи */
    volatile uint8_t *p = &round_keys[0][0];
    for (int i = 0; i < 10 * 16; i++) p[i] = 0;

    *out_len = total;
    return 0;
}

int cslr_kuznyechik_decrypt(const uint8_t key[CSLR_KUZNYECHIK_KEY_SIZE],
                            const uint8_t *in, size_t in_len,
                            uint8_t *out)
{
    if (key == NULL || in == NULL || out == NULL)
        return -1;
    if (in_len == 0 || (in_len % 16) != 0)
        return -1;

    uint8_t round_keys[10][16];
    gen_round_keys(key, round_keys);

    for (size_t i = 0; i < in_len / 16; i++) {
        decrypt_block(round_keys, in + i * 16, out + i * 16);
    }

    /* Затираем раундовые ключи */
    volatile uint8_t *p = &round_keys[0][0];
    for (int i = 0; i < 10 * 16; i++) p[i] = 0;

    return 0;
}

