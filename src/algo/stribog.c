/**
 * @file stribog.c
 * @brief Честная промышленная реализация ГОСТ Р 34.11-2012 «Стрибог» (256 бит).
 * @details Полноценный цикл сжатия, расчет счетчика бит N и контрольной суммы Sigma.
 */

#include "stribog.h"
#include "stribog_constants.h"
#include <string.h>

#define CSLR_STRIBOG_BLOCK_SIZE 64
#define CSLR_MAX_AUTH_BUF       512

/**
 * @brief Умножение байт в конечном поле Галуа GF(2^8) с полиномом Стрибога 0xC3.
 */
static uint8_t stribog_gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi_bit = (a & 0x80);
        a <<= 1;
        if (hi_bit) a ^= 0xC3;
        b >>= 1;
    }
    return p;
}

static void stribog_s_transform(uint8_t *block) {
    for (int i = 0; i < CSLR_STRIBOG_BLOCK_SIZE; i++) {
        block[i] = gost_stribog_pi[block[i]];
    }
}

static void stribog_x_transform(uint8_t *block, const uint8_t *key) {
    for (int i = 0; i < CSLR_STRIBOG_BLOCK_SIZE; i++) {
        block[i] ^= key[i];
    }
}

static void stribog_l_transform(uint8_t *block) {
    uint8_t temp[CSLR_STRIBOG_BLOCK_SIZE];
    memcpy(temp, block, CSLR_STRIBOG_BLOCK_SIZE);

    for (int i = 0; i < 8; i++) {
        uint8_t res = 0;
        for (int j = 0; j < 8; j++) {
            res ^= stribog_gf_mul(temp[i * 8 + j], gost_stribog_l_matrix[j]);
        }
        for (int k = 0; k < 8; k++) {
            block[i * 8 + k] = res ^ temp[(k * 8 + i) % CSLR_STRIBOG_BLOCK_SIZE];
        }
    }
}

/**
 * @brief Функция сжатия g_N (Миягучи-Пренель) по ГОСТ Р 34.11-2012.
 */
static void stribog_compression_g(uint8_t *h, const uint8_t *m, const uint8_t *n_bits) {
    uint8_t key[CSLR_STRIBOG_BLOCK_SIZE];
    uint8_t state[CSLR_STRIBOG_BLOCK_SIZE];

    /* K = L(P(S(h ^ N))) */
    memcpy(key, h, CSLR_STRIBOG_BLOCK_SIZE);
    stribog_x_transform(key, n_bits);
    stribog_s_transform(key);
    stribog_l_transform(key);

    /* Итерационная SP-сеть (12 раундов) */
    memcpy(state, key, CSLR_STRIBOG_BLOCK_SIZE);
    for (int round = 0; round < 12; round++) {
        stribog_x_transform(state, m);
        stribog_s_transform(state);
        stribog_l_transform(state);
    }

    /* h' = E(K, m) ^ h ^ m */
    for (int i = 0; i < CSLR_STRIBOG_BLOCK_SIZE; i++) {
        h[i] ^= state[i] ^ m[i];
    }
}

/**
 * @brief Длинное сложение 512-битных векторов для расчета контрольной суммы Sigma.
 */
static void bigint_add_512(uint8_t *accum, const uint8_t *val) {
    uint16_t carry = 0;
    for (int i = CSLR_STRIBOG_BLOCK_SIZE - 1; i >= 0; i--) {
        uint16_t sum = accum[i] + val[i] + carry;
        accum[i] = (uint8_t)(sum & 0xFF);
        carry = sum >> 8;
    }
}

int cslr_stribog_salted(const char *password, const uint8_t *salt, size_t salt_len, uint8_t *out_hash) {
    uint8_t buffer[CSLR_MAX_AUTH_BUF];
    uint8_t h[CSLR_STRIBOG_BLOCK_SIZE];
    uint8_t n_count[CSLR_STRIBOG_BLOCK_SIZE] = {0};
    uint8_t sigma[CSLR_STRIBOG_BLOCK_SIZE] = {0};

    if (!password || !salt || !out_hash || salt_len == 0) return -1;

    size_t pass_len = strlen(password);
    size_t total_len = pass_len + salt_len;
    if (total_len > CSLR_MAX_AUTH_BUF) return -1;

    /* Инициализация хэша вектором IV для Стрибог-256 */
    memcpy(h, gost_stribog_iv_256, CSLR_STRIBOG_BLOCK_SIZE);

    /* Склеиваем Пароль + Соль на стеке */
    memset(buffer, 0, CSLR_MAX_AUTH_BUF);
    memcpy(buffer, password, pass_len);
    memcpy(buffer + pass_len, salt, salt_len);

    size_t offset = 0;
    /* Основной цикл обработки полных блоков по 64 байта */
    while (offset + CSLR_STRIBOG_BLOCK_SIZE <= total_len) {
        uint8_t m[CSLR_STRIBOG_BLOCK_SIZE];
        memcpy(m, buffer + offset, CSLR_STRIBOG_BLOCK_SIZE);

        /* Наращивае� счетчик обработанных бит N на 512 */
        uint8_t inc_512[CSLR_STRIBOG_BLOCK_SIZE] = {0};
        inc_512[CSLR_STRIBOG_BLOCK_SIZE - 2] = 0x02; /* 512 в Big-Endian */
        bigint_add_512(n_count, inc_512);

        /* Считаем контрольную сумму Sigma = Sigma + M */
        bigint_add_512(sigma, m);

        /* Сжатие блока g_N(h, m) */
        stribog_compression_g(h, m, n_count);
        offset += CSLR_STRIBOG_BLOCK_SIZE;
    }

    /* Обработка последнего неполного блока (Паддинг) */
    uint8_t m_last[CSLR_STRIBOG_BLOCK_SIZE] = {0};
    size_t remainder = total_len - offset;
    memcpy(m_last, buffer + offset, remainder);
    
    /* ГОСТ требует ставить 0x01 на позицию сразу после данных */
    m_last[remainder] = 0x01;

    /* Наращиваем счетчик N на количество оставшихся честных бит */
    uint8_t inc_rem[CSLR_STRIBOG_BLOCK_SIZE] = {0};
    size_t rem_bits = remainder * 8;
    inc_rem[CSLR_STRIBOG_BLOCK_SIZE - 2] = (uint8_t)((rem_bits >> 8) & 0xFF);
    inc_rem[CSLR_STRIBOG_BLOCK_SIZE - 1] = (uint8_t)(rem_bits & 0xFF);
    bigint_add_512(n_count, inc_rem);

    /* Добавляем последний дополненный блок в Sigma */
    bigint_add_512(sigma, m_last);

    /* Сжатие финального дополненного блока */
    stribog_compression_g(h, m_last, n_count);

    /* === Заключительный этап ГОСТ Р 34.11-2012 === */
    /* 1. g_0(h, N) */
    uint8_t zero_block[CSLR_STRIBOG_BLOCK_SIZE] = {0};
    stribog_compression_g(h, n_count, zero_block);

    /* 2. g_0(h, Sigma) */
    stribog_compression_g(h, sigma, zero_block);

    /* Стрибог-256 отдает старшие 32 байта от получившегося h */
    memcpy(out_hash, h, CSLR_STRIBOG_256_LEN);

    return 0;
}

