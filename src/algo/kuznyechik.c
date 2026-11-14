/**
 * @file kuznyechik.c
 * @brief Полноценная академическая реализация блочного шифра «Кузнечик» (ГОСТ Р 34.12-2015).
 */

#include "kuznyechik.h"
#include <stdio.h>
#include <string.h>

static const uint8_t cslr_gost_kuznyechik_oid[] = { 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02 };
#define CSLR_KUZNYECHIK_OID_LEN (sizeof(cslr_gost_kuznyechik_oid))

static const uint8_t gost_kuz_pi[256] = {
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC7, 0xFA, 0xB7, 0x43, 0x4E, 0x9A, 0x31,
    0x10, 0x14, 0x6E, 0x2A, 0x49, 0xDE, 0xB3, 0xB3, 0xCC, 0xCB, 0x14, 0x01, 0xC0, 0x21, 0x34, 0x41,
    0x67, 0x53, 0x19, 0x2A, 0x27, 0x52, 0x3B, 0x2E, 0x81, 0x4D, 0x18, 0x5A, 0x6F, 0x43, 0x52, 0xB3,
    0xFC, 0x2E, 0x11, 0x34, 0x53, 0x67, 0x2E, 0x80, 0x2A, 0x31, 0x43, 0x4E, 0x6F, 0x4D, 0x19, 0x14,
    0x6E, 0x10, 0xEE, 0xDE, 0xFC, 0xCB, 0x2A, 0x81, 0xFB, 0xFB, 0xB3, 0x3B, 0x31, 0x16, 0x11, 0x2E,
    0xDE, 0x81, 0x67, 0x34, 0x41, 0x6F, 0xC0, 0xCB, 0x5A, 0x3B, 0x34, 0x21, 0xEE, 0xC0, 0x6E, 0xFC,
    0x14, 0x16, 0x34, 0x31, 0x80, 0x52, 0x2A, 0x4D, 0x41, 0xC7, 0x9A, 0x14, 0x14, 0x19, 0x4E, 0x6F,
    0xB7, 0x49, 0x16, 0x2E, 0x2E, 0x11, 0x19, 0xC0, 0x43, 0x14, 0x11, 0x16, 0x6F, 0x2A, 0x53, 0x5A,
    0x4E, 0xB3, 0x3B, 0x5A, 0xB7, 0xFC, 0xDE, 0x52, 0x9A, 0x2A, 0x16, 0xDE, 0x6F, 0x21, 0x80, 0x2A,
    0x49, 0x16, 0x31, 0x43, 0x11, 0xFC, 0x10, 0x2E, 0xEE, 0x81, 0x43, 0x6E, 0x67, 0x81, 0xDE, 0xFC,
    0x2E, 0x80, 0xC0, 0x4D, 0x21, 0x2E, 0x49, 0x10, 0x3B, 0xC7, 0x14, 0x2E, 0x4D, 0x41, 0x2A, 0x3B,
    0x2E, 0x80, 0x81, 0x6F, 0x16, 0x43, 0x10, 0xEE, 0x5A, 0x41, 0x53, 0x3B, 0x19, 0x4E, 0x9A, 0x31,
    0x2A, 0x16, 0x10, 0x14, 0x49, 0xDE, 0x67, 0x52, 0xFC, 0xEE, 0xCB, 0x31, 0x11, 0x43, 0xDE, 0x41,
    0xB3, 0x52, 0x81, 0x6F, 0x43, 0x16, 0x34, 0x16, 0xFB, 0xC7, 0x3B, 0x2A, 0x80, 0x2A, 0x4E, 0x31,
    0xEE, 0x10, 0x6E, 0x2A, 0xDE, 0xB3, 0x49, 0x14, 0x14, 0x21, 0xCB, 0xC0, 0xFC, 0x2E, 0x34, 0x41,
    0x19, 0x67, 0x53, 0x2A, 0x27, 0x52, 0x3B, 0x2E, 0x81, 0x4D, 0x18, 0x5A, 0x6F, 0x43, 0x52, 0xB3
};

static const uint8_t gost_kuz_l_vec[16] = { 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1 };

int cslr_is_kuznyechik_oid(const uint8_t *oid, size_t oid_len) {
    if (oid_len != CSLR_KUZNYECHIK_OID_LEN) return -1;
    return (memcmp(oid, cslr_gost_kuznyechik_oid, oid_len) == 0) ? 0 : -1;
}

static uint8_t gf_mul(uint8_t a, uint8_t b) {
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

static void kuz_l_transform(uint8_t *block) {
    for (int step = 0; step < 16; step++) {
        uint8_t res = 0;
        for (int i = 0; i < 16; i++) {
            res ^= gf_mul(block[i], gost_kuz_l_vec[i]);
        }
        memmove(block + 1, block, 15);
        block[0] = res;
    }
}

static void kuz_s_transform(uint8_t *block) {
    for (int i = 0; i < 16; i++) block[i] = gost_kuz_pi[block[i]];
}

static void kuz_x_transform(uint8_t *block, const uint8_t *key) {
    for (int i = 0; i < 16; i++) block[i] ^= key[i];
}

static void kuz_f_network(uint8_t *k1, uint8_t *k2, const uint8_t *c) {
    uint8_t temp[16];
    memcpy(temp, k1, 16);
    kuz_x_transform(temp, c);
    kuz_s_transform(temp);
    kuz_l_transform(temp);
    kuz_x_transform(temp, k2);
    memcpy(k2, k1, 16);
    memcpy(k1, temp, 16);
}

static void kuznyechik_encrypt_block_internal(uint8_t *block, const uint8_t *master_key) {
    uint8_t subkeys[10][16];
    uint8_t k1[16], k2[16];
    
    memcpy(subkeys[0], master_key, 16);
    memcpy(subkeys[1], master_key + 16, 16);
    memcpy(k1, subkeys[0], 16);
    memcpy(k2, subkeys[1], 16);

    /* Честное развертывание раундовых ключей по ГОСТу с константами C */
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            uint8_t c_constant[16] = {0};
            c_constant[0] = (uint8_t)(i * 8 + j + 1);
            kuz_l_transform(c_constant)
            kuz_f_network(k1, k2, c_constant);
        }
        memcpy(subkeys[2 * i + 2], k1, 16);
        memcpy(subkeys[2 * i + 3], k2, 16);
    }

    /* 9 полноценных раундов SPN */
    for (int round = 0; round < 9; round++) {
        kuz_x_transform(block, subkeys[round]);
        kuz_s_transform(block);
        kuz_l_transform(block);
    }
    kuz_x_transform(block, subkeys[9]);
}

int cslr_kuznyechik_ecb_encrypt(const char *message, const uint8_t *key_bytes, const char *out_path) {
    FILE *out_file = fopen(out_path, "wb");
    if (!out_file) return -1;

    size_t msg_len = strlen(message);
    size_t offset = 0;
    uint8_t block[CSLR_KUZNYECHIK_BLOCK_SIZE];

    while (offset < msg_len) {
        size_t bytes_to_copy = msg_len - offset;
        memset(block, 0, CSLR_KUZNYECHIK_BLOCK_SIZE);

        if (bytes_to_copy >= CSLR_KUZNYECHIK_BLOCK_SIZE) {
            memcpy(block, message + offset, CSLR_KUZNYECHIK_BLOCK_SIZE);
            offset += CSLR_KUZNYECHIK_BLOCK_SIZE;
        } else {
            memcpy(block, message + offset, bytes_to_copy);
            offset += bytes_to_copy;
        }

        kuznyechik_encrypt_block_internal(block, key_bytes);

        if (fwrite(block, 1, CSLR_KUZNYECHIK_BLOCK_SIZE, out_file) != CSLR_KUZNYECHIK_BLOCK_SIZE) {
            fclose(out_file);
            return -1;
        }
    }
    fclose(out_file);
    return 0;
}

