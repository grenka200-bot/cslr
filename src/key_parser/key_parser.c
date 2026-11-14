/**
 * @file key_parser.c
 * @brief Универсальный транспортный парсер и генератор контейнеров ключей на чистом Си.
 * @details Полностью изолирован от логики конкретных криптографических шифров.
 */

#include "key_pars_api.h"
#include "key_gen_api.h"
#include <stdio.h>
#include <string.h>

#define CSLR_MAX_KEY_FILE_SIZE 16384 // максимальный размер ключа


/**
 * @brief Внутренняя статическая функция определения типа хранилища по расширению файла.
 */
static enum key_storage_type detect_storage_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext || ext == path) {
        return KEY_STORAGE_DER;
    }
    if (strcmp(ext + 1, "der") == 0) return KEY_STORAGE_DER;
    if (strcmp(ext + 1, "raw") == 0 || strcmp(ext + 1, "bin") == 0) return KEY_STORAGE_RAW_BINARY;
    if (strcmp(ext + 1, "pem") == 0) return KEY_STORAGE_PEM;
    return KEY_STORAGE_DER; 
}

/**
 * @brief Внутренняя безопасная функция разбора длин ASN.1 TLV.
 */
static int read_asn1_length(const uint8_t **ptr, const uint8_t *end, size_t *out_len) {
    if (*ptr >= end) return -1;
    
    uint8_t initial_byte = **ptr;
    (*ptr)++;

    if ((initial_byte & 0x80) == 0) {
        *out_len = initial_byte;
        return 0;
    }

    size_t length_bytes = initial_byte & 0x7F;
    if (length_bytes == 0 || length_bytes > sizeof(size_t) || (*ptr + length_bytes) > end) {
        return -1;
    }

    size_t accumulated_len = 0;
    for (size_t i = 0; i < length_bytes; i++) {
        accumulated_len = (accumulated_len << 8) | (**ptr);
        (*ptr)++;
    }

    *out_len = accumulated_len;
    return 0;
}

/**
 * @brief Внутренняя безопасная функция записи длин ASN.1 TLV.
 */
static int write_asn1_length(uint8_t *buf, size_t buf_size, size_t length) {
    if (buf_size < 1) return -1;
    
    /* Короткая форма (до 127 байт) */
    if (length <= 127) {
        buf[0] = (uint8_t)length;
        return 1;
    }
    /* Длинная форма (1 байт на размер длины: до 255 байт) */
    if (length <= 255) {
        if (buf_size < 2) return -1;
        buf[0] = 0x81;
        buf[1] = (uint8_t)length;
        return 2;
    }
    /* Длинная форма (2 байта на размер длины: до 65535 байт) — ДЛЯ НАШЕГО RSA */
    if (length <= 65535) {
        if (buf_size < 3) return -1;
        buf[0] = 0x82; /* 0x82 означает: длина занимает следующие 2 байта */
        buf[1] = (uint8_t)((length >> 8) & 0xFF);
        buf[2] = (uint8_t)(length & 0xFF);
        return 3;
    }
    return -1; 
}


/**
 * @brief Внутренний линейный разбор структуры PKCS#8.
 */
static int parse_der_internal(const uint8_t *buffer, size_t size, struct parsed_key *out_key) {
    const uint8_t *ptr = buffer;
    const uint8_t *end = buffer + size;
    size_t len = 0;

    if (ptr >= end || *ptr != 0x30) return -1;
    ptr++;
    if (read_asn1_length(&ptr, end, &len) != 0) return -1;

    if ((ptr + 3) > end || ptr[0] != 0x02 || ptr[1] != 0x01 || ptr[2] != 0x00) return -1;
    ptr += 3;

    if (ptr >= end || *ptr != 0x30) return -1;
    ptr++;
    if (read_asn1_length(&ptr, end, &len) != 0) return -1;

    if (ptr >= end || *ptr != 0x06) return -1;
    ptr++;
    if (read_asn1_length(&ptr, end, &len) != 0) return -1;
    if ((ptr + len) > end || len > CSLR_MAX_OID_LEN) return -1;

    memcpy(out_key->oid, ptr, len);
    out_key->oid_len = len;
    ptr += len;

    if (ptr >= end || *ptr != 0x04) return -1;
    ptr++;
    if (read_asn1_length(&ptr, end, &len) != 0) return -1;
    if ((ptr + len) > end || len > CSLR_MAX_SYM_KEY_LEN) return -1;

    out_key->type = KEY_TYPE_SYMMETRIC;
    memcpy(out_key->key_data.symmetric.secret_bytes, ptr, len);
    out_key->key_data.symmetric.secret_len = len;

    return 0;
}

int cslr_load_and_parse_key(const char *path, struct parsed_key *out_key) {
    uint8_t file_buf[CSLR_MAX_KEY_FILE_SIZE]; /* Безопасный буфер на стеке */
    size_t bytes_read = 0;
    if (!path || !out_key) return -1;
    enum key_storage_type storage = detect_storage_type(path);

    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    bytes_read = fread(file_buf, 1, sizeof(file_buf), f);
    fclose(f);

    if (bytes_read == 0 || bytes_read >= sizeof(file_buf)) return -1;

    if (storage == KEY_STORAGE_DER) {
        if (parse_der_internal(file_buf, bytes_read, out_key) != 0) retur -1;
    } else {
        return -1;
    }
    return 0;
}

/**
 * @brief Внутренняя сериализация структуры PKCS#8 на основе её собственных длин метаданных.
 */
static int serialize_der_internal(uint8_t *buf, size_t buf_size, const struct parsed_key *in_key) {
    uint8_t *ptr = buf;
    
    size_t key_len = in_key->key_data.symmetric.secret_len;
    size_t oid_len = in_key->oid_len;
    
    size_t oid_block_len = 1 + 1 + oid_len; 
    size_t key_block_len = 1 + 1 + key_len;
    size_t inner_seq_len = 1 + 1 + oid_block_len;
    size_t total_payload_len = 3 + inner_seq_len + key_block_len; 

    if (buf_size < (1 + 1 + total_payload_len)) return -1;
    
    *ptr++ = 0x30;
    int len_bytes = write_asn1_length(ptr, buf_size - (ptr - buf), total_payload_len);
    if (len_bytes == -1) return -1;
    ptr += len_bytes;

    *ptr++ = 0x02; *ptr++ = 0x01; *ptr++ = 0x00;

    *ptr++ = 0x30;
    len_bytes = write_asn1_length(ptr, buf_size - (ptr - buf), oid_block_len);
    if (len_bytes == -1) return -1;
    ptr += len_bytes;

    *ptr++ = 0x06;
    len_bytes = write_asn1_length(ptr, buf_size - (ptr - buf), oid_len);
    if (len_bytes == -1) return -1;
    ptr += len_bytes;
    memcpy(ptr, in_key->oid, oid_len);
    ptr += oid_len;

    *ptr++ = 0x04;
    len_bytes = write_asn1_length(ptr, buf_size - (ptr - buf), key_len);
    if (len_bytes == -1) return -1;
    ptr += len_bytes;
    memcpy(ptr, in_key->key_data.symmetric.secret_bytes, key_len);
    ptr += key_len;

    return (int)(ptr - buf);
}

int cslr_generate_and_save_key(const char *path, const struct parsed_key *in_key) {
    uint8_t out_buf[CSLR_MAX_KEY_FILE_SIZE] = {0};
    if (!path || !in_key) return -1;
    if (in_key->type != KEY_TYPE_SYMMETRIC) return -1; 

    enum key_storage_type storage = detect_storage_type(path);

    if (storage == KEY_STORAGE_DER) {
        int packed_size = serialize_der_internal(out_buf, sizeof(out_buf), in_key);
        if (packed_size == -1) return -1;

        FILE *f = fopen(path, "wb");
        if (!f) return -1;
        size_t written = fwrite(out_buf, 1, (size_t)packed_size, f);
        fclose(f);
        if (written != (size_t)packed_size) return -1;
    } else {
        return -1;
    }

    return 0;
}

