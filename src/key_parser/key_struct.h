#ifndef KEY_STRUCT_H 
#define KEY_STRUCT_H 

#include <stdint.h>
#include <stddef.h>

/* Ограничения размеров для безопасного выделения памяти на стеке */
#define CSLR_MAX_OID_LEN       32
#define CSLR_MAX_SYM_KEY_LEN   64
#define CSLR_MAX_RSA_MODULUS   4096
#define CSLR_MAX_RSA_EXPONENT   8

/* Тег для определения активного типа ключа в union */
enum key_type {
    KEY_TYPE_SYMMETRIC,
    KEY_TYPE_ASYMMETRIC
};

/* Контекст симметричных алгоритмов (Кузнечик, Магма, AES) */
struct symmetric_key {
    uint8_t secret_bytes[CSLR_MAX_SYM_KEY_LEN];
    size_t secret_len;
};

/* Контекст асимметричных алгоритмов (RSA) */
struct asymmetric_key {
    uint8_t n_modulus[CSLR_MAX_RSA_MODULUS];
    size_t n_len;
    uint8_t e_exponent[CSLR_MAX_RSA_EXPONENT];
    size_t e_len;
};

/* Главный контейнер ключа (Tagged Union) */
struct parsed_key {
    enum key_type type;
    
    /* Универсальный идентификатор алгоритма на верхнем уровне */
    uint8_t oid[CSLR_MAX_OID_LEN]; 
    size_t oid_len;

    union {
        struct symmetric_key symmetric;
        struct asymmetric_key asymmetric;
    } key_data;
};

#endif /* KEY_STRUCT_H */

