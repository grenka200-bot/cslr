#ifndef KEY_CONTAINER_TYPES_H
#define KEY_CONTAINER_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include "key_struct.h"

/**
 * @file key_container_types.h
 * @brief Единые типы данных для транспортных контейнеров ключей (.der, .pem).
 */

/**
 * @enum key_storage_type
 * @brief Поддерживаемые форматы хранения файлов ключей на диске.
 */
enum key_storage_type {
    KEY_STORAGE_RAW_BINARY,
    KEY_STORAGE_BASE64,
    KEY_STORAGE_DER,
    KEY_STORAGE_PEM
};

#endif /* KEY_CONTAINER_TYPES_H */

