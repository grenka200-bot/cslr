#pragma once

#include "key_struct.h"
#include <stdint.h>
#include <stddef.h>

/**
 * @file key_container_types.h
 * @brief Единые типы данных для транспортных контейнеров ключей (.der, .pem).
 */

/**
 * @enum
 *  key_storage_type
 * @brief
 *  Поддерживаемые форматы хранения файлов ключей на диске
 */
typedef enum {
    KEY_STORAGE_RAW_BINARY,
    KEY_STORAGE_BASE64,
    KEY_STORAGE_DER,
    KEY_STORAGE_PEM
} key_storage_type;

