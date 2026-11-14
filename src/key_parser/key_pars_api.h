#ifndef KEY_PARS_API_H
#define KEY_PARS_API_H

#include "key_container_types.h"

/**
 * @file key_pars_api.h
 * @brief API для автоматической загрузки и десериализации ключей.
 */

/**
 * @brief Загружает файл с диска, определяет формат и парсит в структуру.
 * @param[in] path Путь к файлу ключа.
 * @param[out] out_key Структура для заполнения.
 * @return 0 при успехе, -1 при ошибке.
 */
int cslr_load_and_parse_key(const char *path, struct parsed_key *out_key);

#endif /* KEY_PARS_API_H */

