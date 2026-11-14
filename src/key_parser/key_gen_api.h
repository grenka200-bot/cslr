#ifndef KEY_GEN_API_H
#define KEY_GEN_API_H

#include "key_container_types.h"

/**
 * @file key_gen_api.h
 * @brief API для создания, упаковки и сохранения ключей на диск.
 */

/**
 * @brief Генерирует криптографический контейнер и сохраняет его на диск.
 * @details Формат упаковки определяется автоматически по расширению файла.
 * @param[in] path Путь, куда сохранить сгенерированный ключ.
 * @param[in] in_key Заполненная структура ключа (сырые байты и тип).
 * @return 0 при успехе, -1 при ошибке.
 */
int cslr_generate_and_save_key(const char *path, const struct parsed_key *in_key);

#endif /* KEY_GEN_API_H */

