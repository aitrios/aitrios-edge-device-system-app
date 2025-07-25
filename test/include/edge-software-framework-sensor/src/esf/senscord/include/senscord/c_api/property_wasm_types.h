/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef SENSCORD_C_API_PROPERTY_WASM_TYPES_H_
#define SENSCORD_C_API_PROPERTY_WASM_TYPES_H_

#include <stdint.h>

#include "senscord/config.h"

/** Wasm memory pool property key. */
#define SENSCORD_WASM_MEMORY_POOL_PROPERTY_KEY  "wasm_memory_pool_property"

/**
 * @brief Wasm memory pool property.
 */
struct senscord_wasm_memory_pool_property_t {
  uint32_t num;   /**< Number of memory chunks. */
  uint32_t size;  /**< Memory chunk size */
};

#endif  /* SENSCORD_C_API_PROPERTY_WASM_TYPES_H_ */
