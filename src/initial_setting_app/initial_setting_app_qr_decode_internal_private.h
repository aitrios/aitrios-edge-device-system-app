/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _INITIAL_SETTING_APP_QR_DECODE_INTERNAL_PRIVATE_H_
#define _INITIAL_SETTING_APP_QR_DECODE_INTERNAL_PRIVATE_H_

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#if defined(CONFIG_ARCH_CHIP_ESP32)            /* T3P */
#define LINEAR_POOL_SIZE 0x0000000000200000ULL /* MEMORY POOL SIZE 2048KByte */
#define POOL_0_SIZE 0x0000000000080000ULL      /* POOL #0 SIZE      512KByte */
#define POOL_1_SIZE (LINEAR_POOL_SIZE - POOL_0_SIZE)
#endif

#endif // _INITIAL_SETTING_APP_QR_DECODE_INTERNAL_PRIVATE_H_
