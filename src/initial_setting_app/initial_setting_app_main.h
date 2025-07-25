/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#define QRCODE_PAYLOAD_MAX_SIZE (1024)
#define QRCODE_IMAGE_WIDTH (640)
#define QRCODE_IMAGE_HEIGHT (480)

#ifdef CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500
#ifdef CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION
#include "../private/qr_quality_optimization.h"
#else
#define AIMODEL_ID_FOR_QRCODE "999999"
#endif
#else // Use #else for build: CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP
#define AIMODEL_ID_FOR_QRCODE "99999999999999999999999999999999" /* 640 x 480 x 1 (gray scale) */
#endif
