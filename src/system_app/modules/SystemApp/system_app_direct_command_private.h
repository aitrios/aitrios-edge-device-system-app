/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SYSTEM_APP_DIRECT_COMMAND_PRVIVATE_H_
#define _SYSTEM_APP_DIRECT_COMMAND_PRVIVATE_H_

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#include <stdbool.h>
#include "senscord/c_api/senscord_c_api.h"
#include "senscord/inference_stream/c_api/property_c_types.h"
#include "jpeg/include/jpeg.h"
#include "memory_manager.h"
#include "sdk_backdoor.h"
#include "system_app_common.h"
#include "system_app_direct_command.h"

//
// Macros.
//

//
// File private structure and enum.
//

// Register size.

typedef enum {
  RegiSize1Byte = 1,
  RegiSize2Byte = 2,
  RegiSize4Byte = 4,
} RegisterSize;

// DirectCommand response context.

typedef struct {
  SYS_response_id cmd_id;
  void* response;
  int status_code;
  uint32_t retry_count;
  bool* send_complete;
} DcResponseContext;

// DirectCommand res_info.

typedef struct {
  char res_id[CFG_RES_ID_LEN + 1];
  int code;
  char detail_msg[CFG_RES_DETAIL_MSG_LEN + 1];
} ResInfoContext;

// direct_get_image parameters.

typedef struct {
  char sensor_name[DC_SENSOR_NAME_LEN + 1];
  char network_id[DC_NETWORK_ID_LEN + 1];
} DirectGetImageParam;

// Image frame information.

typedef struct {
  void* addr;
  uint32_t size;
  uint64_t time_stamp;
  uint32_t width;
  uint32_t height;
  uint32_t stride;
  senscord_core_t sccore;
  senscord_stream_t scstream;
  senscord_frame_t scframe;
  EsfCodecJpegInputFormat format;
  EsfMemoryManagerHandle handle;
} FrameInfo;

// read_sensor_register and write_sensor_register array parameters.

typedef struct {
  uint64_t address;
  RegisterSize size;
  uint32_t value;
} SensorRegisterInfo;

// read_sensor_register and write_sensor_register parameters.

typedef struct {
  int32_t num;
  SensorRegisterInfo *info;
} SensorRegisterParam;

#endif // _SYSTEM_APP_DIRECT_COMMAND_PRVIVATE_H_
