/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SYSTEM_APP_DEPLOY_PRIVATE_H_
#define _SYSTEM_APP_DEPLOY_PRIVATE_H_

#include <pthread.h>
#include <stdbool.h>
#include "firmware_manager.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

// Config and State Deploy

#define DEPLOY_STR_NAME_LEN                 (32)
#define DEPLOY_STR_NAME_BUF_LEN             (DEPLOY_STR_NAME_LEN + 16)
#define DEPLOY_STR_FIRMWARE_VERSION_LEN     (32)
#define DEPLOY_STR_FIRMWARE_VERSION_BUF_LEN (DEPLOY_STR_FIRMWARE_VERSION_LEN + 16)
#define DEPLOY_STR_VERSION_LEN              (44)
#define DEPLOY_STR_VERSION_BUF_LEN          (DEPLOY_STR_VERSION_LEN + 16)
#define DEPLOY_STR_PACKAGE_URL_LEN          (320)
#define DEPLOY_STR_PACKAGE_URL_BUF_LEN      (DEPLOY_STR_PACKAGE_URL_LEN + 16)
#define DEPLOY_STR_HASH_LEN                 (44)
#define DEPLOY_STR_HASH_BUF_LEN             (DEPLOY_STR_HASH_LEN + 16)
#define DEPLOY_TARGET_MAX_NUM               (10)
#define DEPLOY_STR_CHIP_LEN                 (32)
#define DEPLOY_STR_CHIP_BUF_LEN             (DEPLOY_STR_CHIP_LEN + 16)

// Define of res_info::res_id

#define RES_INFO_RES_ID_LEN      (128)

// Define of res_info::detail_msg

#define RES_INFO_DETAIL_MSG_LEN  (32)

// Utility message queue size

#define MSG_QUEUE_SIZE_FOR_DEPLOY  (3)

// max number of retry for EsfFwMgrOpen

#define MAX_NUMBER_OF_UPDATE_OPEN_RETRY  (60)
#define MAX_NUMBER_OF_UPDATE_RETRY       (10)

// Max time between retry when download failed

#define MAX_NUMBER_OF_UPDATE_RETRY_INTERVAL_TIME_SEC  (256)

// Max number of characters in configuration

#define MAX_NUMBER_OF_CHARACTERS_IN_CONFIGURATION  (8192)

/****************************************************************************
 * Public Type Definitions
 ****************************************************************************/

// define deploy topic

typedef enum {
  DeployTopicFirmware = 0,
  DeployTopicAiModel,
  DeployTopicCameraSetup,
  DeployTopicNum
} DeployTopic_e;

// define deploy component

typedef enum {
  /* 0: sensor_loader           */ DeployComponentSensorLoader           = 0,
  /* 1: sensor_firmware         */ DeployComponentSensorFirmware         = 1,
  /* 2: processor_loader        */ DeployComponentProcessorLoader        = 2,
  /* 3: processor_firmware      */ DeployComponentProcessorFirmware      = 3,
  /* 5: sensor_calibration_parm */ DeployComponentSensorCalibrationParam = 5,
  /* 9: ai_model                */ DeployComponentAiModel                = 9,
  DeployComponentNum,
  /* 0: for v2 loader           */ DeployComponentLoader   = DeployComponentSensorLoader,
  /* 1: for v2 firmware         */ DeployComponentFirmware = DeployComponentSensorFirmware,
  DeployComponentV2Num
} DeployComponent_e;

// define deploy state

typedef enum {
  DeployStateIdle = 0,
  DeployStateRequestReceived = DeployStateIdle,
  DeployStateDownloading,
  DeployStateInstalling,
  DeployStateDone,
  DeployStateFailed,
  DeployStateFailedInvalidRequest,
  DeployStateFailedTokenExpired,
  DeployStateFailedDownloadRetryExceeded,
  DeployStateFailedUnavailable,
  DeployStateNum
} DeployState_e;

// res_info notify message structure.

typedef struct {
    char res_id[RES_INFO_RES_ID_LEN + 1];
    int  code;
    char detail_msg[RES_INFO_DETAIL_MSG_LEN + 1];
} ResInfo_t;

// Struct for deploy target.

typedef struct {
  DeployComponent_e component;
  char              name[DEPLOY_STR_NAME_BUF_LEN];
  char              chip[DEPLOY_STR_CHIP_BUF_LEN];
  char              version[DEPLOY_STR_VERSION_BUF_LEN];
  char              package_url[DEPLOY_STR_PACKAGE_URL_BUF_LEN];
  char              hash[DEPLOY_STR_HASH_BUF_LEN];
  int               size;
  int               progress;
  DeployState_e     process_state;
  DeployState_e     parse_state;
} DeployTarget_t;

// Struct for deploy.

typedef struct {
  char            id[RES_INFO_RES_ID_LEN + 1];
  int             topic_id;
  char            version[DEPLOY_STR_FIRMWARE_VERSION_BUF_LEN];
  uint8_t         deploy_target_num;
  uint8_t         deploy_target_cnt;
  DeployTarget_t *deploy_targets;
  ResInfo_t       res_info;
  DeployState_e   parse_state;
} Deploy_t;

// Struct for deploy initialize parameters

typedef struct {
  Deploy_t              deploy;
  int32_t               msg_handle_dp;
  uint32_t              max_msg_size_dp;
  pthread_t             pid;
  pthread_mutex_t       state_mutex;
  char                 *state_str[DeployTopicNum];
  size_t                state_str_len[DeployTopicNum];
  bool                  is_pre_reboot;
  bool                  is_reboot;
  bool                  is_cancels[DeployTopicNum];
  EsfFwMgrSwArchVersion arch_version;
} DeployInitParams_t;


// Struct for message parameter

typedef struct {
  int    topic_id;
  size_t len;
  char   config[1];
} DeployMessage_t;


// FwWrite callback context

typedef struct {
  EsfFwMgrHandle fwmgr_handle;
  size_t         offset;
  size_t         memory_size;
  void          *sha256_handle;
  uint8_t        hash[32];
} DeployFwWrite_t;

#endif  // _SYSTEM_APP_DEPLOY_PRIVATE_H_
