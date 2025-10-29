/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SYSTEM_APP_STATE_H_
#define _SYSTEM_APP_STATE_H_

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#include "system_app_common.h"

#define ST_AIMODELS_NUM (4)
#define ST_AIMODELS_DUMMY_NUM (0)

#ifdef CONFIG_ARCH_CHIP_ESP32 //T3P
#define ST_CHIPS_NUM (2)
#define CHIPS_IDX_MAIN_CHIP (0)
#define CHIPS_IDX_SENSOR_CHIP (1)
#else
#define ST_CHIPS_NUM (3)
#define CHIPS_IDX_MAIN_CHIP (0)
#define CHIPS_IDX_SENSOR_CHIP (1)
#define CHIPS_IDX_COMPANION_CHIP (2)
#endif // CONFIG_ARCH_CHIP_ESP32

typedef enum {
    WirelessModeNone = 0,
    WirelessModeSta,
    WirelessModeAp,
    WirelessModeStaAp,

    SupportedWirelessModeNum
} SupportedWirelessMode;

typedef enum {
    SensorName = 0,
    SensorId,
    SensorHwVer,
    AiIspDeviceId,

    SensorInfoCategoryNum
} SensorInfoCategory;

//
// Public functions declaration.
//

RetCode SysAppStaInitialize(struct SYS_client *evp_client);
RetCode SysAppStaFinalize(void);
RetCode SysAppStateReadoutDeviceInfo(void);
RetCode SysAppStateReadoutDeviceCapabilities(void);
RetCode SysAppStateReadoutDeviceStates(void);
#if 0 // For_Coverity_Disable_SysAppStateReadoutReserved
RetCode SysAppStateReadoutReserved(void);
#endif
RetCode SysAppStateReadoutSystemSettings(void);
RetCode SysAppStateReadoutNetworkSettings(void);
RetCode SysAppStateReadoutWirelessSetting(void);
RetCode SysAppStateReadoutPeriodicSetting(void);
RetCode SysAppStateReadoutEndpointSettings(void);

RetCode SysAppStateUpdateNumber(uint32_t topic, uint32_t type, int number);
RetCode SysAppStateUpdateNumberWithIdx(uint32_t topic, uint32_t type, int number, uint32_t idx);
RetCode SysAppStateUpdateBoolean(uint32_t topic, uint32_t type, bool boolean);
void SysAppStateUpdateString(uint32_t topic, uint32_t type, const char *string);
RetCode SysAppStateUpdateStringWithIdx(uint32_t topic, uint32_t type, const char *string,
                                       uint32_t idx);
RetCode SysAppStateUpdateSensorTemperature(void);
RetCode SysAppStateUpdateHoursMeter(void);
RetCode SysAppStateSetInvalidArgError(uint32_t topic, uint32_t property);
RetCode SysAppStateSetInvalidArgErrorWithIdx(uint32_t topic, uint32_t property, uint32_t idx);
RetCode SysAppStateSetInternalError(uint32_t topic, uint32_t property);
RetCode SysAppStateSetInternalErrorWithIdx(uint32_t topic, uint32_t property, uint32_t idx);

char *SysAppStateGetReqId(uint32_t topic);
void SysAppStateGetTemperatureUpdateInterval(int *temperature_update_interval);
char *SysAppStateGetProtocolVersion(void);

RetCode SysAppStateSendState(uint32_t req);
RetCode SysAppStaReopenIfClose(void);
RetCode SysAppStaClose(void);

RetCode SysAppStateGetSensCordId(void *core_id);
RetCode SysAppStateGetSensCordStream(void *stream);
bool SysAppStaIsStateQueueEmpty(void);

#ifndef CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION
bool SysAppStateIsUnimplementedTopic(const char *topic);
RetCode SysAppStateSendUnimplementedState(const char *topic, const char *id);
#endif // !CONFIG_EXTERNAL_SYSTEMAPP_ENABLE_SYSTEM_FUNCTION

#endif // _SYSTEM_APP_STATE_H_
