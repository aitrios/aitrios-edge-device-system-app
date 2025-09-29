/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SYSTEM_APP_DEPLOY_H_
#define _SYSTEM_APP_DEPLOY_H_

#ifdef __cplusplus
extern "C" {
#endif

// Deploy handle

typedef void *SysAppDeployHandle;

// Public functions

RetCode SysAppDeployInitialize(void);
RetCode SysAppDeployFinalize(void);
RetCode SysAppDeploy(const char *topic, const char *config, size_t len);
RetCode SysAppDeployGetFirmwareState(char **state, uint32_t *p_size);
RetCode SysAppDeployGetAiModelState(char **state, uint32_t *p_size);
RetCode SysAppDeployGetSensorCalibrationParamState(char **state, uint32_t *p_size);
RetCode SysAppDeployFreeState(char *state);
bool SysAppDeployCheckResetRequest(bool *is_downgrade);
void SysAppDeployFactoryReset(void);
bool SysAppDeployGetCancel(void);

#ifdef __cplusplus
}
#endif

#endif // _SYSTEM_APP_DEPLOY_H_
