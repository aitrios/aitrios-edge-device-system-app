/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SYSTEM_APP_UD_MAIN_H_
#define _SYSTEM_APP_UD_MAIN_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef SYSTEM_APP_UT
#include <unistd.h>
#include "system_app_common.h"
#endif  // #ifdef SYSTEM_APP_UT

// Public data type

typedef int (*SysAppUdDownloadCb)(uint8_t *data, size_t dl_size, void *p_usr_data);

// Public functions

RetCode SysAppUdInitialize(struct SYS_client *iot_client_ud);
RetCode SysAppUdFinalize(void);
size_t  SysAppUdGetImageSize(char *request_url, int *http_status);
ssize_t SysAppUdGetImageData(char              *request_url,
                             size_t             offset,
                             size_t             size,
                             SysAppUdDownloadCb cb,
                             void              *usr_param,
                             int               *http_status);
void SysAppUdRequestToStopDownload(void);
bool SysAppUdIsThisRequestToStopForDownload(void);
void SysAppUdCancelDownloadStopRequest(void);
void SysAppUdWaitForDownloadToStop(void);

#ifdef __cplusplus
}
#endif

#endif // _SYSTEM_APP_UD_MAIN_H_
