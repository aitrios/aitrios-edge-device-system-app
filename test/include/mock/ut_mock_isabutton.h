/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef _UT_MOCK_ISABUTTON_H_
#define _UT_MOCK_ISABUTTON_H_

#include "network_manager.h"

// Prototype
void IsaBtnSetNetworkManagerNotifyCallback(EsfNetworkManagerNotifyInfoCallback nw_callback,
                                           void* nw_callback_private_data,
                                           EsfNetworkManagerNotifyInfo nw_notify_info,
                                           int connect_wait_retry_count);

void IsaBtnSetClockManagerNtpSyncCallback(void (*cm_callback)(bool),
                                          bool cm_sync_success,
                                          int ntp_sync_retry_count);

#endif  // _UT_MOCK_ISABUTTON_H_
