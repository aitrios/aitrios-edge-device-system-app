/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef _UT_MOCK_NETWORK_MANAGER_H_
#define _UT_MOCK_NETWORK_MANAGER_H_

typedef enum {
  kNetworkManagerExecCbIsaBtn = 0,  // Exec cb in IsaBtn
  kNetworkManagerExecCbNM,          // Exec cb in NetworkManager
  kNetworkManagerExecCbNothing,     // Disable exec cb

  kNetworkManagerExecCbNum
} NetworkManagerExecCb;

#endif  // _UT_MOCK_NETWORK_MANAGER_H_
