/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

/****************************************************************************
 * Included Files
 ****************************************************************************/
#ifdef INITIAL_SETTING_APP_UT
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include "network_manager.h"
#include "system_manager.h"
#include "clock_manager.h"
#include "clock_manager_setting.h"
#include "led_manager.h"
#include "initial_setting_app_log.h"
#include "system_app_common.h"
#include "initial_setting_app_button.h"
#include "initial_setting_app_util.h"
#endif // INITIAL_SETTING_APP_UT

/****************************************************************************
 * Pre-processor definitions
 ****************************************************************************/

// Wait time for NTP sync (seconds)
#define NTP_SYNC_WAIT_MAX_SEC (30)

// Wait time for Wifi connection (seconds)
#define WIFI_CONNECT_WAIT_MAX_SEC (15)

// Wait time for Ether connection (seconds)
// If waiting for WiFi connection, it will be half the time
#define ETHER_CONNECT_WAIT_MAX_SEC (30)

/****************************************************************************
 * Private Functions
 ****************************************************************************/

// --> TENTATIVE!! SHOULD BE DELETED.

STATIC EsfNetworkManagerHandle s_esfnm_handle = ESF_NETWORK_MANAGER_INVALID_HANDLE;
STATIC bool s_ntp_sync_notify = false;
STATIC bool s_ntp_sync_done = false;
static int s_connect_info = -1;

/*----------------------------------------------------------------------------*/
STATIC void NetworkManagerCallback(EsfNetworkManagerMode mode, EsfNetworkManagerNotifyInfo info,
                                   void *private_data)
{
    ISA_INFO("Network callback, mode %d info %d prv_data %p", mode, info, private_data);

    if (private_data != NULL) {
        int *data = (int *)private_data;
        *data = info;
    }
}

/*----------------------------------------------------------------------------*/
STATIC void NtpSyncCallback(bool is_sync_success)
{
    if (is_sync_success) {
        ISA_INFO("NTP sync done.");
    }
    else {
        ISA_INFO("NTP sync failed.");
    }

    // Notify callback from ClockManager was called.

    s_ntp_sync_notify = true;

    // Save NTP sync result.

    s_ntp_sync_done = is_sync_success;
}

/*--------------------------------------------------------------------------*/
STATIC RetCode ConnectNetwork(void)
{
    //
    // 1. If SSID is written, try to connect WiFi.
    // 2. If connect WiFi failed or there is no SSID, try to connect Ether
    //

    RetCode ret = kRetOk;

    // Setup network access.

    s_connect_info = -1;

    EsfNetworkManagerResult esfnm_ret = EsfNetworkManagerOpen(
        kEsfNetworkManagerModeNormal, kEsfNetworkManagerHandleTypeControl, &s_esfnm_handle);

    if (esfnm_ret != kEsfNetworkManagerResultSuccess) {
        ISA_ERR("EsfNetworkManagerOpen() ret %d", esfnm_ret);
        ret = kRetFailed;
        goto esfnm_open_error;
    }

    esfnm_ret = EsfNetworkManagerRegisterCallback(s_esfnm_handle, NetworkManagerCallback,
                                                  (void *)&s_connect_info);

    if (esfnm_ret != kEsfNetworkManagerResultSuccess) {
        ISA_ERR("EsfNetworkManagerRegisterCallback() ret %d", esfnm_ret);
        ret = kRetFailed;
        goto esfnm_register_cb_error;
    }

    // WiFi.

    bool wifi_connected = false;
    uint32_t connect_wait_retry = 0;

    EsfNetworkManagerParameterMask esfnm_mask = {0};
    EsfNetworkManagerParameter esfnm_param = {0};
    esfnm_mask.normal_mode.wifi_sta.ssid = 1;

    esfnm_ret = EsfNetworkManagerLoadParameter(&esfnm_mask, &esfnm_param);

    if ((esfnm_ret == kEsfNetworkManagerResultSuccess) &&
        (strlen(esfnm_param.normal_mode.wifi_sta.ssid) >
         1 /*TODO Should be "> 0" but NetworkManager cannot save/load length 0 string.*/)) {
        // Try to connect WiFi.

        memset(&esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
        memset(&esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
        esfnm_mask.normal_mode.netif_kind = 1;
        esfnm_param.normal_mode.netif_kind = 0; // WiFi.

        esfnm_ret = EsfNetworkManagerSaveParameter(&esfnm_mask, &esfnm_param);

        if (esfnm_ret != kEsfNetworkManagerResultSuccess) {
            ISA_WARN("EsfNetworkManagerSaveParameter() faild %d.", esfnm_ret);
        }

        while (true) {
            esfnm_ret = EsfNetworkManagerStart(s_esfnm_handle,
                                               kEsfNetworkManagerStartTypeSaveParameter, NULL);

            if (esfnm_ret != kEsfNetworkManagerResultStatusAlreadyRunning) {
                break;
            }

            sleep(1);
        }

        if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
            while (true) {
                ISA_INFO("Wait WiFi network connect...");

                if (s_connect_info == kEsfNetworkManagerNotifyInfoConnected) {
                    ISA_INFO("WiFi connected.");
                    wifi_connected = true;
                    ret = kRetOk;
                    break;
                }

                if (connect_wait_retry > WIFI_CONNECT_WAIT_MAX_SEC) {
                    // In case factory reset, keep ServiceLED lighting before stop network.

                    if (IsaBtnCheckFactoryResetRequest()) {
                        EsfLedManagerSetLightingPersistence(kEsfLedManagerTargetLedService, true);
                    }

                    // Retry over, stop NetworkManager for Ether.

                    esfnm_ret = EsfNetworkManagerStop(s_esfnm_handle);

                    if (esfnm_ret != kEsfNetworkManagerResultSuccess) {
                        ISA_ERR("EsfNetworkManagerStop(). ret %d", esfnm_ret);
                    }

                    break;
                }

                connect_wait_retry++;

                // Check reboot request.

                if (IsaBtnCheckRebootRequest()) {
                    ret = kRetAbort;
                    goto connect_network_abort;
                }

                // Check factory_reset request.

                if (IsaBtnCheckFactoryResetRequest()) {
                    ret = kRetAbort;
                    goto connect_network_abort;
                }

                sleep(1);
            }
        }
        else {
            ISA_ERR("EsfNetworkManagerStart() ret %d", esfnm_ret);
            ret = kRetFailed;
        }
    }

    // Ether.

    bool ether_connected = false;

    if (wifi_connected != true) {
        // Try to connect Ether.

        memset(&esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
        memset(&esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
        esfnm_mask.normal_mode.netif_kind = 1;
        esfnm_param.normal_mode.netif_kind = 1; // Ether.

        esfnm_ret = EsfNetworkManagerSaveParameter(&esfnm_mask, &esfnm_param);

        if (esfnm_ret != kEsfNetworkManagerResultSuccess) {
            ISA_WARN("EsfNetworkManagerSaveParameter() faild %d.", esfnm_ret);
        }

        while (true) {
            // Wait NetworkManager ready. (For case that connet WiFi fail.)

            esfnm_ret = EsfNetworkManagerStart(s_esfnm_handle,
                                               kEsfNetworkManagerStartTypeSaveParameter, NULL);

            if (esfnm_ret != kEsfNetworkManagerResultStatusAlreadyRunning) {
                break;
            }

            sleep(1);
        }

        if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
            while (true) {
                ISA_INFO("Wait Ether connect...");

                if (s_connect_info == kEsfNetworkManagerNotifyInfoConnected) {
                    ISA_INFO("Ether connected.");
                    ether_connected = true;
                    ret = kRetOk;
                    break;
                }

                if (connect_wait_retry > ETHER_CONNECT_WAIT_MAX_SEC) {
                    // In case factory reset, keep ServiceLED lighting before stop network.

                    if (IsaBtnCheckFactoryResetRequest()) {
                        EsfLedManagerSetLightingPersistence(kEsfLedManagerTargetLedService, true);
                    }

                    // Retry over, stop NetworkManager.

                    esfnm_ret = EsfNetworkManagerStop(s_esfnm_handle);

                    if (esfnm_ret != kEsfNetworkManagerResultSuccess) {
                        ISA_ERR("EsfNetworkManagerStop(). ret %d", esfnm_ret);
                    }

                    break;
                }

                connect_wait_retry++;

                // Check reboot request.

                if (IsaBtnCheckRebootRequest()) {
                    ret = kRetAbort;
                    goto connect_network_abort;
                }

                // Check factory_reset request.

                if (IsaBtnCheckFactoryResetRequest()) {
                    ret = kRetAbort;
                    goto connect_network_abort;
                }

                sleep(1);
            }
        }
        else {
            ISA_ERR("EsfNetworkManagerStart() ret %d", esfnm_ret);
            ret = kRetFailed;
        }
    }

    // If both of WiFi and Ether failed, return fail.

    if ((wifi_connected == false) && (ether_connected == false)) {
        ISA_CRIT("WiFi and Ether connect failed.");
        ret = kRetFailed;
        goto connect_network_error;
    }

    return ret;

    //
    // Error handling.
    //

connect_network_abort:

    // In case factory reset, keep ServiceLED lighting before stop network.

    if (IsaBtnCheckFactoryResetRequest()) {
        EsfLedManagerSetLightingPersistence(kEsfLedManagerTargetLedService, true);
    }

    EsfNetworkManagerStop(s_esfnm_handle);

connect_network_error:

    EsfNetworkManagerUnregisterCallback(s_esfnm_handle);

esfnm_register_cb_error:

    EsfNetworkManagerClose(s_esfnm_handle);

esfnm_open_error:

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode StartSyncNtp(void)
{
    RetCode ret = kRetOk;

    //
    // Setup NTP access.
    // NTP server should be saved in EsfClockManager. (Default NTP server is too.)
    //

    uint32_t sync_wait_retry = 0;

    EsfClockManagerParams cm_param = {
        .common.sync_interval = 64,
        .common.polling_time = 3,
        .skip_and_limit.type = kClockManagerParamTypeDefault,
        .slew_setting.type = kClockManagerParamTypeDefault,
    };

    EsfClockManagerParamsMask cm_mask = {
        .common.sync_interval = 1,
        .common.polling_time = 1,
        .skip_and_limit.type = 1,
        .slew_setting.type = 1,
    };

    EsfClockManagerReturnValue esfcm_ret = EsfClockManagerSetParams(&cm_param, &cm_mask);

    if (esfcm_ret != kClockManagerSuccess) {
        ISA_CRIT("EsfClockManagerSetParams() ret %d", esfcm_ret);
        ret = kRetFailed;
        goto esfcm_set_error;
    }

    esfcm_ret = EsfClockManagerRegisterCbOnNtpSyncComplete(NtpSyncCallback);

    if (esfcm_ret != kClockManagerSuccess) {
        ISA_CRIT("EsfClockManagerRegisterCbOnNtpSyncComplete() ret %d", esfcm_ret);
        ret = kRetFailed;
        goto esfcm_regcb_error;
    }

    do {
        esfcm_ret = EsfClockManagerStart();

        if (esfcm_ret != kClockManagerSuccess) {
            ISA_CRIT("EsfClockManagerStart() ret %d", esfcm_ret);
            ret = kRetFailed;
            goto esfcm_start_error;
        }

        // Wait NTP sync.

        while (s_ntp_sync_notify != true) {
            // Check reboot request.

            if (IsaBtnCheckRebootRequest()) {
                EsfClockManagerStop();
                ret = kRetAbort;
                goto esfcm_sync_abort;
            }

            // Check factory_reset request.

            if (IsaBtnCheckFactoryResetRequest()) {
                EsfClockManagerStop();
                ret = kRetAbort;
                goto esfcm_sync_abort;
            }

            if (sync_wait_retry > NTP_SYNC_WAIT_MAX_SEC) {
                ISA_CRIT("NTP sync timeout.");
                EsfClockManagerStop();
                ret = kRetFailed;
                goto esfcm_sync_abort;
            }

            ISA_INFO("Wait NTP sync...");
            sync_wait_retry++;
            sleep(1);
        }

        // Reset sync notify for retry.

        s_ntp_sync_notify = false;

        // If sync failed, retry sync. (stop - restart)

        if (s_ntp_sync_done != true) {
            esfcm_ret = EsfClockManagerStop();

            if (esfcm_ret != kClockManagerSuccess) {
                ISA_ERR("EsfClockManagerStop() ret %d", esfcm_ret);
            }
        }
    } while (s_ntp_sync_done != true);

esfcm_sync_abort:
esfcm_start_error:

    EsfClockManagerUnregisterCbOnNtpSyncComplete();

esfcm_regcb_error:
esfcm_set_error:

    return ret;
}

// <-- TENTATIVE!! SHOULD BE DELETED.
