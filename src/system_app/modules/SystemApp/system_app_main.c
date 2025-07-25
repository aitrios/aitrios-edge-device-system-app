/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>

#if defined(__linux__)
#include <unistd.h>
#include <pthread.h>
#endif

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <assert.h>

#include "evp/sdk_sys.h"
#include "sdk_backdoor.h"

#include "system_app_log.h"

#include "hal_i2c.h"
#include "hal_driver.h"
#include "hal_ioexp.h"
#include "system_manager.h"
#include "network_manager.h"
#include "clock_manager.h"
#include "clock_manager_setting.h"
#include "memory_manager.h"
#include "parameter_storage_manager.h"
#include "sensor_main.h"
#include "utility_msg.h"
#include "utility_timer.h"
#include "power_manager.h"
#include "firmware_manager.h"

#include "system_app_direct_command.h"
#include "system_app_configuration.h"
#include "system_app_state.h"
#include "system_app_deploy.h"
#include "system_app_ud_main.h"
#include "system_app_led.h"
#include "system_app_button.h"
#include "system_app_timer.h"
#include "system_app_util.h"
#include "system_app_main_private.h"

//
// Macros.
//

#define MAINTHREAD_STACKSIZE (12288)
#define NETWORK_CONNECT_RETRY_NUM (15)

// Timeout count to wait for state queue to be empty for deploy reboot.

#define REBOOT_RETRY_NUM_FOR_DEPLOY (30)

//
// File private structure and enum.
//

//
// File static variables.
//
#if defined(__NuttX__)
static const char *sc_dev_name = "/dev/esp/partition/evp_data";
static const char *sc_mnt_name = "/evp_data";
static const char *sc_fformat = "littlefs";
#endif

static EsfNetworkManagerHandle s_esfnm_handle = ESF_NETWORK_MANAGER_INVALID_HANDLE;
STATIC bool s_ntp_sync_notify = false;
STATIC bool s_ntp_sync_done = false;
static bool s_is_evp_connect_checked = false;
static int s_connect_info = -1;

#if !defined(__NuttX__)
static pthread_t g_systemapp_main;
static bool g_systemapp_signalled;
#endif

//
// File static private functions.
//

/*----------------------------------------------------------------------------*/
STATIC RetCode CheckProjectIdAndRegisterToken(void)
{
    RetCode ret = kRetNotFound;

    size_t project_id_size = ESF_SYSTEM_MANAGER_PROJECT_ID_MAX_SIZE;
    size_t register_token_size = ESF_SYSTEM_MANAGER_REGISTER_TOKEN_MAX_SIZE;

    char *project_id = (char *)malloc(project_id_size);
    char *register_token = (char *)malloc(register_token_size);

    if (project_id == NULL || register_token == NULL) {
        SYSAPP_ERR("malloc");
        ret = kRetMemoryError;
        goto exit;
    }

    EsfSystemManagerResult res;

    res = EsfSystemManagerGetProjectId(project_id, &project_id_size);

    if (res != kEsfSystemManagerResultOk) {
        SYSAPP_ERR("EsfSystemManagerGetProjectId:%d", res);
        goto exit;
    }

    res = EsfSystemManagerGetRegisterToken(register_token, &register_token_size);

    if (res != kEsfSystemManagerResultOk) {
        SYSAPP_ERR("EsfSystemManagerGetProjectId:%d", res);
        goto exit;
    }

    SYSAPP_INFO("ProjectId:%s", project_id);
    SYSAPP_INFO("RegiToken:%s", register_token);

    /* Check if ProjectId and RegisterToken are set */

    if (project_id[0] != '\0' && register_token[0] != '\0') {
        ret = kRetOk;
    }

exit:
    /* Clean up */

    if (project_id) {
        free(project_id);
    }

    if (register_token) {
        free(register_token);
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC ToOperation ToOperatingStatus(void)
{
    /* Check whether to launch InitialSettingApp */

    ToOperation operation = ToSystem;
    char *mqtt_host = NULL;
    char *mqtt_port = NULL;

    /* Check if QR code mode is enabled */

    int32_t qr_mode_tmo = 0;

    EsfSystemManagerResult res = EsfSystemManagerGetQrModeTimeoutValue(&qr_mode_tmo);

    if (res != kEsfSystemManagerResultOk) {
        SYSAPP_ERR("EsfSystemManagerGetQrModeTimeoutValue:%d", res);
        qr_mode_tmo = 0;
    }

    SYSAPP_INFO("QrModeTimeoutValue=%d", qr_mode_tmo);

    if (qr_mode_tmo != 0) {
        operation = ToInitialSetting;
        goto errout;
    }

    /* Check if QR code mode is enabled form endpoint */

    size_t mqtt_host_size = ESF_SYSTEM_MANAGER_EVP_HUB_URL_MAX_SIZE;
    size_t mqtt_port_size = ESF_SYSTEM_MANAGER_EVP_HUB_PORT_MAX_SIZE;

    mqtt_host = (char *)malloc(mqtt_host_size);
    mqtt_port = (char *)malloc(mqtt_port_size);

    if (mqtt_host == NULL || mqtt_port == NULL) {
        SYSAPP_ERR("malloc");
        goto errout;
    }

    res = EsfSystemManagerGetEvpHubUrl(mqtt_host, &mqtt_host_size);

    if (res != kEsfSystemManagerResultOk) {
        SYSAPP_ERR("EsfSystemManagerGetEvpHubUrl:%d", res);
        mqtt_host[0] = '\0';
    }

    res = EsfSystemManagerGetEvpHubPort(mqtt_port, &mqtt_port_size);

    if (res != kEsfSystemManagerResultOk) {
        SYSAPP_ERR("EsfSystemManagerGetEvpHubPort:%d", res);
        mqtt_port[0] = '\0';
    }

    SYSAPP_INFO("Host[%s]", mqtt_host);
    SYSAPP_INFO("Port[%s]", mqtt_port);

    if (mqtt_host[0] == '\0' || mqtt_port[0] == '\0') {
        /* When there is no data in the endpoint URL and port */

        operation = ToInitialSetting;

#if defined(CONFIG_BOARD_WIFI_SMALL_ES)
        /* T3Ws does not support PS mode. It will be forced to set to QR code mode */

        EsfSystemManagerSetQrModeTimeoutValue(-1);
#endif
    }
    else {
        /* If endpoint is set and projectId and RegisterToken are set,
     *transition to InitialSettingApp. */

        if (CheckProjectIdAndRegisterToken() == kRetOk) {
            operation = ToInitialSetting;
        }
    }

errout:
    /* Clean up */

    if (mqtt_host) {
        free(mqtt_host);
    }
    if (mqtt_port) {
        free(mqtt_port);
    }

    return operation;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode ExecInitialSettingApp(void)
{
    /* Launch initial_setting_app */

    SYSAPP_INFO("Exec initial_setting_app");

#if defined(__NuttX__)
    extern int initial_setting_app_main(int argc, char *argv[]);

    pid_t pid;
    int quit_status = 0;

    pid = task_create("initial_setting_app", CONFIG_EXTERNAL_ISAPP_PRIORITY,
                      CONFIG_EXTERNAL_ISAPP_STACKSIZE, initial_setting_app_main, NULL);
    if (pid < 0) {
        SYSAPP_ERR("Failed to create task");
        return 1;
    }

    /* Suspend execution of process until child process terminate */

    for (;;) {
        int ret = waitpid(pid, &quit_status, 0);
        if (ret > 0) {
            if (WIFEXITED(quit_status)) {
                SYSAPP_ERR("SystemApp exit with status %d", WEXITSTATUS(quit_status));
            }
            break;
        }

        if (ret < 0) {
            SYSAPP_ERR("Unexpected error: %d", errno);
            break;
        }
    }
#else
    extern int initial_setting_app_main();

    /*
   * The NuttX implementation creates a new task to run the initial settings app
   * but simply waits for it to complete before continuing. For Linux, we will
   * just run the main function directly.
   */

    int ret = initial_setting_app_main();
    if (ret < 0)
        SYSAPP_ERR("Unexpected error: %d", errno);

#endif

    SYSAPP_INFO("Exit initial_setting_app");

    return kRetOk;
}

/*----------------------------------------------------------------------------*/
STATIC void NetworkManagerCallback(EsfNetworkManagerMode mode, EsfNetworkManagerNotifyInfo info,
                                   void *private_data)
{
    SYSAPP_DBG("Network callback, mode %d info %d prv_data %p", mode, info, private_data);

    if (private_data != NULL) {
        int *data = (int *)private_data;
        *data = info;
    }
}

/*----------------------------------------------------------------------------*/
STATIC void NtpSyncCallback(bool is_sync_success)
{
    if (is_sync_success) {
        SYSAPP_INFO("NTP sync done.");
    }
    else {
        SYSAPP_INFO("NTP sync failed.");
    }

    // Notify callback from ClockManager was called.

    s_ntp_sync_notify = true;

    // Save NTP sync result.

    s_ntp_sync_done = is_sync_success;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode ConnectNetwork(TerminationReason *abort_reason)
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
        SYSAPP_ERR("EsfNetworkManagerOpen() ret %d", esfnm_ret);
        ret = kRetFailed;
        goto esfnm_open_error;
    }

    esfnm_ret = EsfNetworkManagerRegisterCallback(s_esfnm_handle, NetworkManagerCallback,
                                                  (void *)&s_connect_info);

    if (esfnm_ret != kEsfNetworkManagerResultSuccess) {
        SYSAPP_ERR("EsfNetworkManagerRegisterCallback() ret %d", esfnm_ret);
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
            SYSAPP_WARN("EsfNetworkManagerSaveParameter() faild %d.", esfnm_ret);
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
                SYSAPP_INFO("Wait WiFi network connect...");

                if (s_connect_info == kEsfNetworkManagerNotifyInfoConnected) {
                    SYSAPP_INFO("WiFi connected.");
                    wifi_connected = true;
                    ret = kRetOk;
                    break;
                }

                if (connect_wait_retry > NETWORK_CONNECT_RETRY_NUM) {
                    // In case factory reset, keep ServiceLED lighting before stop network.

                    if (SysAppBtnCheckFactoryResetRequest()) {
                        EsfLedManagerSetLightingPersistence(kEsfLedManagerTargetLedService, true);
                    }

                    // Retry over, stop NetworkManager for Ether.

                    esfnm_ret = EsfNetworkManagerStop(s_esfnm_handle);

                    if (esfnm_ret != kEsfNetworkManagerResultSuccess) {
                        SYSAPP_ERR("EsfNetworkManagerStop(). ret %d", esfnm_ret);
                    }

                    break;
                }

                connect_wait_retry++;

                // Check factory reset request.

                if (SysAppBtnCheckFactoryResetRequest()) {
                    ret = kRetAbort;
                    *abort_reason = FactoryResetButtonRequested;
                    goto connect_network_abort;
                }

                // Check reboot request.

                if (SysAppBtnCheckRebootRequest()) {
                    ret = kRetAbort;
                    *abort_reason = RebootRequested;
                    goto connect_network_abort;
                }

                sleep(1);
            }
        }
        else {
            SYSAPP_ERR("EsfNetworkManagerStart() ret %d", esfnm_ret);
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
            SYSAPP_WARN("EsfNetworkManagerSaveParameter() faild %d.", esfnm_ret);
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
            connect_wait_retry = 0;

            while (true) {
                SYSAPP_INFO("Wait Ether connect...");

                if (s_connect_info == kEsfNetworkManagerNotifyInfoConnected) {
                    SYSAPP_INFO("Ether connected.");
                    ether_connected = true;
                    ret = kRetOk;
                    break;
                }

                if (connect_wait_retry > NETWORK_CONNECT_RETRY_NUM) {
                    // In case factory reset, keep ServiceLED lighting before stop network.

                    if (SysAppBtnCheckFactoryResetRequest()) {
                        EsfLedManagerSetLightingPersistence(kEsfLedManagerTargetLedService, true);
                    }

                    // Retry over, stop NetworkManager.

                    esfnm_ret = EsfNetworkManagerStop(s_esfnm_handle);

                    if (esfnm_ret != kEsfNetworkManagerResultSuccess) {
                        SYSAPP_ERR("EsfNetworkManagerStop(). ret %d", esfnm_ret);
                    }

                    break;
                }

                connect_wait_retry++;

                // Check factory reset request.

                if (SysAppBtnCheckFactoryResetRequest()) {
                    ret = kRetAbort;
                    *abort_reason = FactoryResetButtonRequested;
                    goto connect_network_abort;
                }

                // Check reboot request.

                if (SysAppBtnCheckRebootRequest()) {
                    ret = kRetAbort;
                    *abort_reason = RebootRequested;
                    goto connect_network_abort;
                }

                sleep(1);
            }
        }
        else {
            SYSAPP_ERR("EsfNetworkManagerStart() ret %d", esfnm_ret);
            ret = kRetFailed;
        }
    }

    // If both of WiFi and Ether failed, return fail.

    if ((wifi_connected == false) && (ether_connected == false)) {
        SYSAPP_ERR("WiFi and Ether connect failed.");
        ret = kRetFailed;
        goto connect_network_error;
    }

    return ret;

    //
    // Error handling.
    //

connect_network_abort:

    // In case factory reset, keep ServiceLED lighting before stop network.

    if (*abort_reason == FactoryResetButtonRequested) {
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
STATIC RetCode DisconnectNetwork(void)
{
    RetCode ret = kRetOk;

    // Stop NetworkManager.

    EsfNetworkManagerResult esfnm_ret = EsfNetworkManagerStop(s_esfnm_handle);

    if (esfnm_ret != kEsfNetworkManagerResultSuccess) {
        SYSAPP_WARN("EsfNetworkManagerStop(). ret %d", esfnm_ret);
        ret = kRetFailed;
    }

    // Unregister callback.

    esfnm_ret = EsfNetworkManagerUnregisterCallback(s_esfnm_handle);

    if (esfnm_ret != kEsfNetworkManagerResultSuccess) {
        SYSAPP_WARN("EsfNetworkManagerUnregisterCallback(). ret %d", esfnm_ret);
        ret = kRetFailed;
    }

    // Close NetworkManager.

    esfnm_ret = EsfNetworkManagerClose(s_esfnm_handle);

    if (esfnm_ret != kEsfNetworkManagerResultSuccess) {
        SYSAPP_WARN("EsfNetworkManagerClose(). ret %d", esfnm_ret);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC RetCode StartSyncNtp(TerminationReason *abort_reason)
{
    RetCode ret = kRetOk;

    //
    // Setup NTP access.
    // NTP server should be saved in EsfClockManager. (Default NTP server is too.)
    //

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
        SYSAPP_ERR("EsfClockManagerSetParams() ret %d", esfcm_ret);
        ret = kRetFailed;
        goto esfcm_set_error;
    }

    esfcm_ret = EsfClockManagerRegisterCbOnNtpSyncComplete(NtpSyncCallback);

    if (esfcm_ret != kClockManagerSuccess) {
        SYSAPP_ERR("EsfClockManagerRegisterCbOnNtpSyncComplete() ret %d", esfcm_ret);
        ret = kRetFailed;
        goto esfcm_regcb_error;
    }

    do {
        esfcm_ret = EsfClockManagerStart();

        if (esfcm_ret != kClockManagerSuccess) {
            SYSAPP_ERR("EsfClockManagerStart() ret %d", esfcm_ret);
            ret = kRetFailed;
            goto esfcm_start_error;
        }

        // Wait NTP sync.

        while (s_ntp_sync_notify != true) {
            // Check factory reset request.

            if (SysAppBtnCheckFactoryResetRequest()) {
                EsfClockManagerStop();
                ret = kRetAbort;
                *abort_reason = FactoryResetButtonRequested;
                goto esfcm_sync_abort;
            }

            // Check reboot request.

            if (SysAppBtnCheckRebootRequest()) {
                EsfClockManagerStop();
                ret = kRetAbort;
                *abort_reason = RebootRequested;
                goto esfcm_sync_abort;
            }

            SYSAPP_INFO("Wait NTP sync...");
            sleep(2);
        }

        // Reset sync notify for retry.

        s_ntp_sync_notify = false;

        // If sync failed, retry sync. (stop - restart)

        if (s_ntp_sync_done != true) {
            esfcm_ret = EsfClockManagerStop();

            if (esfcm_ret != kClockManagerSuccess) {
                SYSAPP_ERR("EsfClockManagerStop() ret %d", esfcm_ret);
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

/*----------------------------------------------------------------------------*/
STATIC RetCode StopSyncNtp(void)
{
    RetCode ret = kRetOk;

    // Stop ClockManager.

    EsfClockManagerReturnValue esfcm_ret = EsfClockManagerStop();

    if (esfcm_ret != kClockManagerSuccess) {
        SYSAPP_WARN("EsfClockManagerStop() failed %d", esfcm_ret);
        ret = kRetFailed;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
STATIC bool SetupDirMount(void)
{
#if defined(__NuttX__)
    struct stat st;

    int ret = stat(sc_mnt_name, &st);

    if ((ret == 0) && ((st.st_mode & S_IFMT) == S_IFDIR)) {
        printf("%s %d [INF] %s already exists\n", __FILE_NAME__, __LINE__, sc_mnt_name);
        return true;
    }

    // Mount necessary directories.

    printf("%s %d [INF] mount %s to %s\n", __FILE_NAME__, __LINE__, sc_dev_name, sc_mnt_name);

    ret = mount(sc_dev_name, sc_mnt_name, sc_fformat, 0, NULL);

    if (ret != 0) {
        printf("%s %d [INF] mount(evp_data) failed %d\n", __FILE_NAME__, __LINE__, errno);

        ret = mount(sc_dev_name, sc_mnt_name, sc_fformat, 0, "autoformat");

        if (ret != 0) {
            printf("%s %d [INF] mount(evp_data, autoformat) failed %d\n", __FILE_NAME__, __LINE__,
                   errno);
            return false;
        }
    }
#endif
    return true;
}

#if 0 // TODO:Should_be_unmounted
/*----------------------------------------------------------------------------*/
static void CreanupDirMount(void) {
  int ret = umount(sc_mnt_name);

  if (ret != 0) {
    printf("%s %d umount(evp_data) failed %d", __FILE_NAME__, __LINE__, errno);
  }

  return;
}
#endif

/*----------------------------------------------------------------------------*/
#if defined(__NuttX__)
STATIC void *SysAppMain(void *ptr)
{
    TerminationReason *reason = ptr;
#else
STATIC TerminationReason SysAppMain(void)
{
    TerminationReason reason;
#endif // __NuttX__
    RetCode ret = kRetOk;
#if defined(__NuttX__)
    pid_t pid = (pid_t)-1;
#endif
    struct SYS_client *sys_client = NULL;
    enum SYS_result sys_ret = SYS_RESULT_OK;
    s_is_evp_connect_checked = false;
    int reboot_tmo_cnt = 0;
    bool is_deploy_reboot = false;
    bool is_downgrade = false;

    // Initialize SsfSensor.

    SsfSensorErrCode ssfss_ret = SsfSensorInit();

    if (ssfss_ret != kSsfSensorOk) {
        SYSAPP_ERR("SsfSensorInit() ret %d", ssfss_ret);
        goto ssfss_init_error;
    }

    // Connect network. Keep retyr until connect will be succeeded.

    do {
#if defined(__NuttX__)
        ret = ConnectNetwork(reason);
#else
        ret = ConnectNetwork(&reason);
#endif // __NuttX__

        if (ret == kRetAbort) {
            SYSAPP_INFO("Network connect abort.");
            goto network_abort;
        }

        if (ret != kRetOk) {
            SYSAPP_WARN("ConnectNetwork() ret %d, retry.", ret);
        }

        // Check reboot request.

        if (SysAppBtnCheckRebootRequest()) {
            ret = kRetAbort;
#if defined(__NuttX__)
            *reason = RebootRequested;
#else
            reason = RebootRequested;
#endif // __NuttX__
            goto network_abort;
        }

        // Check factory reset request.

        if (SysAppBtnCheckFactoryResetRequest()) {
            ret = kRetAbort;
#if defined(__NuttX__)
            *reason = FactoryResetButtonRequested;
#else
            reason = FactoryResetButtonRequested;
#endif // __NuttX__
            goto network_abort;
        }

        sleep(1);
    } while (ret != kRetOk);

    // Sync NTP.
#if defined(__NuttX__)
    ret = StartSyncNtp(reason);
#else
    ret = StartSyncNtp(&reason);
#endif // __NuttX__

    if (ret != kRetOk) {
        SYSAPP_ERR("StartSyncNtp() ret %d", ret);
        goto ntp_sync_error;
    }

    // Start EvpAgent.
#if defined(__NuttX__)
    extern int evp_agent_main(int, FAR char **);
    pid = task_create("EVP Agent", 101, CONFIG_DEFAULT_TASK_STACKSIZE, evp_agent_main, NULL);

    if (pid == (pid_t)-1) {
        SYSAPP_ERR("task_create() pid %d", pid);
        goto evp_agent_create_error;
    }
#else  /* __NuttX__ */
    extern int evp_agent_startup();
    ret = evp_agent_startup();
    if (ret) {
        SYSAPP_ERR("Failed to create EVP Agent\n");
        goto evp_agent_create_error;
    }
#endif /* __NuttX__ */

    // Setup EvpAgent and get a handle.
    while (sys_client == NULL) {
        sys_client = EVP_Agent_register_sys_client();
        if (sys_client == NULL) {
            SYSAPP_WARN("Sys Client registration failed, retrying in 100ms...");
            usleep(100 * 1000); // 100ms wait
        }
    }

    // Initialize Timer block.

    ret = SysAppTimerInitialize();

    if (ret != kRetOk) {
        SYSAPP_ERR("SysAppTimerInitialize() ret %d", ret);
        goto timer_initialize_failed;
    }

    // Initialize DirectCommand block.

    ret = SysAppDcmdInitialize(sys_client);

    if (ret != kRetOk) {
        SYSAPP_ERR("SysAppDcmdInitialize(%p) ret %d", sys_client, ret);
        goto direct_command_initialize_failed;
    }

    // Initialize Configuration block.

    ret = SysAppCfgInitialize(sys_client);

    if (ret != kRetOk) {
        SYSAPP_ERR("SysAppCfgInitialize(%p) ret %d", sys_client, ret);
        goto configuration_initialize_failed;
    }

    // Initialize State block.
    ret = SysAppStaInitialize(sys_client);
    if (ret != kRetOk) {
        SYSAPP_ERR("SysAppStaInitialize(%p) ret %d", sys_client, ret);
        goto state_initialize_failed;
    }

    // Initialize upload and download block.
    ret = SysAppUdInitialize(sys_client);

    if (ret != kRetOk) {
        SYSAPP_ERR("SysAppUdInitialize(%p) ret %d", sys_client, ret);
        goto ud_initialize_failed;
    }

    // Initialize Deploy block.

    ret = SysAppDeployInitialize();

    if (ret != kRetOk) {
        SYSAPP_ERR("SysAppDeployInitialize(%p) ret %d", sys_client, ret);
        goto deploy_initialize_failed;
    }

    // Process loop.
    while (true) {
        // Check EVP Connection and control LED.

        if (!s_is_evp_connect_checked) {
            s_is_evp_connect_checked = true;
        }

#if !defined(__NuttX__)
        if (g_systemapp_signalled)
            break;
#endif

        sys_ret = SYS_process_event(sys_client, 1000);

        if (sys_ret == SYS_RESULT_SHOULD_EXIT) {
            SYSAPP_ERR("SYS_process_event() ret %d", ret);
            break;
        }

#if defined(__NuttX__)
        if (SysAppDcmdCheckSelfTerminate(reason)) {
            SYSAPP_DBG("Self terminated. reason %d", *reason);
#else
        if (SysAppDcmdCheckSelfTerminate(&reason)) {
            SYSAPP_DBG("Self terminated. reason %d", reason);
#endif // __NuttX__
            break;
        }

        if (SysAppBtnCheckRebootRequest()) {
            SYSAPP_INFO("Reboot was requested by button.");
#if defined(__NuttX__)
            *reason = RebootRequested;
#else
            reason = RebootRequested;
#endif // __NuttX__
            break;
        }

        if (SysAppBtnCheckFactoryResetRequest()) {
            SYSAPP_INFO("Factory reset was requested by button.");
#if defined(__NuttX__)
            *reason = FactoryResetButtonRequested;
#else
            reason = FactoryResetButtonRequested;
#endif // __NuttX__
            break;
        }

        if (SysAppDeployCheckResetRequest(&is_downgrade)) {
            if (is_deploy_reboot == false) {
                /* Wait until the state queue is empty */

                if (SysAppStaIsStateQueueEmpty()) {
                    SYSAPP_INFO("=== Reset was requested by deploy ===");
                    is_deploy_reboot = true;
                    reboot_tmo_cnt = 0;
                }
                else {
                    // Remedy: If queue is not empty after 30 loops, forced reset is performed.

                    SYSAPP_INFO("Wait until the state queue is empty:%d", reboot_tmo_cnt);

                    if (reboot_tmo_cnt++ > REBOOT_RETRY_NUM_FOR_DEPLOY) {
                        SYSAPP_INFO("Timeout");
                        SYSAPP_INFO("reboot device");
                        if (is_downgrade) {
#if defined(__NuttX__)
                            *reason = FactoryResetDeployRequested;
#else
                            reason = FactoryResetDeployRequested;
#endif // __NuttX__
                        }
                        else {
#if defined(__NuttX__)
                            *reason = RebootRequested;
#else
                            reason = RebootRequested;
#endif
                        }
                        break;
                    }
                }
            }
            else {
                /* Wait until the cloud is notified.
         * As a workaround, wait REBOOT_RETRY_NUM_FOR_DEPLOY seconds and then reboot */

                SYSAPP_INFO("Wait reboot:%d", reboot_tmo_cnt);

                if (reboot_tmo_cnt++ > REBOOT_RETRY_NUM_FOR_DEPLOY) {
                    SYSAPP_INFO("reboot device");
                    if (is_downgrade) {
#if defined(__NuttX__)
                        *reason = FactoryResetDeployRequested;
#else
                        reason = FactoryResetDeployRequested;
#endif
                    }
                    else {
#if defined(__NuttX__)
                        *reason = RebootRequested;
#else
                        reason = RebootRequested;
#endif
                    }
                    break;
                }
            }
        }
    }

    // Finalize process.

    // Stop Keep Alive of WDT

#if defined(__NuttX__)
    if (*reason != UnDefined) {
#else
    if (reason != UnDefined) {
#endif
        SYSAPP_INFO("Stop Keep Alive of WDT");
        EsfPwrMgrWdtTerminate();
    }

    SysAppDeployFinalize();

deploy_initialize_failed:

    SysAppUdFinalize();

ud_initialize_failed:

    SysAppStaFinalize();

state_initialize_failed:

    SysAppCfgFinalize();

configuration_initialize_failed:

    SysAppDcmdFinalize();

direct_command_initialize_failed:

    SysAppTimerFinalize();

timer_initialize_failed:

    if (sys_client != NULL) {
        int evp_unreg_ret = EVP_Agent_unregister_sys_client(sys_client);
        if (evp_unreg_ret != 0) {
            SYSAPP_ERR("EVP_Agent_unregister_sys_client() ret %d", evp_unreg_ret);
        }
    }

#if defined(__NuttX__)
    if (pid != (pid_t)-1) {
        task_delete(pid);
    }
#else  /* __NuttX__ */
    extern void evp_agent_shutdown();
    evp_agent_shutdown();
#endif /* __NuttX__ */

evp_agent_create_error:

    StopSyncNtp();

ntp_sync_error:

#if defined(__NuttX__)
    // In case factory reset, keep ServiceLED lighting before stop network.

    if ((*reason == FactoryResetRequested) || (*reason == FactoryResetButtonRequested) ||
        (*reason == FactoryResetDeployRequested)) {
        EsfLedManagerSetLightingPersistence(kEsfLedManagerTargetLedService, true);
    }
#endif /* __NuttX__ */

    DisconnectNetwork();

network_abort:

    s_is_evp_connect_checked = false;

    SsfSensorExit();

ssfss_init_error:

#if defined(__NuttX__)
    pthread_exit(reason);

    return NULL;
#else
    return reason;
#endif /* __NuttX__ */
}

/*----------------------------------------------------------------------------*/
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if defined SYSTEM_APP_UT && defined(__NuttX__)
int system_app_main_for_test(int argc, FAR char *argv[])
{
#elif !defined(__NuttX__) // SYSTEM_APP_UT
STATIC void *system_app_main(void *data)
{
#else
int main(int argc, FAR char *argv[])
{
    (void)argc;
    (void)argv;
#endif // SYSTEM_APP_UT
    int ret;
#if defined(__NuttX__)
    pthread_t sysapp_main;
    pthread_attr_t sysapp_main_attr;
#endif
    TerminationReason reason = UnDefined;
    RetCode isa_ret = kRetOk;

#ifdef CONFIG_FIRMWARE_VERSION
    SYSAPP_DBG("FW version  :%s\n", CONFIG_FIRMWARE_VERSION);
#endif

    // Mount directries.

    if (SetupDirMount() != true) {
        printf("mount and format faild\n");
        goto errout;
    }

    // Check and execute the conditions to launch initial_setting_app.

    if (ToOperatingStatus() == ToInitialSetting) {
        isa_ret = ExecInitialSettingApp();

        if (isa_ret == kRetOk) {
            // initial_setting_app has finished launching.

            return 0;
        }
    }

    // Initialize Button block.

    ret = SysAppBtnInitialize();

    if (ret != kRetOk) {
        SYSAPP_ERR("SysAppBtnInitialize() ret %d", ret);
        reason = RebootRequested;
        goto errout;
    }

    // If InitialSettingApp cannot be started,
    // the device will wait for a reboot request via the button.

    if (isa_ret != kRetOk) {
        SYSAPP_ERR("ExecInitialSettingApp() ret %d", isa_ret);
        goto errout;
    }

#if defined(__NuttX__)
    // Create SyaAppMain thread.

    ret = pthread_attr_init(&sysapp_main_attr);

    if (ret != 0) {
        SYSAPP_ERR("pthread_attr_init() ret %d\n", ret);
        goto errout;
    }

    ret = pthread_attr_setstacksize(&sysapp_main_attr, MAINTHREAD_STACKSIZE);

    if (ret != 0) {
        SYSAPP_ERR("pthread_attr_setstacksize() ret %d\n", ret);
        goto errout;
    }

    ret = pthread_create(&sysapp_main, &sysapp_main_attr, SysAppMain, &reason);

    if (ret != 0) {
        SYSAPP_ERR("pthread_create() ret %d\n", ret);
        goto errout;
    }

    // Wait SysAppMain ends.

    ret = pthread_join(sysapp_main, NULL);

    if (ret != 0) {
        SYSAPP_ERR("pthread_join() ret %d\n", ret);
    }
#else
    reason = SysAppMain();
#endif /* __NuttX__ */

errout:
#if 0 // TODO:Should_be_unmounted
  // Clean up mount.

  CreanupDirMount();
#endif

    // Execute reboot or shutdown if requested.

    if (reason == RebootRequested) {
        SysAppDcmdRebootCore();
    }
    else if (reason == FactoryResetRequested) {
        SysAppDcmdFactoryResetCore();
    }
    else if (reason == FactoryResetButtonRequested) {
        SysAppBtnExecuteFactoryResetCore();
    }
    else if (reason == FactoryResetDeployRequested) {
        SysAppDeployFactoryReset();
    }
    else {
#if defined(__NuttX__)
        // If SystemApp terminates due to an error, etc.,
        // it will wait for a factory reboot request via the button.

        for (;;) {
            SYSAPP_INFO("Check factory reset request.\n");

            if (SysAppBtnCheckFactoryResetRequest()) {
                // Stop Keep Alive of WDT

                SYSAPP_INFO("Stop Keep Alive of WDT");
                EsfPwrMgrWdtTerminate();

                SYSAPP_INFO("Factory reset was requested by button.\n");
                SysAppBtnExecuteFactoryResetCore();
                break;
            }

            sleep(1);
        }
#else
        /*
     * We have no button manager currently on Linux and so can't wait for a hw
     * reset signal - warn and return.
     */
        SYSAPP_WARN("Unknown reason for SystemApp main thread exit. Returning\n");
#endif
    }

    SysAppBtnFinalize();

    return 0;
}

/*
 *TODO:Some test case for this code later 
 *&& !defined(SYSTEM_APP_UT) will be deleted later
*/
#if !defined(__NuttX__) && !defined(SYSTEM_APP_UT)
int startup_system_app()
{
    int ret;

    ret = pthread_create(&g_systemapp_main, NULL, system_app_main, NULL);
    if (ret) {
        SYSAPP_ERR("Failed to create SystemApp thread\n");
        return ret;
    }

    pthread_setname_np(g_systemapp_main, "system-app");
    return 0;
}

int terminate_system_app()
{
    int ret;

    g_systemapp_signalled = true;

    ret = pthread_join(g_systemapp_main, NULL);
    if (ret) {
        SYSAPP_ERR("Failed to join SystemApp thread\n");
        return ret;
    }

    return 0;
}
#endif /* !__NuttX__ */

#ifdef __cplusplus
}
#endif /* __cplusplus */
