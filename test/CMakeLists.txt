cmake_minimum_required(VERSION 3.10)
set(PROJECT_NAME retrofit_unit_test)
project(${PROJECT_NAME} LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ------------------------------
# Common Setting
# ------------------------------
option(RETROFIT_UNIT_DEBUG "unit test debug option" ON)
if(RETROFIT_UNIT_DEBUG)
    set(CFGOPT "-O0 -g -coverage")
    #set(CFGOPT "-O0 -g -fsanitize=address -fno-omit-frame-pointer")
else()
    set(CFGOPT "-O2")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall ${CFGOPT}")

set(TEST_TOP_DIR ${CMAKE_SOURCE_DIR})
set(REPOSITRY_TOP_DIR ${CMAKE_SOURCE_DIR}/..)
set(MOCKDIR ${TEST_TOP_DIR}/mock)

include_directories(/usr/include)

add_definitions(-DSYSTEM_APP_UT)
add_definitions(-DINITIAL_SETTING_APP_UT)

# for log output
# add_definitions(-DUT_LOG_OUTPUT_ENABLE)

# for sw wdt
add_definitions(-DCONFIG_EXTERNAL_POWER_MANAGER_SW_WDT_ID_2=2)

if(NOT DEFINED DEVICE_TYPE)
  set(DEVICE_TYPE Undefine)
endif()

if(DEVICE_TYPE STREQUAL "Raspi")
  add_definitions(-D__linux__)
  add_definitions(-U__NuttX__)
  add_definitions(-DCONFIG_EXTERNAL_SYSTEMAPP_STREAM_AND_IMAGE_CONCURRENT)
  message(STATUS "Building for Raspi: __linux__ is enabled.")
else()
  add_definitions(-D__NuttX__)
  add_definitions(-U__linux__)
  message(STATUS "Building for ${DEVICE_TYPE}: __NuttX__ is enabled.")
endif()

message("DEVICE_TYPE=${DEVICE_TYPE}")

if((DEVICE_TYPE STREQUAL "T3P" OR DEVICE_TYPE STREQUAL "T3Ws") AND EXISTS "${CMAKE_SOURCE_DIR}/private")
    set(CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION TRUE)
endif()

# ------------------------------
# Define mock source codes
# ------------------------------
set(MOCK_SRCS
    ${MOCKDIR}/ut_mock_network_manager.c
    ${MOCKDIR}/ut_mock_led_manager.c
    ${MOCKDIR}/ut_mock_codec_json.c
    ${MOCKDIR}/ut_mock_button_manager.c
    ${MOCKDIR}/ut_mock_codec_base64.c
    ${MOCKDIR}/ut_mock_log_manager.c
    ${MOCKDIR}/ut_mock_power_manager.c
    ${MOCKDIR}/ut_mock_clock_manager.c
    ${MOCKDIR}/ut_mock_firmware_manager.c
    ${MOCKDIR}/ut_mock_system_manager.c
    ${MOCKDIR}/ut_mock_devicesetting.c
    ${MOCKDIR}/ut_mock_esfsensor.c
    ${MOCKDIR}/ut_mock_hal.c
    ${MOCKDIR}/ut_mock_memory_manager.c
    ${MOCKDIR}/ut_mock_parameter_storage_manager.c
    ${MOCKDIR}/ut_mock_utility_log.c
    ${MOCKDIR}/ut_mock_utility_msg.c
    ${MOCKDIR}/ut_mock_utility_timer.c
    ${MOCKDIR}/ut_mock_codec_jpeg.c

    ${MOCKDIR}/ut_mock_senscord.c

    ${MOCKDIR}/ut_mock_evpagent.c

    ${MOCKDIR}/ut_mock_mbedtls.c

    ${MOCKDIR}/ut_mock_quirc.c

    ${MOCKDIR}/ut_mock_zxing.c

    ${MOCKDIR}/ut_mock_sysappcmn.c
    ${MOCKDIR}/ut_mock_sysappadditionalinfo.c
    ${MOCKDIR}/ut_mock_sysappdeploy.c
    ${MOCKDIR}/ut_mock_sysappled.c
    ${MOCKDIR}/ut_mock_sysappdcmd.c
    ${MOCKDIR}/ut_mock_sysappstate.c
    ${MOCKDIR}/ut_mock_sysapplog.c
    ${MOCKDIR}/ut_mock_sysapptimer.c
    ${MOCKDIR}/ut_mock_sysappbtn.c
    ${MOCKDIR}/ut_mock_sysappcfg.c
    ${MOCKDIR}/ut_mock_sysapptimer.c
    ${MOCKDIR}/ut_mock_sysappud.c

    ${MOCKDIR}/ut_mock_isamain.c
    ${MOCKDIR}/ut_mock_isaps.c
    ${MOCKDIR}/ut_mock_isadecode.c
    ${MOCKDIR}/ut_mock_isaqrcode.c
    ${MOCKDIR}/ut_mock_isadecodeinternal.c
    ${MOCKDIR}/ut_mock_isabutton.c
    ${MOCKDIR}/ut_mock_isatimer.c

    ${MOCKDIR}/ut_mock_printf.c
    ${MOCKDIR}/ut_mock_syslog.c
    ${MOCKDIR}/ut_mock_sched.c
    ${MOCKDIR}/ut_mock_waitpid.c
    ${MOCKDIR}/ut_mock_std_memory_allocate.c
    ${MOCKDIR}/ut_mock_mount.c
    ${MOCKDIR}/ut_mock_stat.c
    ${MOCKDIR}/ut_mock_sleep.c

    ${MOCKDIR}/ut_mock_std_pthread_h.c
    ${MOCKDIR}/ut_mock_std_time_h.c
)

if(DEFINED CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION)
    list(APPEND MOCK_SRCS ${MOCKDIR}/ut_mock_private_qr_quality_opt.c)
endif()

# ------------------------------
# Define include Directories
# ------------------------------
set(INCS
    ${TEST_TOP_DIR}/include/
    ${TEST_TOP_DIR}/include/mbedtls/include/
    ${TEST_TOP_DIR}/include/quirc/lib/
    ${TEST_TOP_DIR}/include/zxing-cpp/src/wrappers/c/
    ${REPOSITRY_TOP_DIR}/src/system_app/include/
    ${REPOSITRY_TOP_DIR}/src/system_app/modules/SystemApp/
    ${REPOSITRY_TOP_DIR}/src/initial_setting_app/

    ${TEST_TOP_DIR}/include/edge-software-framework/src/esf/network_manager/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/esf/led_manager/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/esf/button_manager/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/esf/clock_manager/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/esf/parameter_storage_manager/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/esf/log_manager/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/esf/codec/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/esf/codec/jpeg/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/esf/power_manager/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/esf/firmware_manager/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/esf/system_manager/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/esf/memory_manager/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/hal/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/utility/log/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/utility/msg/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/utility/timer/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/wasm_binding/codec/jpeg/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/wasm_binding/deviceid/include/
    ${TEST_TOP_DIR}/include/edge-software-framework/src/porting_layer/include/

    ${TEST_TOP_DIR}/include/edge-software-framework-sensor/src/esf/senscord/include/
    ${TEST_TOP_DIR}/include/edge-software-framework-sensor/src/esf/senscord_component_inference/include/
    ${TEST_TOP_DIR}/include/edge-software-framework-sensor/src/esf/sensor_main/include/
    ${TEST_TOP_DIR}/include/edge-software-framework-sensor/src/esf/sensor_ai_lib/include/

    ${TEST_TOP_DIR}/include/evp-device-agent/evp_agent/
    ${TEST_TOP_DIR}/include/evp-device-agent/evp_agent/include/
    ${TEST_TOP_DIR}/include/evp-device-agent/evp_agent/wedge-agent/include/

    ${TEST_TOP_DIR}/include/mock/
)

if(DEFINED CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION)
    list(APPEND INCS ${REPOSITRY_TOP_DIR}/src/private/)
endif()

# ------------------------------
# Define wrap symbols
# ------------------------------
set(WRAP_ESF_SYMBOLES
    ## network_manager
    EsfNetworkManagerInit
    EsfNetworkManagerDeinit
    EsfNetworkManagerOpen
    EsfNetworkManagerClose
    EsfNetworkManagerStart
    EsfNetworkManagerStop
    EsfNetworkManagerRegisterCallback
    EsfNetworkManagerSaveParameter
    EsfNetworkManagerLoadParameter
    EsfNetworkManagerUnregisterCallback

    ## led_manager
    EsfLedManagerGetStatus
    EsfLedManagerInit
    EsfLedManagerDeinit
    EsfLedManagerSetStatus
    EsfLedManagerSetLightingPersistence

    ## codec json
    EsfJsonOpen
    EsfJsonClose
    EsfJsonObjectInit
    EsfJsonSerialize
    EsfJsonObjectGet
    EsfJsonValueTypeGet
    EsfJsonStringGet
    EsfJsonIntegerGet
    EsfJsonRealGet
    EsfJsonBooleanGet
    EsfJsonStringInit
    EsfJsonObjectSet
    EsfJsonIntegerInit
    EsfJsonRealInit
    EsfJsonBooleanInit
    EsfJsonArrayInit
    EsfJsonArrayAppend
    EsfJsonDeserialize
    EsfJsonArrayCount
    EsfJsonArrayGet
    EsfJsonSerializeFree
    EsfJsonSerializeSizeGet
    EsfJsonStringInitHandle
    EsfJsonSerializeHandle

    ## button_manager
    EsfButtonManagerOpen
    EsfButtonManagerClose
    EsfButtonManagerRegisterPressedCallback
    EsfButtonManagerRegisterReleasedCallback
    EsfButtonManagerRegisterLongPressedCallback
    EsfButtonManagerUnregisterPressedCallback
    EsfButtonManagerUnregisterReleasedCallback
    EsfButtonManagerUnregisterLongPressedCallback
    EsfButtonManagerEnableNotificationCallback
    EsfButtonManagerDisableNotificationCallback

    ## codec base64
    EsfCodecBase64Encode
    EsfCodecBase64Decode
    EsfCodecBase64GetEncodeSize
    EsfCodecBase64GetDecodeSize
    EsfCodecBase64EncodeHandle

    ## codec jpeg
    EsfCodecJpegEncode
    EsfCodecJpegEncodeHandle

    ## log_manager
    EsfLogManagerInit
    EsfLogManagerDeinit
    EsfLogManagerSetParameter
    EsfLogManagerGetParameter
    EsfLogManagerStartGettingDlog
    EsfLogManagerStoreDlog
    EsfLogManagerGetLogInfo
    EsfLogManagerGetExceptionData
    EsfLogManagerStart

    ## power_manager
    EsfPwrMgrStart
    EsfPwrMgrStop
    EsfPwrMgrPrepareReboot
    EsfPwrMgrExecuteReboot
    EsfPwrMgrPrepareShutdown
    EsfPwrMgrExecuteShutdown
    EsfPwrMgrGetVoltage
    EsfPwrMgrHoursMeterGetValue
    EsfPwrMgrGetSupplyType
    EsfPwrMgrWdtTerminate
    EsfPwrMgrSwWdtStart
    EsfPwrMgrSwWdtStop
    EsfPwrMgrSwWdtKeepalive

    ## clock_manager
    EsfClockManagerSetParamsForcibly
    EsfClockManagerSetParams
    EsfClockManagerGetParams
    EsfClockManagerRegisterCbOnNtpSyncComplete
    EsfClockManagerStart
    EsfClockManagerStop
    EsfClockManagerUnregisterCbOnNtpSyncComplete
    EsfClockManagerInit
    EsfClockManagerDeinit

    ## firmware_manager
    EsfFwMgrGetFactoryResetFlag
    EsfFwMgrGetInfo
    EsfFwMgrInit
    EsfFwMgrDeinit
    EsfFwMgrSetFactoryResetFlag
    EsfFwMgrOpen
    EsfFwMgrWrite
    EsfFwMgrClose
    EsfFwMgrErase
    EsfFwMgrPostProcess
    EsfFwMgrCopyToInternalBuffer
    EsfFwMgrStartFactoryReset
    EsfFwMgrGetBinaryHeaderInfo

    ## memory_manager
    EsfMemoryManagerInitialize
    EsfMemoryManagerFinalize
    EsfMemoryManagerMap
    EsfMemoryManagerUnmap
    EsfMemoryManagerAllocate
    EsfMemoryManagerFree
    EsfMemoryManagerFopen
    EsfMemoryManagerFclose
    EsfMemoryManagerFseek
    EsfMemoryManagerFread
    EsfMemoryManagerWasmAllocate
    EsfMemoryManagerWasmFree
    EsfMemoryManagerGetHandleInfo

    ## parameter_storage_manager
    EsfParameterStorageManagerInit
    EsfParameterStorageManagerDeinit

    ## system_manager
    EsfSystemManagerGetDeviceManifest
    EsfSystemManagerSetProjectId
    EsfSystemManagerSetRegisterToken
    EsfSystemManagerGetEvpHubUrl
    EsfSystemManagerGetEvpHubPort
    EsfSystemManagerSetEvpHubUrl
    EsfSystemManagerSetEvpHubPort
    EsfSystemManagerSetEvpTls
    EsfSystemManagerGetQrModeTimeoutValue
    EsfSystemManagerSetQrModeTimeoutValue
    EsfSystemManagerGetProjectId
    EsfSystemManagerGetRegisterToken
    EsfSystemManagerGetHwInfo

    ## utility log
    UtilityLogInit
    UtilityLogOpen
    UtilityLogClose
    UtilityLogDeinit
    UtilityLogForcedOutputToUart
    UtilityLogWriteDLog
    UtilityLogWriteELog

    ## utility msg
    UtilityMsgInitialize
    UtilityMsgFinalize
    UtilityMsgRecv
    UtilityMsgSend
    UtilityMsgOpen
    UtilityMsgClose

    ## utility timer
    UtilityTimerInitialize
    UtilityTimerFinalize
    UtilityTimerCreate
    UtilityTimerDelete
    UtilityTimerStart
    UtilityTimerStop
    UtilityTimerCreateEx

    ## hal driver
    HalDriverInitialize
    HalDriverFinalize

    ## hal i2c
    HalI2cInitialize
    HalI2cFinalize

    ## hal ioexp
    HalIoexpInitialize
    HalIoexpFinalize

    ## TENTATIVE devicesetting
    SsfDeviceSettingInit
    SsfDeviceSettingDeinit
    SsfDeviceSettingOpen
    SsfDeviceSettingClose
)

set(WRAP_ESF_SENSOR_SYMBOLES
    ## sensor_main
    SsfSensorInit
    SsfSensorExit
    EsfSensorPowerOFF
    EsfSensorInit
    EsfSensorExit
    EsfSensorUtilitySetupFiles
    SsfSensorLibGetState
)

set(WRAP_SENSCORD_SYMBOLES
    ## senscord
    senscord_core_init
    senscord_core_open_stream
    senscord_stream_get_property
    senscord_core_close_stream
    senscord_core_exit
    senscord_stream_start
    senscord_stream_stop
    senscord_stream_set_property
    senscord_stream_get_frame
    senscord_stream_release_frame
    senscord_channel_get_raw_data
    senscord_frame_get_channel_from_channel_id
    senscord_get_last_error_cause
)

set(WRAP_EVP_SYMBOLES
    ## evpagent
    EVP_undeployModules
    EVP_wasm_runtime_register_natives
    evp_agent_main
    EVP_getAgentStatus
    EVP_Agent_unregister_sys_client
    EVP_Agent_register_sys_client
    SYS_set_state
    SYS_send_telemetry
    SYS_process_event
    SYS_set_response_cb
    SYS_set_configuration_cb
    SYS_register_command_cb
    SYS_get_blob
    evp_agent_startup
    evp_agent_shutdown
)

set(WRAP_MBEDTLS_SYMBOLES
    mbedtls_sha256_init
    mbedtls_sha256_starts
    mbedtls_sha256_update
    mbedtls_sha256_finish
    mbedtls_sha256_free
)

set(WRAP_QUIRC_SYMBOLES
    quirc_destroy
    quirc_new
    quirc_resize
    quirc_begin
    quirc_end
    quirc_count
    quirc_extract
    quirc_decode
)

set(WRAP_ZXING_SYMBOLES
    zxing_ImageView_new
    zxing_ImageView_delete
    zxing_BarcodeFormatsFromString
    zxing_BarcodeFormatFromString
    zxing_BarcodeFormatToString
    zxing_DecodeHints_new
    zxing_DecodeHints_delete
    zxing_DecodeHints_setTryHarder
    zxing_DecodeHints_setTryRotate
    zxing_DecodeHints_setTryInvert
    zxing_DecodeHints_setTryDownscale
    zxing_DecodeHints_setIsPure
    zxing_DecodeHints_setReturnErrors
    zxing_DecodeHints_setFormats
    zxing_DecodeHints_setBinarizer
    zxing_DecodeHints_setEanAddOnSymbol
    zxing_DecodeHints_setTextMode
    zxing_ContentTypeToString
    zxing_Result_isValid
    zxing_Result_errorMsg
    zxing_Result_format
    zxing_Result_contentType
    zxing_Result_bytes
    zxing_Result_text
    zxing_Result_ecLevel
    zxing_Result_symbologyIdentifier
    zxing_Result_orientation
    zxing_Result_isInverted
    zxing_Result_isMirrored
    zxing_ReadBarcode
    zxing_ReadBarcodes
    zxing_Result_delete
    zxing_Results_delete
    zxing_Results_size
    zxing_Results_at
)

set(WRAP_SCHED_SYMBOLES
    task_create
    task_delete
)

set(WRAP_WAITPID_SYMBOLES
    waitpid
)

set(WRAP_PRINTF_SYMBOLES
    printf
)

set(WRAP_SYSLOG_SYMBOLES
    syslog
)

set(WRAP_MOUNT_SYMBOLES
    mount
)

set(WRAP_STAT_SYMBOLES
    stat
)

set(WRAP_SLEEP_SYMBOLES
    sleep
)

set(WRAP_ISA_MAIN_SYMBOLES
    initial_setting_app_main
)

set(WRAP_ISA_PS_SYMBOLES
    IsaRunProvisioningService
)

set(WRAP_ISA_DECODE_SYMBOLES
    IsaCodecQrDecodeQrCode
)

set(WRAP_ISA_DECODE_INTERNAL_SYMBOLES
    IsaLargeHeapAlloc
    IsaLargeHeapFree
    IsaCodecQrCreateInstance
    IsaCodecQrDetect
    IsaCodecQrDecodeQrCodeInfo
    IsaCodecQrStoreDecodingResult
)

set(WRAP_ISA_QRCODE_SYMBOLES
    IsaQrcodeInit
    IsaQrcodeDecodePayload
    IsaWriteQrcodePayloadToFlash
    IsaClearMultiQRParam
    IsaQrcodeExit
)

set(WRAP_ISA_BUTTON_SYMBOLES
    IsaBtnInitialize
    IsaBtnFinalize
    IsaBtnCheckRebootRequest
    IsaBtnCheckFactoryResetRequest
    IsaBtnExecuteFactoryResetCore
)

set(WRAP_ISA_TIMER_SYMBOLES
    IsaTimerInitialize
    IsaTimerFinalize
    IsaTimerStart
    IsaTimerStop
)

if(DEFINED CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION)
    set(WRAP_PRIVATE_QR_QUALITY_OPT_SYMBOLES
        SetupCameraExposureAndMetering
    )
else()
    set(WRAP_PRIVATE_QR_QUALITY_OPT_SYMBOLES
    )
endif()

set(WRAP_SYSTEMAPP_BUTTON_SYMBOLES
    ## sysappbtn
    SysAppBtnInitialize
    SysAppBtnCheckFactoryResetRequest
    SysAppBtnFinalize
    SysAppBtnExecuteFactoryResetCore
    SysAppBtnCheckRebootRequest
)

set(WRAP_SYSTEMAPP_CMN_SYMBOLES
    ## sysappcmn
    SysAppCmnExtractStringValue
    SysAppCmnExtractNumberValue
    SysAppCmnExtractRealNumberValue
    SysAppCmnExtractBooleanValue
    SysAppCmnExtractObjectValue
    SysAppCmnGetReqId
    SysAppCmnSetStringValue
    SysAppCmnSetNumberValue
    SysAppCmnSetRealNumberValue
    SysAppCmnSetBooleanValue
    SysAppCmnSetObjectValue
    SysAppCmnSetArrayValue
    SysAppCmnMakeJsonResInfo
    SysAppCmnSetStringValueHandle
)

set(WRAP_SYSTEMAPP_DEPLOY_SYMBOLES
    ## sysappdeploy
    SysAppDeployGetFirmwareState
    SysAppDeployGetAiModelState
    SysAppDeployGetSensorCalibrationParamState
    SysAppDeployInitialize
    SysAppDeployCheckResetRequest
    SysAppDeployFinalize
    SysAppDeploy
    SysAppDeployFreeState
    SysAppDeployFactoryReset
    SysAppDeployGetCancel
)

set(WRAP_SYSTEMAPP_LED_SYMBOLES
    ## sysappled
    SysAppLedSetAppStatus
    SysAppLedUnsetAppStatus
    SysAppLedSetEnable
    SysAppLedGetEnable
)

set(WRAP_SYSTEMAPP_CFG_SYMBOLES
    ## sysappcfg
    SysAppCfgInitialize
    SysAppCfgFinalize
)

set(WRAP_SYSTEMAPP_DCMD_SYMBOLES
    ## sysappdcmd
    SysAppDcmdCheckSelfTerminate
    SysAppDcmdInitialize
    SysAppDcmdFinalize
    SysAppDcmdRebootCore
    SysAppDcmdFactoryResetCore
)

set(WRAP_SYSTEMAPP_STATE_SYMBOLES
    ## sysappstate
    SysAppStateUpdateString
    SysAppStateSendState
    SysAppStaInitialize
    SysAppStaFinalize
    SysAppStateUpdateNumberWithIdx
    SysAppStateSetInternalErrorWithIdx
    SysAppStateSetInvalidArgErrorWithIdx
    SysAppStateUpdateStringWithIdx
    SysAppStateUpdateBoolean
    SysAppStateUpdateNumber
    SysAppStateSetInvalidArgError
    SysAppStateSetInternalError
    SysAppStaClose
    SysAppStaReopenIfClose
    SysAppStateGetSensCordId
    SysAppStateGetSensCordStream
    SysAppStateGetReqId
    SysAppStateGetProtocolVersion
    SysAppStateGetTemperatureUpdateInterval
    SysAppStaIsStateQueueEmpty
    SysAppStateSendUnimplementedState
    SysAppStateIsUnimplementedTopic
)

set(WRAP_SYSTEMAPP_ADDITIONALINFO_SYMBOLES
    ## sysappadditionalinfo
    SysAppAdditionalInfoCollect
)

set(WRAP_SYSTEMAPP_LOG_SYMBOLES
    ## sysapplog
    SysAppLogGetParameterNumber
    SysAppLogGetParameterString
    SysAppLogSetParameterNumber
    SysAppLogSetParameterString
)

set(WRAP_SYSTEMAPP_UD_SYMBOLES
    ## sysappud
    SysAppUdInitialize
    SysAppUdFinalize
    SysAppUdGetImageSize
    SysAppUdGetImageData
    SysAppUdRequestToStopDownload
    SysAppUdIsThisRequestToStopForDownload
    SysAppUdCancelDownloadStopRequest
    SysAppUdWaitForDownloadToStop
)

set(WRAP_SYSTEMAPP_TIMER_SYMBOLES
    ## sysapptimer
    SysAppTimerStartTimer
    SysAppTimerStopTimer
    SysAppTimerInitialize
    SysAppTimerFinalize
    SysAppTimerUpdateTimer
)

set(WRAP_STD_TIME_H_SYMBOLES
    ## time.h
    clock_gettime
)

set(WRAP_STD_PTHREAD_H_SYMBOLES
    ## pthread.h
    pthread_create
    pthread_join
    pthread_attr_init
    pthread_attr_setstacksize
    pthread_cond_destroy
    pthread_cond_init
    pthread_cond_signal
    pthread_cond_timedwait
    pthread_mutex_destroy
    pthread_mutex_init
    pthread_mutex_lock
    pthread_mutex_unlock
    pthread_attr_destroy

    # !!!!! Caution !!!!!
    # Do NOT add "pthread_exit".
    # The prototype declaration of pthread_exit has a non-return function designator,
    # so the code after pthread_exit becomes invalid code.
    # This results in unexpected test target behavior.
    # Therefore, pthread_exit is mocked in a different way.
)

# ------------------------------
# unit tests (subdirectory)
# ------------------------------
add_subdirectory(system_app/system_app_state)
add_subdirectory(system_app/system_app_button)
add_subdirectory(system_app/system_app_main)
add_subdirectory(system_app/system_app_common)
add_subdirectory(system_app/system_app_led)
add_subdirectory(system_app/system_app_log)
add_subdirectory(system_app/system_app_timer)
add_subdirectory(system_app/system_app_ud_main)
add_subdirectory(system_app/system_app_configuration)
add_subdirectory(system_app/system_app_deploy)
add_subdirectory(system_app/system_app_direct_command)

add_subdirectory(initial_setting_app/initial_setting_app_qrcode)
add_subdirectory(initial_setting_app/main)
add_subdirectory(initial_setting_app/initial_setting_app_ps)
add_subdirectory(initial_setting_app/initial_setting_app_ps_stub)
add_subdirectory(initial_setting_app/initial_setting_app_qr_decode)
add_subdirectory(initial_setting_app/initial_setting_app_qr_decode_internal)
add_subdirectory(initial_setting_app/initial_setting_app_button)
add_subdirectory(initial_setting_app/initial_setting_app_timer)

if(DEFINED CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION)
    add_subdirectory(private/qr_quality_optimization)
endif()
