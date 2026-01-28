/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include "system_app_additional_info.h"
#include "system_app_common.h"
#include "system_app_log.h"
#include "system_app_util.h"

//
// Macros.
//

// Provide default values if not defined by build system

#ifndef EDC_VERSION
#define EDC_VERSION ""
#endif

//
// Device profile configuration for additional_info items
//

#if defined(CONFIG_EXTERNAL_SYSTEMAPP_VERSION_PROFILE_FULL)
#define SYSAPP_USE_EDC_VERSION 1
#define SYSAPP_USE_SENSCORD_VERSION 1
#define SYSAPP_USE_KERNEL_VERSION 1
#define SYSAPP_USE_LIBCAMERA_VERSION 1
#define SYSAPP_USE_IMX500_FIRMWARE_VERSION 1
#define SYSAPP_USE_IMX500_TOOLS_VERSION 1

#elif defined(CONFIG_EXTERNAL_SYSTEMAPP_VERSION_PROFILE_MINIMAL)
#define SYSAPP_USE_EDC_VERSION 1

#endif

//
// File private structure.
//

//
// File static variables.
//

//
// File static private functions.
//

#if !defined(CONFIG_EXTERNAL_SYSTEMAPP_VERSION_PROFILE_NONE)
STATIC void SysAppAppendInfoItem(StAdditionalInfoParams *info, const char *key, const char *value);
#endif

#ifdef SYSAPP_USE_KERNEL_VERSION
STATIC RetCode SysAppGetKernelVersion(char *version_buf, size_t buf_len);
STATIC void SysAppAddKernelVersion(StAdditionalInfoParams *info);
#endif

#ifdef SYSAPP_USE_LIBCAMERA_VERSION
STATIC RetCode SysAppGetLibcameraVersion(char *version_buf, size_t buf_len);
STATIC void SysAppAddLibcameraVersion(StAdditionalInfoParams *info);
#endif

#ifdef SYSAPP_USE_IMX500_FIRMWARE_VERSION
STATIC RetCode SysAppGetImx500FirmwareVersion(char *version_buf, size_t buf_len);
STATIC void SysAppAddImx500FirmwareVersion(StAdditionalInfoParams *info);
#endif

#ifdef SYSAPP_USE_IMX500_TOOLS_VERSION
STATIC RetCode SysAppGetImx500ToolsVersion(char *version_buf, size_t buf_len);
STATIC void SysAppAddImx500ToolsVersion(StAdditionalInfoParams *info);
#endif

#ifdef SYSAPP_USE_SENSCORD_VERSION
STATIC RetCode SysAppGetSenscordVersion(char *version_buf, size_t buf_len);
STATIC void SysAppAddSenscordVersion(StAdditionalInfoParams *info);
#endif

#ifdef SYSAPP_USE_EDC_VERSION
STATIC void SysAppAddEdcVersion(StAdditionalInfoParams *info);
#endif

//
// Private functions.
//

#if !defined(CONFIG_EXTERNAL_SYSTEMAPP_VERSION_PROFILE_NONE)
/*----------------------------------------------------------------------*/
STATIC void SysAppAppendInfoItem(StAdditionalInfoParams *info, const char *key, const char *value)
{
    if (info->item_count >= ST_ADDITIONAL_INFO_MAX_ITEMS || value == NULL || value[0] == '\0') {
        return;
    }

    strncpy(info->items[info->item_count].key, key, ST_ADDITIONAL_INFO_KEY_LEN - 1);
    info->items[info->item_count].key[ST_ADDITIONAL_INFO_KEY_LEN - 1] = '\0';
    strncpy(info->items[info->item_count].value, value, ST_ADDITIONAL_INFO_VALUE_LEN - 1);
    info->items[info->item_count].value[ST_ADDITIONAL_INFO_VALUE_LEN - 1] = '\0';
    info->item_count++;
}
#endif

#ifdef SYSAPP_USE_KERNEL_VERSION
/*----------------------------------------------------------------------*/
STATIC RetCode SysAppGetKernelVersion(char *version_buf, size_t buf_len)
{
    struct utsname buf;

    if (version_buf == NULL || buf_len == 0) {
        return kRetFailed;
    }

    if (uname(&buf) != 0) {
        version_buf[0] = '\0';
        return kRetFailed;
    }

    strncpy(version_buf, buf.release, buf_len - 1);
    version_buf[buf_len - 1] = '\0';

    return kRetOk;
}

/*----------------------------------------------------------------------*/
STATIC void SysAppAddKernelVersion(StAdditionalInfoParams *info)
{
    char kernel_version[ST_ADDITIONAL_INFO_VALUE_LEN] = "";
    if (SysAppGetKernelVersion(kernel_version, sizeof(kernel_version)) == kRetOk) {
        SysAppAppendInfoItem(info, "kernel_version", kernel_version);
    }
}
#endif // SYSAPP_USE_KERNEL_VERSION

#ifdef SYSAPP_USE_LIBCAMERA_VERSION
/*----------------------------------------------------------------------*/
STATIC RetCode SysAppGetLibcameraVersion(char *version_buf, size_t buf_len)
{
    const char *argv[] = {"dpkg-query", "-W", "-f=${Version}", "libcamera[0-9]*", NULL};
    return SysAppCmnExecuteCommand(argv, version_buf, buf_len, true);
}

/*----------------------------------------------------------------------*/
STATIC void SysAppAddLibcameraVersion(StAdditionalInfoParams *info)
{
    char libcamera_version[ST_ADDITIONAL_INFO_VALUE_LEN] = "";
    if (SysAppGetLibcameraVersion(libcamera_version, sizeof(libcamera_version)) == kRetOk) {
        SysAppAppendInfoItem(info, "libcamera_version", libcamera_version);
    }
}
#endif // SYSAPP_USE_LIBCAMERA_VERSION

#ifdef SYSAPP_USE_IMX500_FIRMWARE_VERSION
/*----------------------------------------------------------------------*/
STATIC RetCode SysAppGetImx500FirmwareVersion(char *version_buf, size_t buf_len)
{
    const char *argv[] = {"dpkg-query", "-W", "-f=${Version}", "imx500-firmware", NULL};
    return SysAppCmnExecuteCommand(argv, version_buf, buf_len, true);
}

/*----------------------------------------------------------------------*/
STATIC void SysAppAddImx500FirmwareVersion(StAdditionalInfoParams *info)
{
    char imx500_firmware_version[ST_ADDITIONAL_INFO_VALUE_LEN] = "";
    if (SysAppGetImx500FirmwareVersion(imx500_firmware_version, sizeof(imx500_firmware_version)) ==
        kRetOk) {
        SysAppAppendInfoItem(info, "imx500_firmware_version", imx500_firmware_version);
    }
}
#endif // SYSAPP_USE_IMX500_FIRMWARE_VERSION

#ifdef SYSAPP_USE_IMX500_TOOLS_VERSION
/*----------------------------------------------------------------------*/
STATIC RetCode SysAppGetImx500ToolsVersion(char *version_buf, size_t buf_len)
{
    const char *argv[] = {"dpkg-query", "-W", "-f=${Version}", "imx500-tools", NULL};
    return SysAppCmnExecuteCommand(argv, version_buf, buf_len, true);
}

/*----------------------------------------------------------------------*/
STATIC void SysAppAddImx500ToolsVersion(StAdditionalInfoParams *info)
{
    char imx500_tools_version[ST_ADDITIONAL_INFO_VALUE_LEN] = "";
    if (SysAppGetImx500ToolsVersion(imx500_tools_version, sizeof(imx500_tools_version)) == kRetOk) {
        SysAppAppendInfoItem(info, "imx500_tools_version", imx500_tools_version);
    }
}
#endif // SYSAPP_USE_IMX500_TOOLS_VERSION

#ifdef SYSAPP_USE_SENSCORD_VERSION
/*----------------------------------------------------------------------*/
STATIC RetCode SysAppGetSenscordVersion(char *version_buf, size_t buf_len)
{
    return SysAppCmnReadVersionFile("/opt/senscord/version_senscord.txt", version_buf, buf_len);
}

/*----------------------------------------------------------------------*/
STATIC void SysAppAddSenscordVersion(StAdditionalInfoParams *info)
{
    char senscord_version[ST_ADDITIONAL_INFO_VALUE_LEN] = "";
    if (SysAppGetSenscordVersion(senscord_version, sizeof(senscord_version)) == kRetOk) {
        SysAppAppendInfoItem(info, "senscord_version", senscord_version);
    }
}
#endif // SYSAPP_USE_SENSCORD_VERSION

#ifdef SYSAPP_USE_EDC_VERSION
/*----------------------------------------------------------------------*/
STATIC void SysAppAddEdcVersion(StAdditionalInfoParams *info)
{
    SysAppAppendInfoItem(info, "edc_version", EDC_VERSION);
}
#endif // SYSAPP_USE_EDC_VERSION

//
// Public functions.
//

/*----------------------------------------------------------------------*/
RetCode SysAppAdditionalInfoCollect(StAdditionalInfoParams *info)
{
    SYSAPP_DBG("SysAppAdditionalInfoCollect()");

    if (info == NULL) {
        return kRetFailed;
    }

    memset(info, 0, sizeof(*info));

#ifdef SYSAPP_USE_EDC_VERSION
    SysAppAddEdcVersion(info);
#endif

#ifdef SYSAPP_USE_SENSCORD_VERSION
    SysAppAddSenscordVersion(info);
#endif

#ifdef SYSAPP_USE_KERNEL_VERSION
    SysAppAddKernelVersion(info);
#endif

#ifdef SYSAPP_USE_LIBCAMERA_VERSION
    SysAppAddLibcameraVersion(info);
#endif

#ifdef SYSAPP_USE_IMX500_FIRMWARE_VERSION
    SysAppAddImx500FirmwareVersion(info);
#endif

#ifdef SYSAPP_USE_IMX500_TOOLS_VERSION
    SysAppAddImx500ToolsVersion(info);
#endif

    return kRetOk;
}
