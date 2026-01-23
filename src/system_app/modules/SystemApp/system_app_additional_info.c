/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include "system_app_additional_info.h"
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
// Determine which helper functions are needed based on enabled features
//

#if defined(SYSAPP_USE_SENSCORD_VERSION)
#define SYSAPP_USE_FILE_READER 1
#endif

#if defined(SYSAPP_USE_LIBCAMERA_VERSION) || defined(SYSAPP_USE_IMX500_FIRMWARE_VERSION) || \
    defined(SYSAPP_USE_IMX500_TOOLS_VERSION)
#define SYSAPP_USE_COMMAND_EXECUTOR 1
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

#ifdef SYSAPP_USE_COMMAND_EXECUTOR
STATIC RetCode SysAppExecuteCommand(const char **argv, char *output_buf, size_t buf_len,
                                    bool trim_newline);
#endif

#ifdef SYSAPP_USE_FILE_READER
STATIC RetCode SysAppGetFromFile(const char *file_path, char *version_buf, size_t buf_len);
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

#ifdef SYSAPP_USE_COMMAND_EXECUTOR
/*----------------------------------------------------------------------*/
STATIC RetCode SysAppExecuteCommand(const char **argv, char *output_buf, size_t buf_len,
                                    bool trim_newline)
{
    // Execute external command and capture output.
    // Success is determined by exit code (0 = success, non-zero = failure).
    // On failure, output_buf is set to "". On success, output_buf contains output or "" if no output.

    if ((argv == NULL) || (output_buf == NULL) || (buf_len == 0)) {
        if ((output_buf != NULL) && (buf_len > 0)) {
            output_buf[0] = '\0';
        }
        return kRetFailed;
    }

    // Create pipe for stdout redirection.

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        output_buf[0] = '\0';
        return kRetFailed;
    }

    // Fork process.

    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        output_buf[0] = '\0';
        return kRetFailed;
    }

    if (pid == 0) {
        // Child process: redirect stdout to pipe and execute command.

        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execvp(argv[0], (char *const *)argv);
        exit(1);
    }

    // Parent process: read output and wait for child.

    close(pipefd[1]);

    ssize_t bytes = read(pipefd[0], output_buf, buf_len - 1);
    close(pipefd[0]);

    // Wait for child process and check exit status.

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code != 0) {
            output_buf[0] = '\0';
            return kRetFailed;
        }
    }
    else {
        output_buf[0] = '\0';
        return kRetFailed;
    }

    // Process output: remove trailing newline if requested.

    if (bytes > 0) {
        if (trim_newline && (output_buf[bytes - 1] == '\n')) {
            bytes--;
        }
        output_buf[bytes] = '\0';
    }
    else {
        output_buf[0] = '\0';
    }

    return kRetOk;
}
#endif // SYSAPP_USE_COMMAND_EXECUTOR

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
    return SysAppExecuteCommand(argv, version_buf, buf_len, true);
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
    return SysAppExecuteCommand(argv, version_buf, buf_len, true);
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
    return SysAppExecuteCommand(argv, version_buf, buf_len, true);
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

#ifdef SYSAPP_USE_FILE_READER
STATIC RetCode SysAppGetFromFile(const char *file_path, char *version_buf, size_t buf_len)
{
    /* Read version from file in "Version: X.X.X" format
     * File format example: "Version: 0.1.30"
     * Extract: "0.1.30"
     */

    if (file_path == NULL || version_buf == NULL || buf_len == 0) {
        if (version_buf != NULL && buf_len > 0) {
            version_buf[0] = '\0';
        }
        return kRetFailed;
    }

    FILE *fp = fopen(file_path, "r");
    if (fp == NULL) {
        version_buf[0] = '\0';
        return kRetFailed;
    }

    char line_buf[256] = "";
    if (fgets(line_buf, sizeof(line_buf), fp) == NULL) {
        fclose(fp);
        version_buf[0] = '\0';
        return kRetFailed;
    }

    fclose(fp);

    /* Parse "Version: X.X.X" format */

    const char *version_str = strstr(line_buf, "Version:");
    if (version_str == NULL) {
        version_buf[0] = '\0';
        return kRetFailed;
    }

    /* Skip "Version:" and whitespace */

    version_str += strlen("Version:");
    while (*version_str == ' ' || *version_str == '\t') {
        version_str++;
    }

    /* Copy version part, trimming newline */

    size_t i = 0;
    while (i < buf_len - 1 && version_str[i] != '\0' && version_str[i] != '\n' &&
           version_str[i] != '\r') {
        version_buf[i] = version_str[i];
        i++;
    }
    version_buf[i] = '\0';

    return kRetOk;
}
#endif // SYSAPP_USE_FILE_READER

#ifdef SYSAPP_USE_SENSCORD_VERSION
/*----------------------------------------------------------------------*/
STATIC RetCode SysAppGetSenscordVersion(char *version_buf, size_t buf_len)
{
    return SysAppGetFromFile("/opt/senscord/version_senscord.txt", version_buf, buf_len);
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
