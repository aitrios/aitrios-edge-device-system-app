/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#if defined(__linux__)
#include <unistd.h>
#endif

#ifdef SYSTEM_APP_UT
#include <errno.h>
/* UT_BYPASS_{DATA|CODE}_* defines variables and bypass codes to emulate  */
/* the output behavior of internal functions that cannot be mocked. */
/* ut_*_bypass - 0:execute_original_function. 1:bypass(emulate outputs) */
/* ut_*_... - emulated output values for bypass */
#define UT_BYPASS_DATA_WAITBLOBOPERATIONCALLBACK \
    int ut_bdw_bypass = 0;                       \
    int ut_bdw_ret;
#define UT_BYPASS_CODE_WAITBLOBOPERATIONCALLBACK \
    if (ut_bdw_bypass)                           \
        return ut_bdw_ret;
#define UT_BYPASS_DATA_BLOBDOWNLOAD \
    int ut_bdb_bypass = 0;          \
    int ut_bdb_ret[2];              \
    int ut_bdb_status[2];           \
    long ut_bdb_dl_size[2];         \
    int ut_bdb_num = 0;             \
    int ut_bdb_rp = 0;
#define UT_BYPASS_CODE_BLOBDOWNLOAD               \
    if (ut_bdb_bypass) {                          \
        *dl_size = ut_bdb_dl_size[ut_bdb_rp];     \
        *http_status = ut_bdb_status[ut_bdb_rp];  \
        int ret = ut_bdb_ret[ut_bdb_rp];          \
        ut_bdb_rp = (ut_bdb_rp + 1) % ut_bdb_num; \
        return ret;                               \
    }
UT_BYPASS_DATA_WAITBLOBOPERATIONCALLBACK;
UT_BYPASS_DATA_BLOBDOWNLOAD;
#else
#define UT_BYPASS_CODE_WAITBLOBOPERATIONCALLBACK
#define UT_BYPASS_CODE_BLOBDOWNLOAD
#endif // SYSTEM_APP_UT

#include "utility_msg.h"
#include "evp/sdk_sys.h"
#include "system_app_common.h"
#include "system_app_log.h"
#include "system_app_led.h"
#include "system_app_deploy.h"
#include "system_app_ud_main.h"
#include "system_app_util.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

// Download retry count

#define NUMBER_OF_DOWNLOAD_RETRY (10)

// Define size of the final unit and read interval for obtaining download file

#define MIN_NUM_OF_READ_BYTE (8192)
#define FIRST_DOWNLOAD_OFFSET_BYTE (2097152)

/* HTTP Error Response Code 416 Range Not Satisfiable */

#define HTTP_STATUS_416_RANGE_NOT_SATISFIABLE (416)

/* HTTP Error Response Code 403 Forbidden */

#define HTTP_STATUS_403_FORBIDDEN (403)

/* Timeout when receiving a message [ms] */

#define RECV_TIME_OUT (30 * 60 * 1000)

/* Number of retries waiting for forced stop to complete */

#define WAIT_FORCE_STOP_RETRY_NUM (60)

/****************************************************************************
 * Private type definitions
 ****************************************************************************/

typedef struct {
    enum SYS_result result;
    size_t data_dead;
    bool cb_signaled;
    int http_status;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    SysAppUdDownloadCb cb;
    void *usr_data;
} blob_cb_context;

/****************************************************************************
 * Private Data
 ****************************************************************************/

// DCS client

STATIC struct SYS_client *s_iot_client_ud = NULL;

// Forced download end flag

STATIC bool s_is_force_stop = false;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/*--------------------------------------------------------------------------*/
enum SYS_result WaitBlobOperationCallback(blob_cb_context *ctx)
{
    UT_BYPASS_CODE_WAITBLOBOPERATIONCALLBACK; /* Only for unit tests */

    /* Callback for EVP_blobOperation */

    struct timespec ts;
    uint64_t ns;
    enum SYS_result ret = SYS_RESULT_OK;

    /* Set signal timeout */

    clock_gettime(CLOCK_REALTIME, &ts);

    ns = ts.tv_sec;
    ns *= 1000000000L;
    ns += ((uint64_t)RECV_TIME_OUT * 1000000L);

    ts.tv_sec = ns / 1000000000;
    ts.tv_nsec = ns % 1000000000;

    /* Wait thread */

    int wait_result = 0;

    do {
        wait_result = pthread_cond_timedwait(&ctx->cond, &ctx->mutex, &ts);

        if (wait_result != ETIMEDOUT) {
            continue;
        }

        /*
     *  If pthread_cond_timedwait returns "ETIMEDOUT" before the time expires,
     *  ignore received "ETIMEDOUT" as a NOISE signal.
     *  And retry pthread_cond_timedwait().
     */

        /* Check if the time has really passed? */

        struct timespec tsc;
        uint64_t nsc;

        clock_gettime(CLOCK_REALTIME, &tsc);
        nsc = (uint64_t)tsc.tv_sec * 1000000000 + tsc.tv_nsec;

        if (nsc >= ns) {
            /* Really expired. */

            /***
      * If the callback function is executed after a timeout, a NULL access occurs.
      * To avoid NULL access, ensure the callback function returns an error if executed after a timeout.
      * 
      * If the callback function is not called, it results in an infinite wait because of the continue statement.
      * However, the callback function not being called does not occur in either normal or abnormal scenarios.
      * It only happens if there is a system issue (e.g., worker process freeze).
      * Therefore, the current implementation does not have any operational issues.
      ***/

            ctx->result = SYS_RESULT_ERRNO;
            SYSAPP_ERR("!!!TIMEOUT!!!");
            sleep(1);
            continue;
        }

        /* Not expired. Detect NOISE signal. */

        SYSAPP_WARN("pthread_cond_timedwait() Noise detected!Target:%lld.%09ld detected:%lld.%09ld",
                    ts.tv_sec, ts.tv_nsec, tsc.tv_sec, tsc.tv_nsec);

        wait_result = 0;

    } while (!ctx->cb_signaled);

    ctx->cb_signaled = false;

    if (wait_result == ETIMEDOUT) {
        /* Timeout */
        SYSAPP_ERR("Timeout pthread_cond_timedwait()");
        ret = SYS_RESULT_TIMEDOUT;
    }
    else if (wait_result == 0) {
        /* OK */
        ret = ctx->result;
    }
    else {
        SYSAPP_ERR("Failed to pthread_cond_timedwait()=%d", wait_result);
        ret = SYS_RESULT_TIMEDOUT;
    }

    pthread_mutex_unlock(&ctx->mutex);

    return ret;
}

/*--------------------------------------------------------------------------*/
STATIC enum SYS_result BlobDownLoadCb(struct SYS_client *, struct SYS_blob_data *blob,
                                      enum SYS_callback_reason reason, void *user)
{
    /* Callback for blob download */

    if (user == NULL) {
        SYSAPP_ERR("user is NULL");
        return SYS_RESULT_ERRNO;
    }

    if (blob == NULL) {
        SYSAPP_ERR("blob is NULL");
        return SYS_RESULT_ERRNO;
    }

    blob_cb_context *ctx = (blob_cb_context *)user;

    int blob_http_status = blob->status_code;
    int blob_error = blob->error;

    ctx->http_status = blob_http_status;

    switch (reason) {
        case SYS_REASON_MORE_DATA:
            /* Read downloaded data. */

            if (ctx->result == SYS_RESULT_ERRNO) {
                /* If any error occurs, the download will be terminated. */

                return SYS_RESULT_ERRNO;
            }

            if (SysAppUdIsThisRequestToStopForDownload()) {
                /* Forced termination requested! */

                SYSAPP_INFO("Stop the download by a request.");
                return SYS_RESULT_ERRNO;
            }

            ctx->data_dead += blob->len;

            if (ctx->cb == NULL) {
                return SYS_RESULT_OK;
            }

            /* Call a callback. Within the callback, call another callback... */

            if (ctx->cb(blob->blob_buffer, blob->len, ctx->usr_data) < 0) {
                ctx->result = SYS_RESULT_ERRNO;
                SYSAPP_ERR("Blob Callback Error reason:%d http_status:%d errno:%d", reason,
                           blob_http_status, blob_error);

                /* If any error occurs, the download will be terminated. */

                return SYS_RESULT_ERRNO;
            }

            ctx->result = SYS_RESULT_OK;

            return SYS_RESULT_OK;

        case SYS_REASON_FINISHED:
            SYSAPP_DBG("Blob Callback reason:SYS_REASON_FINISHED");

            if ((blob_http_status / 100) != 2) {
                if (blob_http_status == HTTP_STATUS_416_RANGE_NOT_SATISFIABLE) {
                    /* If the download file size is out of range, set the read size to 0 and return OK. */

                    SYSAPP_INFO("http_status: %d", blob_http_status);
                    ctx->result = SYS_RESULT_OK;
                    ctx->data_dead = 0;
                }
                else {
                    SYSAPP_ERR("http_status: %d", blob_http_status);
                    ctx->result = SYS_RESULT_ERRNO;
                }
            }
            else {
                /* If the http status is in the 200 range, the operation is successful. */

                ctx->result = SYS_RESULT_OK;
            }
            break;

        case SYS_REASON_TIMEOUT:
            SYSAPP_INFO("Blob Callback reason:SYS_REASON_TIMEOUT http_status:%d errno:%d",
                        blob_http_status, blob_error);
            ctx->result = SYS_RESULT_TIMEDOUT;
            break;

        case SYS_REASON_ERROR:
            SYSAPP_ERR("Blob Callback Error reason:SYS_REASON_ERROR http_status:%d errno:%d",
                       blob_http_status, blob_error);
            ctx->result = SYS_RESULT_ERRNO;
            break;

        default:
            SYSAPP_ERR("Blob Callback Error reason:%d http_status:%d errno:%d", reason,
                       blob_http_status, blob_error);

            ctx->result = SYS_RESULT_ERRNO;
            break;
    }

    /* Release lock */
    int retry_count = 0;
    int max_retries = 5;
    int lock_ret;

    while ((lock_ret = pthread_mutex_lock(&ctx->mutex)) == EAGAIN && retry_count < max_retries) {
        retry_count++;
        usleep(1000); // wait 1ms
    }

    if (lock_ret != 0) {
        ctx->result = SYS_RESULT_ERRNO;
    }

    ctx->cb_signaled = true;
    pthread_cond_signal(&ctx->cond);
    pthread_mutex_unlock(&ctx->mutex);

    return SYS_RESULT_OK;
}

/*--------------------------------------------------------------------------*/
STATIC enum SYS_result BlobDownload(struct SYS_client *h, const char *request_url, size_t offset,
                                    size_t size, SysAppUdDownloadCb cb, void *usr_data,
                                    size_t *dl_size, int *http_status)
{
    UT_BYPASS_CODE_BLOBDOWNLOAD; /* Only for unit tests */

    /* Get download image */

    enum SYS_result sys_result;

    /* Set headers */

    char value[64];

    struct SYS_http_header headers[2];

    /* Set the scan range */

    if (size == 0) {
        snprintf(value, sizeof(value), "bytes=%zu-", offset);
    }
    else {
        snprintf(value, sizeof(value), "bytes=%zu-%zu", offset, offset + size - 1);
    }

    headers[0].key = "Range";
    headers[0].value = value;
    headers[1].key = NULL;
    headers[1].value = NULL;

    /* Initiaize mutex and condition */

    SYSAPP_INFO("%s:%s", headers[0].key, headers[0].value);

    blob_cb_context *ctx_ptr = (blob_cb_context *)malloc(sizeof(blob_cb_context));

    if (ctx_ptr == NULL) {
        SYSAPP_ERR("malloc");
        return SYS_RESULT_ERRNO;
    }

    if (pthread_mutex_init(&ctx_ptr->mutex, NULL) != 0) {
        SYSAPP_ERR("pthread_mutex_init() failed");
        free(ctx_ptr);
        return SYS_RESULT_ERRNO;
    }

    if (pthread_cond_init(&ctx_ptr->cond, NULL) != 0) {
        SYSAPP_ERR("pthread_cond_init() failed");
        pthread_mutex_destroy(&ctx_ptr->mutex);
        free(ctx_ptr);
        return SYS_RESULT_ERRNO;
    }

    ctx_ptr->cb_signaled = false;
    ctx_ptr->cb = cb;
    ctx_ptr->usr_data = usr_data;
    ctx_ptr->data_dead = 0;
    ctx_ptr->result = SYS_RESULT_OK;
    ctx_ptr->http_status = 0;

    int retry_count = 0;
    int max_retries = 5;
    int lock_ret;

    while ((lock_ret = pthread_mutex_lock(&ctx_ptr->mutex)) == EAGAIN &&
           retry_count < max_retries) {
        retry_count++;
        usleep(1000); // wait 1ms
    }

    if (lock_ret != 0) {
        SYSAPP_ERR("pthread_mutex_lock is failed errno:%d ", lock_ret);
        pthread_cond_destroy(&ctx_ptr->cond);
        pthread_mutex_destroy(&ctx_ptr->mutex);
        free(ctx_ptr);
        return SYS_RESULT_ERRNO;
    }

    /* Start download */

    size = 0;

    SYSAPP_INFO("SYS_get_blob");

    sys_result = SYS_get_blob(h, request_url, headers, BlobDownLoadCb, ctx_ptr);

    if (sys_result != SYS_RESULT_OK) {
        SYSAPP_ERR("Failed SYS_get_blob()=%d", sys_result);
        pthread_mutex_unlock(&ctx_ptr->mutex);

        /* If download not start,
     * set http_status to -1 to instruct caller to stop the download without retry. */

        ctx_ptr->http_status = -1;
    }
    else {
        SYSAPP_INFO("Wait blob operation...");

        sys_result = WaitBlobOperationCallback(ctx_ptr);

        if (SYS_RESULT_OK == sys_result) {
            size = ctx_ptr->data_dead;
        }
    }

    if (http_status) {
        *http_status = ctx_ptr->http_status;
    }

    if (dl_size) {
        *dl_size = size;
    }

    /* free condition variable and mutex */

    pthread_cond_destroy(&ctx_ptr->cond);
    pthread_mutex_destroy(&ctx_ptr->mutex);

    free(ctx_ptr);

    return sys_result;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/*--------------------------------------------------------------------------*/
RetCode SysAppUdInitialize(struct SYS_client *iot_client_ud)
{
    /* Initialize */

    SYSAPP_INFO("UdInitialize");

    if (s_iot_client_ud) {
        SYSAPP_WARN("Already initialized");
        return kRetOk;
    }

    s_iot_client_ud = iot_client_ud;

    return kRetOk;
}

/*--------------------------------------------------------------------------*/
RetCode SysAppUdFinalize(void)
{
    /* Finalize */

    SYSAPP_INFO("UdFinalize");

    if (s_iot_client_ud == NULL) {
        SYSAPP_WARN("Not initialized");
        return kRetOk;
    }

    s_iot_client_ud = NULL;

    return kRetOk;
}

/*--------------------------------------------------------------------------*/
size_t SysAppUdGetImageSize(char *request_url, int *http_status)
{
    /* Get data size of download image */

    enum SYS_result ret;
    size_t dl_size = 0;
    size_t offset = FIRST_DOWNLOAD_OFFSET_BYTE;
    size_t base = 0;           /* Download start base position */
    size_t max_range_size = 0; /* Approximate download file size */
    int retry = 0;             /* Retry counter when download fails */
    int idx = 0;
    int status = 0;

    if (s_iot_client_ud == NULL) {
        SYSAPP_ERR("Not initialized");
        return 0;
    }

    /* Get file size by binary search process overview
   * 1. Download the base + offset position
   * 2. When the download is successful, update the base, double the offset, and re-download
   * 3. If the download is not successful due to a setting outside the range,
        set a rough size. Halve the offset and re-download
   * 4. When the download is successful, update the base, halve the offset, and re-download
   * 5. Repeat until the offset becomes 0. */

    for (;;) {
        if (SysAppUdIsThisRequestToStopForDownload()) {
            SYSAPP_INFO("Stop the download by a request.");
            ret = SYS_RESULT_ERRNO;
            break;
        }

        ret = BlobDownload(s_iot_client_ud, request_url, base + offset, MIN_NUM_OF_READ_BYTE, NULL,
                           NULL, &dl_size, &status);

        if (ret != SYS_RESULT_OK) {
            /* An error occurred */

            SYSAPP_ERR("BlobDownload");

            if (status == HTTP_STATUS_403_FORBIDDEN) {
                SYSAPP_INFO("Forbidden");
                break;
            }

            /* If download not start,
       * set http_status to -1 to instruct caller to stop the download without retry. */

            if (status < 0) {
                SYSAPP_ERR("URL is not http:// or https://");
                break;
            }

            if (++retry > NUMBER_OF_DOWNLOAD_RETRY) {
                /* If the retry count is reached, the error will be terminated */

                break;
            }

            SYSAPP_INFO("Retry(%d)", retry);
            continue;
        }

        if (dl_size == 0) {
            /* Access outside the range of download file */

            SYSAPP_INFO("%2d:Range over(%zu:%zu)", idx, base, offset);

            if (max_range_size == 0) {
                /* Set the approximate file size */

                max_range_size = base + offset;
                SYSAPP_INFO("Approximate file size=%zu", max_range_size);
            }

            /* Halve offset and try again */

            offset /= 2;

            if (offset < MIN_NUM_OF_READ_BYTE) {
                /* When the minimum access unit is reached, try accessing from offset 0 */

                offset = 0;
            }
        }
        else {
            /* File access successful */

            SYSAPP_INFO("%2d:size=%zu/%zu:%zu", idx, dl_size, base, offset);

            if (offset == 0) {
                /* Termination of Access */

                break;
            }

            /* Update the access start position */

            base += offset;

            if (max_range_size == 0) {
                /* If an approximate file sizes are not set, double the offset and retry */

                offset *= 2;
            }
            else {
                /* If an approximate file size is set, try halving the offset and retrying */

                offset /= 2;
            }
        }

        idx++;
    }

    if (http_status) {
        *http_status = status;
    }

    if (ret != SYS_RESULT_OK) {
        return 0;
    }

    return base + dl_size;
}

/*--------------------------------------------------------------------------*/
ssize_t SysAppUdGetImageData(char *request_url, size_t offset, size_t size, SysAppUdDownloadCb cb,
                             void *usr_param, int *http_status)
{
    /* Get data of download image */

    if (s_iot_client_ud == NULL) {
        SYSAPP_ERR("Not initialized");
        return -1;
    }

    if (SysAppUdIsThisRequestToStopForDownload()) {
        SYSAPP_INFO("Stop the download by a request.");
        return -1;
    }

    size_t dl_size = 0;

    enum SYS_result sys_result = BlobDownload(s_iot_client_ud, request_url, offset, size, cb,
                                              usr_param, &dl_size, http_status);
    if (sys_result != SYS_RESULT_OK) {
        return -1;
    }

    return dl_size;
}

/*--------------------------------------------------------------------------*/
void SysAppUdRequestToStopDownload(void)
{
    /* Request to stop download */

    s_is_force_stop = true;
}

/*--------------------------------------------------------------------------*/

bool SysAppUdIsThisRequestToStopForDownload(void)
{
    /* Is this a request to stop download */

    if (SysAppDeployGetCancel()) {
        return true;
    }

    return s_is_force_stop;
}

/*--------------------------------------------------------------------------*/
void SysAppUdCancelDownloadStopRequest(void)
{
    /* Cancel request to stop download */

    s_is_force_stop = false;
}

/*--------------------------------------------------------------------------*/
void SysAppUdWaitForDownloadToStop(void)
{
    /* Wait for download to stop */

    if (s_iot_client_ud == NULL) {
        SYSAPP_ERR("Not initialized");
        return;
    }

    int retry;

    SYSAPP_INFO("Wait download stop");

    for (retry = 0; retry < WAIT_FORCE_STOP_RETRY_NUM; retry++) {
        if (s_is_force_stop == false) {
            /* Once the forced stop is complete, exit */

            break;
        }

        /* Run SYS_process_event() now,
     * as the download process will be unresponsive if you do not do so. */

        if (SYS_process_event(s_iot_client_ud, 1000) == SYS_RESULT_SHOULD_EXIT) {
            SYSAPP_ERR("SYS_process_event");
            break;
        }
    }

    SYSAPP_INFO("Wait download stop end(%d/%d)", retry, WAIT_FORCE_STOP_RETRY_NUM);
}
