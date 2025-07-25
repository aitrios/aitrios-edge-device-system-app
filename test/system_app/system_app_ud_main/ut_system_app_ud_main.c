/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include "evp/sdk_sys.h"
#include "system_app_ud_main.h"

/*----------------------------------------------------------------------------*/

//
// Common
//

extern struct SYS_client *s_iot_client_ud;
extern bool s_is_force_stop;

// UT bypass emuleted values for WaitBlobOperationCallback
extern int ut_bdw_bypass;
extern int ut_bdw_ret;
// UT bypass emuleted values for BlobDownload
extern int ut_bdb_bypass;
extern int ut_bdb_ret[2];
extern int ut_bdb_status[2];
extern long ut_bdb_dl_size[2];
extern int ut_bdb_num;
extern int ut_bdb_rp;

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

enum SYS_result WaitBlobOperationCallback(blob_cb_context *ctx);
enum SYS_result BlobDownLoadCb(struct SYS_client *, struct SYS_blob_data *blob,
                               enum SYS_callback_reason reason, void *user);
enum SYS_result BlobDownload(struct SYS_client *h, const char *request_url, size_t offset,
                             size_t size, SysAppUdDownloadCb cb, void *usr_data, size_t *dl_size,
                             int *http_status);

/*----------------------------------------------------------------------------*/
static int ret_dummy_cb;
static int dummy_cb(uint8_t *data, size_t dl_size, void *p_usr_data)
{
    return ret_dummy_cb;
}

/*----------------------------------------------------------------------------*/
static void internal_WaitBlobOperationCallback(int ret)
{
    ut_bdw_bypass = 1;
    ut_bdw_ret = ret;
}

/*----------------------------------------------------------------------------*/
static void internal_BlobDownload(enum SYS_result ret_val, int status, size_t dl_size)
{
    ut_bdb_bypass = 1;
    ut_bdb_status[0] = status;
    ut_bdb_dl_size[0] = dl_size;
    ut_bdb_ret[0] = ret_val;
    ut_bdb_num = 1;
    ut_bdb_rp = 0;
}

/*----------------------------------------------------------------------------*/
static void internal_BlobDownload_2nd(enum SYS_result ret_val, int status, size_t dl_size)
{
    ut_bdb_bypass = 1;
    ut_bdb_status[1] = status;
    ut_bdb_dl_size[1] = dl_size;
    ut_bdb_ret[1] = ret_val;
    ut_bdb_num = 2;
    ut_bdb_rp = 0;
}

/*----------------------------------------------------------------------------*/
static void internal_SysAppUdGetImageSizeLoop(bool is_cancel)
{
    int rp = ut_bdb_rp;
    int retry = 0;
    size_t offset = (2097152);
    size_t base = 0;
    size_t max_range_size = 0; /* Approximate download file size */

    for (;;) {
        if (ut_bdb_bypass == 0) {
            break;
        }

        // for SysAppDeployGetCancel

        will_return(__wrap_SysAppDeployGetCancel, is_cancel);

        if (is_cancel) {
            break;
        }

        if (ut_bdb_ret[rp] != SYS_RESULT_OK) {
            if (ut_bdb_status[rp] == 403) {
                break;
            }

            if (ut_bdb_status[rp] < 0) {
                break;
            }

            if (++retry > 10) {
                break;
            }
        }

        if (ut_bdb_dl_size[rp] == 0) {
            if (max_range_size == 0) {
                max_range_size = base + offset;
            }

            offset /= 2;

            if (offset < 8192) {
                offset = 0;
            }
        }
        else {
            if (offset == 0) {
                break;
            }

            base += offset;

            if (max_range_size == 0) {
                offset *= 2;
            }
            else {
                offset /= 2;
            }
        }

        rp = (rp + 1) % ut_bdb_num;
    }
}

/*----------------------------------------------------------------------------*/

//
// enum SYS_result WaitBlobOperationCallback(blob_cb_context *ctx)
//

/*----------------------------------------------------------------------------*/
static void test_WaitBlobOperationCallback_fully_success(void **state)
{
    ut_bdw_bypass = 0; // no bypass
    blob_cb_context ctx;

    // clock_gettime() 1.return 2.tv_sec 3.tv_nsec
    will_return(__wrap_clock_gettime, 0);  // return:0 (success)
    will_return(__wrap_clock_gettime, 0);  // tv_sec:0 (sec)
    will_return(__wrap_clock_gettime, 0L); // tv_nsec:0L (ns)

    // pthread_cond_timedwait() 1.return
    will_return(__wrap_pthread_cond_timedwait, 0); // return:0

    /* while */
    ctx.cb_signaled = true;
    ctx.result = SYS_RESULT_OK;

    will_return(__wrap_pthread_mutex_unlock, 0); // return:0

    enum SYS_result ret = WaitBlobOperationCallback(&ctx);

    assert_int_equal(ret, SYS_RESULT_OK);
    assert_int_equal(ctx.cb_signaled, false);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_WaitBlobOperationCallback_error_noise(void **state)
{
    ut_bdw_bypass = 0; // no bypass
    blob_cb_context ctx;

    // clock_gettime() 1.return 2.tv_sec 3.tv_nsec
    will_return(__wrap_clock_gettime, 0);  // return:0 (success)
    will_return(__wrap_clock_gettime, 0);  // tv_sec:0 (sec)
    will_return(__wrap_clock_gettime, 0L); // tv_nsec:0L (ns)

    // pthread_cond_timedwait() 1.return
    will_return(__wrap_pthread_cond_timedwait, ETIMEDOUT); // return:ETIMEDOUT

    // clock_gettime() 1.return 2.tv_sec 3.tv_nsec
    will_return(__wrap_clock_gettime, 0);  // return:0 (success)
    will_return(__wrap_clock_gettime, 0);  // tv_sec:0 (sec)
    will_return(__wrap_clock_gettime, 0L); // tv_nsec:0L (ns)

    /* while */
    ctx.cb_signaled = true;
    ctx.result = SYS_RESULT_OK;

    will_return(__wrap_pthread_mutex_unlock, 0); // return:0

    enum SYS_result ret = WaitBlobOperationCallback(&ctx);

    assert_int_equal(ret, SYS_RESULT_OK);
    assert_int_equal(ctx.cb_signaled, false);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_WaitBlobOperationCallback_error_timedout(void **state)
{
    ut_bdw_bypass = 0; // no bypass
    blob_cb_context ctx;

    // clock_gettime() 1.return 2.tv_sec 3.tv_nsec
    will_return(__wrap_clock_gettime, 0);  // return:0 (success)
    will_return(__wrap_clock_gettime, 0);  // tv_sec:0 (sec)
    will_return(__wrap_clock_gettime, 0L); // tv_nsec:0L (ns)

    // pthread_cond_timedwait() 1.return
    will_return(__wrap_pthread_cond_timedwait, ETIMEDOUT); // return:ETIMEDOUT

    // clock_gettime() 1.return 2.tv_sec 3.tv_nsec
    will_return(__wrap_clock_gettime, 0);    // return:0 (success)
    will_return(__wrap_clock_gettime, 2000); // tv_sec:0 (sec)
    will_return(__wrap_clock_gettime, 0L);   // tv_nsec:0L (ns)

    /* while */
    ctx.cb_signaled = true;
    ctx.result = SYS_RESULT_OK;

    will_return(__wrap_pthread_mutex_unlock, 0); // return:0

    enum SYS_result ret = WaitBlobOperationCallback(&ctx);

    assert_int_equal(ret, SYS_RESULT_TIMEDOUT);
    assert_int_equal(ctx.cb_signaled, false);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_WaitBlobOperationCallback_error_timedwait(void **state)
{
    ut_bdw_bypass = 0; // no bypass
    blob_cb_context ctx;

    // clock_gettime() 1.return 2.tv_sec 3.tv_nsec
    will_return(__wrap_clock_gettime, 0);  // return:0 (success)
    will_return(__wrap_clock_gettime, 0);  // tv_sec:0 (sec)
    will_return(__wrap_clock_gettime, 0L); // tv_nsec:0L (ns)

    // pthread_cond_timedwait() 1.return
    will_return(__wrap_pthread_cond_timedwait, 22); // return:22

    /* while */
    ctx.cb_signaled = true;
    ctx.result = SYS_RESULT_OK;

    will_return(__wrap_pthread_mutex_unlock, 0); // return:0

    enum SYS_result ret = WaitBlobOperationCallback(&ctx);

    assert_int_equal(ret, SYS_RESULT_TIMEDOUT);
    assert_int_equal(ctx.cb_signaled, false);

    return;
}

/*----------------------------------------------------------------------------*/

//
// STATIC enum SYS_result BlobDownLoadCb(struct SYS_client       *,
//                                       struct SYS_blob_data    *blob,
//                                       enum SYS_callback_reason reason,
//                                       void                    *user)
//

/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_fully_success_more_data(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 0;
    blob->error = 0;
    blob->len = 3;

    // for switch(reason)
    reason = SYS_REASON_MORE_DATA;
    ctx.result = SYS_RESULT_OK;
    s_is_force_stop = false;
    ctx.data_dead = 0;
    ctx.cb = &dummy_cb;
    ret_dummy_cb = 0;

    // for SysAppDeployGetCancel
    will_return(__wrap_SysAppDeployGetCancel, false);

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_OK);
    assert_int_equal(ctx.result, SYS_RESULT_OK);
    assert_int_equal(ctx.data_dead, 3);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_fully_success_finished(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 200;
    blob->error = 0;
    blob->len = 3;

    // for switch(reason)
    reason = SYS_REASON_FINISHED;

    // release lock
    will_return(__wrap_pthread_mutex_lock, 0);   // return:0 (success)
    will_return(__wrap_pthread_cond_signal, 0);  // return:0 (success)
    will_return(__wrap_pthread_mutex_unlock, 0); // return:0 (success)

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_OK);
    assert_int_equal(ctx.result, SYS_RESULT_OK);
    assert_int_equal(ctx.cb_signaled, true);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_success_mutex_lock_retry(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};
    ctx.cb_signaled = false;

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 200;
    blob->error = 0;
    blob->len = 3;

    // for switch(reason)
    reason = SYS_REASON_FINISHED;

    // release lock
    will_return(__wrap_pthread_mutex_lock, EAGAIN); // <-- error !
    will_return(__wrap_pthread_mutex_lock, 0);      // return:0 (success)
    will_return(__wrap_pthread_cond_signal, 0);     // return:0 (success)
    will_return(__wrap_pthread_mutex_unlock, 0);    // return:0 (success)

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_OK);
    assert_int_equal(ctx.result, SYS_RESULT_OK);
    assert_int_equal(ctx.cb_signaled, true);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_error_no_user(void **state)
{
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason = SYS_REASON_MORE_DATA;

    void *user = NULL; // <- error!
    struct SYS_blob_data *blob = NULL;

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_ERRNO);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_error_no_blob(void **state)
{
    blob_cb_context ctx;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason = SYS_REASON_MORE_DATA;

    void *user = &ctx;
    struct SYS_blob_data *blob = NULL; // <- error!

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_ERRNO);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_error_more_data_1(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 0;
    blob->error = 0;
    blob->len = 3;

    // for switch(reason)
    reason = SYS_REASON_MORE_DATA;
    ctx.result = SYS_RESULT_ERRNO; // <- error!

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_ERRNO);
    assert_int_equal(ctx.result, SYS_RESULT_ERRNO);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_error_more_data_2(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 0;
    blob->error = 0;
    blob->len = 3;

    // for switch(reason)
    reason = SYS_REASON_MORE_DATA;
    ctx.result = SYS_RESULT_OK;
    s_is_force_stop = true; // <- busy!
    ctx.data_dead = 0;
    ctx.cb = &dummy_cb;
    ret_dummy_cb = 0;

    // for SysAppDeployGetCancel
    will_return(__wrap_SysAppDeployGetCancel, false);

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_ERRNO);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_error_more_data_3(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 0;
    blob->error = 0;
    blob->len = 3;

    // for switch(reason)
    reason = SYS_REASON_MORE_DATA;
    ctx.result = SYS_RESULT_OK;
    s_is_force_stop = false;
    ctx.data_dead = 0;
    ctx.cb = NULL; // <- error!

    // for SysAppDeployGetCancel
    will_return(__wrap_SysAppDeployGetCancel, false);

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_OK);
    assert_int_equal(ctx.data_dead, 3);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_error_more_data_4(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 0;
    blob->error = 0;
    blob->len = 3;

    // for switch(reason)
    reason = SYS_REASON_MORE_DATA;
    ctx.result = SYS_RESULT_OK;
    s_is_force_stop = false;
    ctx.data_dead = 0;
    ctx.cb = &dummy_cb;
    ret_dummy_cb = -1; // <- error!

    // for SysAppDeployGetCancel
    will_return(__wrap_SysAppDeployGetCancel, false);

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_ERRNO);
    assert_int_equal(ctx.result, SYS_RESULT_ERRNO);
    assert_int_equal(ctx.data_dead, 3);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_error_more_data_5(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 0;
    blob->error = 0;
    blob->len = 3;

    // for switch(reason)
    reason = SYS_REASON_MORE_DATA;
    ctx.result = SYS_RESULT_OK;
    s_is_force_stop = false;
    ctx.data_dead = 0;
    ctx.cb = &dummy_cb;
    ret_dummy_cb = 0;

    // for SysAppDeployGetCancel
    will_return(__wrap_SysAppDeployGetCancel, true);

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_ERRNO);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_error_finished_416(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 416;
    blob->error = 0;
    blob->len = 3;

    // for switch(reason)
    reason = SYS_REASON_FINISHED;

    // release lock
    will_return(__wrap_pthread_mutex_lock, 0);   // return:0 (success)
    will_return(__wrap_pthread_cond_signal, 0);  // return:0 (success)
    will_return(__wrap_pthread_mutex_unlock, 0); // return:0 (success)

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_OK);
    assert_int_equal(ctx.result, SYS_RESULT_OK);
    assert_int_equal(ctx.cb_signaled, true);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_error_finished_417(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 417;
    blob->error = 0;
    blob->len = 3;

    // for switch(reason)
    reason = SYS_REASON_FINISHED;

    // release lock
    will_return(__wrap_pthread_mutex_lock, 0);   // return:0 (success)
    will_return(__wrap_pthread_cond_signal, 0);  // return:0 (success)
    will_return(__wrap_pthread_mutex_unlock, 0); // return:0 (success)

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_OK);
    assert_int_equal(ctx.result, SYS_RESULT_ERRNO);
    assert_int_equal(ctx.cb_signaled, true);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_error_timeout(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 0;
    blob->error = 999;
    blob->len = 3;

    // for switch(reason)
    reason = SYS_REASON_TIMEOUT; // <- error!
    ctx.http_status = 999;

    // release lock
    will_return(__wrap_pthread_mutex_lock, 0);   // return:0 (success)
    will_return(__wrap_pthread_cond_signal, 0);  // return:0 (success)
    will_return(__wrap_pthread_mutex_unlock, 0); // return:0 (success)

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_OK);
    assert_int_equal(ctx.result, SYS_RESULT_TIMEDOUT);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_error_error(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 0;
    blob->error = 999;
    blob->len = 3;

    // for switch(reason)
    reason = SYS_REASON_ERROR; // <- error!
    ctx.http_status = 999;

    // release lock
    will_return(__wrap_pthread_mutex_lock, 0);   // return:0 (success)
    will_return(__wrap_pthread_cond_signal, 0);  // return:0 (success)
    will_return(__wrap_pthread_mutex_unlock, 0); // return:0 (success)

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_OK);
    assert_int_equal(ctx.result, SYS_RESULT_ERRNO);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_error_default(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 0;
    blob->error = 999;
    blob->len = 3;

    // for switch(reason)
    reason = 999; // <- error!
    ctx.http_status = 999;

    // release lock
    will_return(__wrap_pthread_mutex_lock, 0);   // return:0 (success)
    will_return(__wrap_pthread_cond_signal, 0);  // return:0 (success)
    will_return(__wrap_pthread_mutex_unlock, 0); // return:0 (success)

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_OK);
    assert_int_equal(ctx.result, SYS_RESULT_ERRNO);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_error_mutex_lock(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};
    ctx.cb_signaled = false;

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 200;
    blob->error = 0;
    blob->len = 3;

    // for switch(reason)
    reason = SYS_REASON_FINISHED;

    // release lock
    will_return(__wrap_pthread_mutex_lock, -1);  // <-- error !
    will_return(__wrap_pthread_cond_signal, 0);  // return:0 (success)
    will_return(__wrap_pthread_mutex_unlock, 0); // return:0 (success)

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_OK);
    assert_int_equal(ctx.result, SYS_RESULT_ERRNO);
    assert_int_equal(ctx.cb_signaled, true);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownloadCb_error_mutex_lock_retry_max(void **state)
{
    blob_cb_context ctx;
    struct SYS_blob_data blob_data;
    enum SYS_result ret = SYS_RESULT_OK;
    enum SYS_callback_reason reason;
    char b_buff[1024] = {"ABC"};
    ctx.cb_signaled = false;

    void *user = &ctx;
    struct SYS_blob_data *blob = &blob_data;
    blob->method = "";
    blob->url = "";
    blob->response_headers = "";
    blob->blob_buffer = &b_buff;
    blob->status_code = 200;
    blob->error = 0;
    blob->len = 3;

    // for switch(reason)
    reason = SYS_REASON_FINISHED;

    // release lock
    will_return(__wrap_pthread_mutex_lock, EAGAIN); // <-- error !
    will_return(__wrap_pthread_mutex_lock, EAGAIN); // <-- error !
    will_return(__wrap_pthread_mutex_lock, EAGAIN); // <-- error !
    will_return(__wrap_pthread_mutex_lock, EAGAIN); // <-- error !
    will_return(__wrap_pthread_mutex_lock, EAGAIN); // <-- error !
    will_return(__wrap_pthread_mutex_lock, EAGAIN); // <-- error !
    will_return(__wrap_pthread_cond_signal, 0);     // return:0 (success)
    will_return(__wrap_pthread_mutex_unlock, 0);    // return:0 (success)

    ret = BlobDownLoadCb(s_iot_client_ud, blob, reason, user);

    assert_int_equal(ret, SYS_RESULT_OK);
    assert_int_equal(ctx.result, SYS_RESULT_ERRNO);
    assert_int_equal(ctx.cb_signaled, true);

    return;
}

/*----------------------------------------------------------------------------*/

//
// STATIC enum SYS_result BlobDownload(struct SYS_client *h,
//                                     const char        *request_url,
//                                     size_t             offset,
//                                     size_t             size,
//                                     SysAppUdDownloadCb cb,
//                                     void              *usr_data,
//                                     size_t            *dl_size,
//                                     int               *http_status)
//

/*----------------------------------------------------------------------------*/
static void test_BlobDownload_fully_success1(void **state)
{
    enum SYS_result ret;
    char *udata = "user_data";

    char *request_url = "dummy_url";
    size_t offset;
    size_t size;
    SysAppUdDownloadCb cb;
    void *usr_data;
    size_t dl_size;
    int http_status;

    // size
    offset = 0;
    size = 0;
    cb = &dummy_cb;
    usr_data = udata;

    // malloc
    will_return(mock_malloc, false);
    will_return(mock_malloc, true); // exec malloc

    // pthread_mutex_init
    will_return(__wrap_pthread_mutex_init, 0);
    // pthread_cond_init
    will_return(__wrap_pthread_cond_init, 0);
    // pthread_mutex_lock
    will_return(__wrap_pthread_mutex_lock, 0);

    // StartDownload
    will_return(__wrap_SYS_get_blob, SYS_RESULT_OK);

    // WaitBlobOperationCallback
    internal_WaitBlobOperationCallback(SYS_RESULT_OK);

    // pthread_cond_destory
    will_return(__wrap_pthread_cond_destroy, 0);
    // pthread_mutex_destory
    will_return(__wrap_pthread_mutex_destroy, 0);

    // free
    will_return(mock_free, false);

    ut_bdb_bypass = 0;

    ret = BlobDownload(s_iot_client_ud, request_url, offset, size, cb, usr_data, &dl_size,
                       &http_status);

    assert_int_equal(ret, SYS_RESULT_OK);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownload_fully_success2(void **state)
{
    enum SYS_result ret;
    char *udata = "user_data";

    char *request_url = "dummy_url";
    size_t offset;
    size_t size;
    SysAppUdDownloadCb cb;
    void *usr_data;

    // size
    offset = 0;
    size = 64;
    cb = &dummy_cb;
    usr_data = udata;

    // malloc
    will_return(mock_malloc, false);
    will_return(mock_malloc, true); // exec malloc

    // pthread_mutex_init
    will_return(__wrap_pthread_mutex_init, 0);
    // pthread_cond_init
    will_return(__wrap_pthread_cond_init, 0);
    // pthread_mutex_lock
    will_return(__wrap_pthread_mutex_lock, 0);

    // StartDownload
    will_return(__wrap_SYS_get_blob, SYS_RESULT_OK);

    // WaitBlobOperationCallback
    internal_WaitBlobOperationCallback(SYS_RESULT_OK);

    // http_status
    // dl_size

    // pthread_cond_destory
    will_return(__wrap_pthread_cond_destroy, 0);
    // pthread_mutex_destory
    will_return(__wrap_pthread_mutex_destroy, 0);

    // free
    will_return(mock_free, false);

    ut_bdb_bypass = 0;

    ret = BlobDownload(s_iot_client_ud, request_url, offset, size, cb, usr_data, NULL, NULL);

    assert_int_equal(ret, SYS_RESULT_OK);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownload_fully_success3(void **state)
{
    enum SYS_result ret;
    char *udata = "user_data";

    char *request_url = "dummy_url";
    size_t offset;
    size_t size;
    SysAppUdDownloadCb cb;
    void *usr_data;

    // size
    offset = 0;
    size = 64;
    cb = &dummy_cb;
    usr_data = udata;

    // malloc
    will_return(mock_malloc, false);
    will_return(mock_malloc, true); // exec malloc

    // pthread_mutex_init
    will_return(__wrap_pthread_mutex_init, 0);
    // pthread_cond_init
    will_return(__wrap_pthread_cond_init, 0);
    // pthread_mutex_lock
    will_return(__wrap_pthread_mutex_lock, 0);

    // StartDownload
    will_return(__wrap_SYS_get_blob, SYS_RESULT_OK);

    // WaitBlobOperationCallback
    internal_WaitBlobOperationCallback(SYS_RESULT_OK);

    // pthread_cond_destory
    will_return(__wrap_pthread_cond_destroy, 0);
    // pthread_mutex_destory
    will_return(__wrap_pthread_mutex_destroy, 0);

    // free
    will_return(mock_free, false);

    ut_bdb_bypass = 0;

    ret = BlobDownload(s_iot_client_ud, request_url, offset, size, cb, usr_data, NULL, NULL);

    assert_int_equal(ret, SYS_RESULT_OK);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownload_error_malloc(void **state)
{
    enum SYS_result ret;
    char *udata = "user_data";

    char *request_url = "dummy_url";
    size_t offset;
    size_t size;
    SysAppUdDownloadCb cb;
    void *usr_data;

    // size
    offset = 0;
    size = 64;
    cb = &dummy_cb;
    usr_data = udata;

    // malloc
    will_return(mock_malloc, false);
    will_return(mock_malloc, false); // return NULL

    ut_bdb_bypass = 0;

    ret = BlobDownload(s_iot_client_ud, request_url, offset, size, cb, usr_data, NULL, NULL);

    assert_int_equal(ret, SYS_RESULT_ERRNO);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownload_error_mutex_init(void **state)
{
    enum SYS_result ret;
    char *udata = "user_data";

    char *request_url = "dummy_url";
    size_t offset;
    size_t size;
    SysAppUdDownloadCb cb;
    void *usr_data;

    // size
    offset = 0;
    size = 64;
    cb = &dummy_cb;
    usr_data = udata;

    // malloc
    will_return(mock_malloc, false);
    will_return(mock_malloc, true); // exec malloc

    // pthread_mutex_init
    will_return(__wrap_pthread_mutex_init, -1); // <- error!

    // free
    will_return(mock_free, false);

    ut_bdb_bypass = 0;

    ret = BlobDownload(s_iot_client_ud, request_url, offset, size, cb, usr_data, NULL, NULL);

    assert_int_equal(ret, SYS_RESULT_ERRNO);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownload_error_cond_init(void **state)
{
    enum SYS_result ret;
    char *udata = "user_data";

    char *request_url = "dummy_url";
    size_t offset;
    size_t size;
    SysAppUdDownloadCb cb;
    void *usr_data;

    // size
    offset = 0;
    size = 64;
    cb = &dummy_cb;
    usr_data = udata;

    // malloc
    will_return(mock_malloc, false);
    will_return(mock_malloc, true); // exec malloc

    // pthread_mutex_init
    will_return(__wrap_pthread_mutex_init, 0);
    // pthread_cond_init
    will_return(__wrap_pthread_cond_init, -1); // <-- error !

    // pthread_mutex_destroy
    will_return(__wrap_pthread_mutex_destroy, 0);

    // free
    will_return(mock_free, false);

    ut_bdb_bypass = 0;

    ret = BlobDownload(s_iot_client_ud, request_url, offset, size, cb, usr_data, NULL, NULL);

    assert_int_equal(ret, SYS_RESULT_ERRNO);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownload_error_mutex_lock(void **state)
{
    enum SYS_result ret;
    char *udata = "user_data";

    char *request_url = "dummy_url";
    size_t offset;
    size_t size;
    SysAppUdDownloadCb cb;
    void *usr_data;

    // size
    offset = 0;
    size = 64;
    cb = &dummy_cb;
    usr_data = udata;

    // malloc
    will_return(mock_malloc, false);
    will_return(mock_malloc, true); // exec malloc

    // pthread_mutex_init
    will_return(__wrap_pthread_mutex_init, 0);
    // pthread_cond_init
    will_return(__wrap_pthread_cond_init, 0);
    // pthread_mutex_lock
    will_return(__wrap_pthread_mutex_lock, -1); // <-- error !

    // pthread_cond_destory
    will_return(__wrap_pthread_cond_destroy, 0);

    // pthread_mutex_destroy
    will_return(__wrap_pthread_mutex_destroy, 0);

    // free
    will_return(mock_free, false);

    ut_bdb_bypass = 0;

    ret = BlobDownload(s_iot_client_ud, request_url, offset, size, cb, usr_data, NULL, NULL);

    assert_int_equal(ret, SYS_RESULT_ERRNO);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownload_error_mutex_lock_retry_max(void **state)
{
    enum SYS_result ret;
    char *udata = "user_data";

    char *request_url = "dummy_url";
    size_t offset;
    size_t size;
    SysAppUdDownloadCb cb;
    void *usr_data;

    // size
    offset = 0;
    size = 64;
    cb = &dummy_cb;
    usr_data = udata;

    // malloc
    will_return(mock_malloc, false);
    will_return(mock_malloc, true); // exec malloc

    // pthread_mutex_init
    will_return(__wrap_pthread_mutex_init, 0);
    // pthread_cond_init
    will_return(__wrap_pthread_cond_init, 0);
    // pthread_mutex_lock
    will_return(__wrap_pthread_mutex_lock, EAGAIN); // <-- error !
    will_return(__wrap_pthread_mutex_lock, EAGAIN); // <-- error !
    will_return(__wrap_pthread_mutex_lock, EAGAIN); // <-- error !
    will_return(__wrap_pthread_mutex_lock, EAGAIN); // <-- error !
    will_return(__wrap_pthread_mutex_lock, EAGAIN); // <-- error !
    will_return(__wrap_pthread_mutex_lock, EAGAIN); // <-- error !

    // pthread_cond_destory
    will_return(__wrap_pthread_cond_destroy, 0);

    // pthread_mutex_destroy
    will_return(__wrap_pthread_mutex_destroy, 0);

    // free
    will_return(mock_free, false);

    ut_bdb_bypass = 0;

    ret = BlobDownload(s_iot_client_ud, request_url, offset, size, cb, usr_data, NULL, NULL);

    assert_int_equal(ret, SYS_RESULT_ERRNO);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownload_error_SYS_get_blob(void **state)
{
    enum SYS_result ret;
    char *udata = "user_data";

    char *request_url = "dummy_url";
    size_t offset;
    size_t size;
    SysAppUdDownloadCb cb;
    void *usr_data;

    // size
    offset = 0;
    size = 64;
    cb = &dummy_cb;
    usr_data = udata;

    // malloc
    will_return(mock_malloc, false);
    will_return(mock_malloc, true); // exec malloc

    // pthread_mutex_init
    will_return(__wrap_pthread_mutex_init, 0);
    // pthread_cond_init
    will_return(__wrap_pthread_cond_init, 0);
    // pthread_mutex_lock
    will_return(__wrap_pthread_mutex_lock, 0);

    // StartDownload
    will_return(__wrap_SYS_get_blob, SYS_RESULT_ERRNO); //  <= error!

    // pthread_mutex_unlock
    will_return(__wrap_pthread_mutex_unlock, 0);

    // pthread_cond_destory
    will_return(__wrap_pthread_cond_destroy, 0);
    // pthread_mutex_destory
    will_return(__wrap_pthread_mutex_destroy, 0);

    // free
    will_return(mock_free, false);

    ut_bdb_bypass = 0;

    ret = BlobDownload(s_iot_client_ud, request_url, offset, size, cb, usr_data, NULL, NULL);

    assert_int_equal(ret, SYS_RESULT_ERRNO);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_BlobDownload_error_WaitBlobOperationCallback(void **state)
{
    enum SYS_result ret;
    char *udata = "user_data";

    char *request_url = "dummy_url";
    size_t offset;
    size_t size;
    SysAppUdDownloadCb cb;
    void *usr_data;

    // size
    offset = 0;
    size = 64;
    cb = &dummy_cb;
    usr_data = udata;

    // malloc
    will_return(mock_malloc, false);
    will_return(mock_malloc, true); // exec malloc

    // pthread_mutex_init
    will_return(__wrap_pthread_mutex_init, 0);
    // pthread_cond_init
    will_return(__wrap_pthread_cond_init, 0);
    // pthread_mutex_lock
    will_return(__wrap_pthread_mutex_lock, 0);

    // StartDownload
    will_return(__wrap_SYS_get_blob, SYS_RESULT_OK);

    // WaitBlobOperationCallback
    internal_WaitBlobOperationCallback(SYS_RESULT_ERRNO); // <= error!

    // pthread_cond_destory
    will_return(__wrap_pthread_cond_destroy, 0);
    // pthread_mutex_destory
    will_return(__wrap_pthread_mutex_destroy, 0);

    // free
    will_return(mock_free, false);

    ut_bdb_bypass = 0;

    ret = BlobDownload(s_iot_client_ud, request_url, offset, size, cb, usr_data, NULL, NULL);

    assert_int_equal(ret, SYS_RESULT_ERRNO);

    return;
}

/*----------------------------------------------------------------------------*/

//
// RetCode SysAppUdInitialize(struct SYS_client *iot_client_ud)
//

/*----------------------------------------------------------------------------*/
static void test_SysAppUdInitialize_success_normal(void **state)
{
    RetCode ret;

    s_iot_client_ud = NULL; // Emulate not initialized.

    ret = SysAppUdInitialize(s_iot_client_ud);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdInitialize_success_already(void **state)
{
    RetCode ret;
    struct SYS_client client;

    s_iot_client_ud = &client; // Emulate already initialized.

    ret = SysAppUdInitialize(s_iot_client_ud);

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// RetCode SysAppUdFinalize(void)
//

/*----------------------------------------------------------------------------*/
static void test_SysAppUdFinalize_success_normal(void **state)
{
    RetCode ret;
    struct SYS_client client;

    s_iot_client_ud = &client; // Emulate already initialized.

    ret = SysAppUdFinalize();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdFinalize_success_notinitialized(void **state)
{
    RetCode ret;

    s_iot_client_ud = NULL; // Emulate not initialized.

    ret = SysAppUdFinalize();

    assert_int_equal(ret, kRetOk);

    return;
}

/*----------------------------------------------------------------------------*/

//
// size_t SysAppUdGetImageSize(char *request_url, int *http_status)
//

/*----------------------------------------------------------------------------*/
static void test_SysAppUdGetImageSize_fully_success(void **state)
{
    size_t ret;
    int ret_status;
    struct SYS_client client;

    // SysAppUdIsThisRequestToStopForDownload();
    s_is_force_stop = false;

    s_iot_client_ud = &client; // Emulate already initialized.

    internal_BlobDownload(SYS_RESULT_OK, 0, 1); // ret, status, dl_size

    internal_SysAppUdGetImageSizeLoop(false);

    ret = SysAppUdGetImageSize("req_url", &ret_status);

    assert_int_not_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdGetImageSize_fully_success2(void **state)
{
    size_t ret;
    int ret_status;
    struct SYS_client client;

    // SysAppUdIsThisRequestToStopForDownload();
    s_is_force_stop = false;

    s_iot_client_ud = &client; // Emulate already initialized.

    internal_BlobDownload(SYS_RESULT_OK, 0, 0);     // ret, status, dl_size
    internal_BlobDownload_2nd(SYS_RESULT_OK, 0, 1); // ret, status, dl_size

    internal_SysAppUdGetImageSizeLoop(false);

    ret = SysAppUdGetImageSize("req_url", &ret_status);

    assert_int_not_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdGetImageSize_error_not_initialized(void **state)
{
    size_t ret;
    int ret_status;

    // SysAppUdIsThisRequestToStopForDownload();
    s_is_force_stop = false;

    s_iot_client_ud = NULL; // Emulate not initialized.

    ret = SysAppUdGetImageSize("req_url", &ret_status);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdGetImageSize_error_already_downloading(void **state)
{
    size_t ret;
    int ret_status;
    struct SYS_client client;

    s_iot_client_ud = &client; // Emulate already initialized.
    // SysAppUdIsThisRequestToStopForDownload();
    s_is_force_stop = true;

    // for SysAppDeployGetCancel
    will_return(__wrap_SysAppDeployGetCancel, false);

    ret = SysAppUdGetImageSize("req_url", &ret_status);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdGetImageSize_error_http403(void **state)
{
    size_t ret;
    int ret_status;
    struct SYS_client client;

    // SysAppUdIsThisRequestToStopForDownload();
    s_is_force_stop = false;

    s_iot_client_ud = &client; // Emulate already initialized.

    internal_BlobDownload(SYS_RESULT_ERRNO, 403, 0); // ret, status, dl_size

    internal_SysAppUdGetImageSizeLoop(false);

    ret = SysAppUdGetImageSize("req_url", &ret_status);

    assert_int_equal(ret, 0);
    assert_int_equal(ret_status, 403);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdGetImageSize_BadParams(void **state)
{
    size_t ret;
    int ret_status;
    struct SYS_client client;

    // SysAppUdIsThisRequestToStopForDownload();
    s_is_force_stop = false;

    s_iot_client_ud = &client; // Emulate already initialized.

    internal_BlobDownload(SYS_RESULT_ERRNO, -1, 0); // ret, status, dl_size

    internal_SysAppUdGetImageSizeLoop(false);

    ret = SysAppUdGetImageSize("req_url", &ret_status);

    assert_int_equal(ret, 0);
    assert_int_equal(ret_status, -1);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdGetImageSize_error_retry_over(void **state)
{
    size_t ret;
    int ret_status;
    struct SYS_client client;

    // SysAppUdIsThisRequestToStopForDownload();
    s_is_force_stop = false;

    s_iot_client_ud = &client; // Emulate already initialized.

    internal_BlobDownload(SYS_RESULT_ERRNO, 0, 0); // 1
    internal_BlobDownload(SYS_RESULT_ERRNO, 0, 0); // 2
    internal_BlobDownload(SYS_RESULT_ERRNO, 0, 0); // 3
    internal_BlobDownload(SYS_RESULT_ERRNO, 0, 0); // 4
    internal_BlobDownload(SYS_RESULT_ERRNO, 0, 0); // 5
    internal_BlobDownload(SYS_RESULT_ERRNO, 0, 0); // 6
    internal_BlobDownload(SYS_RESULT_ERRNO, 0, 0); // 7
    internal_BlobDownload(SYS_RESULT_ERRNO, 0, 0); // 8
    internal_BlobDownload(SYS_RESULT_ERRNO, 0, 0); // 9
    internal_BlobDownload(SYS_RESULT_ERRNO, 0, 0); // 10
    internal_BlobDownload(SYS_RESULT_ERRNO, 0, 0); // 11 error!

    internal_SysAppUdGetImageSizeLoop(false);

    ret = SysAppUdGetImageSize("req_url", &ret_status);

    assert_int_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdGetImageSize_no_http_status(void **state)
{
    size_t ret;
    struct SYS_client client;

    // SysAppUdIsThisRequestToStopForDownload();
    s_is_force_stop = false;

    s_iot_client_ud = &client; // Emulate already initialized.

    internal_BlobDownload(SYS_RESULT_OK, 0, 1); // ret, status, dl_size

    internal_SysAppUdGetImageSizeLoop(false);

    ret = SysAppUdGetImageSize("req_url", NULL);

    assert_int_not_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdGetImageSize_min_num_of_read_unit(void **state)
{
    size_t ret;
    struct SYS_client client;

    // SysAppUdIsThisRequestToStopForDownload();
    s_is_force_stop = false;

    s_iot_client_ud = &client; // Emulate already initialized.

    internal_BlobDownload(SYS_RESULT_OK, 0, 0); // ret, status, dl_size
    internal_BlobDownload(SYS_RESULT_OK, 0, 1); // ret, status, dl_size

    internal_SysAppUdGetImageSizeLoop(false);

    ret = SysAppUdGetImageSize("req_url", NULL);

    assert_int_not_equal(ret, 0);

    return;
}

/*----------------------------------------------------------------------------*/

//
// ssize_t SysAppUdGetImageData(char              *request_url,
//                             size_t             offset,
//                             size_t             size,
//                             SysAppUdDownloadCb cb,
//                             void              *usr_param,
//                             int               *http_status)
//

/*----------------------------------------------------------------------------*/
static void test_SysAppUdGetImageData_fully_success(void **state)
{
    ssize_t ret;
    size_t offset = 0;
    size_t size = 0;
    SysAppUdDownloadCb cb = &dummy_cb;
    void *usr_param = NULL;
    int http_status;
    struct SYS_client client;

    // SysAppUdIsThisRequestToStopForDownload();
    s_is_force_stop = false;

    s_iot_client_ud = &client; // Emulate already initialized.

    internal_BlobDownload(SYS_RESULT_OK, 0, 1);

    // for SysAppDeployGetCancel
    will_return(__wrap_SysAppDeployGetCancel, false);

    ret = SysAppUdGetImageData("req_url", offset, size, cb, usr_param, &http_status);

    assert_int_equal(ret, 1);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdGetImageData_error_not_initialized(void **state)
{
    ssize_t ret;
    size_t offset = 0;
    size_t size = 0;
    SysAppUdDownloadCb cb = &dummy_cb;
    void *usr_param = NULL;
    int http_status;

    s_iot_client_ud = NULL; // Emulate not initialized.

    ret = SysAppUdGetImageData("req_url", offset, size, cb, usr_param, &http_status);

    assert_int_equal(ret, -1);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdGetImageData_error_already_downloading(void **state)
{
    ssize_t ret;
    size_t offset = 0;
    size_t size = 0;
    SysAppUdDownloadCb cb = &dummy_cb;
    void *usr_param = NULL;
    int http_status;
    struct SYS_client client;

    s_iot_client_ud = &client; // Emulate already initialized.
    s_is_force_stop = true;

    // for SysAppDeployGetCancel
    will_return(__wrap_SysAppDeployGetCancel, false);

    ret = SysAppUdGetImageData("req_url", offset, size, cb, usr_param, &http_status);

    assert_int_equal(ret, -1);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdGetImageData_error_blob_download(void **state)
{
    ssize_t ret;
    size_t offset = 0;
    size_t size = 0;
    SysAppUdDownloadCb cb = &dummy_cb;
    void *usr_param = NULL;
    int http_status;
    struct SYS_client client;

    // SysAppUdIsThisRequestToStopForDownload();
    s_iot_client_ud = &client; // Emulate already initialized.
    s_is_force_stop = false;

    // for SysAppDeployGetCancel
    will_return(__wrap_SysAppDeployGetCancel, false);

    internal_BlobDownload(SYS_RESULT_ERRNO, 0, 0);

    ret = SysAppUdGetImageData("req_url", offset, size, cb, usr_param, &http_status);

    assert_int_equal(ret, -1);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdGetImageData_fully_stop_deploy(void **state)
{
    ssize_t ret;
    size_t offset = 0;
    size_t size = 0;
    SysAppUdDownloadCb cb = &dummy_cb;
    void *usr_param = NULL;
    int http_status;
    struct SYS_client client;

    // SysAppUdIsThisRequestToStopForDownload();
    s_is_force_stop = false;

    s_iot_client_ud = &client; // Emulate already initialized.

    internal_BlobDownload(SYS_RESULT_OK, 0, 1);

    // for SysAppDeployGetCancel
    will_return(__wrap_SysAppDeployGetCancel, true);

    ret = SysAppUdGetImageData("req_url", offset, size, cb, usr_param, &http_status);

    assert_int_equal(ret, -1);

    return;
}

/*----------------------------------------------------------------------------*/

//
// void SysAppUdRequestToStopDownload(void)
//

/*----------------------------------------------------------------------------*/
static void test_SysAppUdRequestToStopDownload_fully_success(void **state)
{
    // SysAppUdIsThisRequestToStopForDownload();
    s_is_force_stop = false;

    SysAppUdRequestToStopDownload();

    assert_true(s_is_force_stop);

    return;
}

/*----------------------------------------------------------------------------*/

//
// bool SysAppUdIsThisRequestToStopForDownload(void)
//

/*----------------------------------------------------------------------------*/
static void test_SysAppUdIsThisRequestToStopForDownload_fully_success_true(void **state)
{
    bool ret;
    s_is_force_stop = true;

    // for SysAppDeployGetCancel
    will_return(__wrap_SysAppDeployGetCancel, true);

    ret = SysAppUdIsThisRequestToStopForDownload();

    assert_int_equal(s_is_force_stop, ret);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdIsThisRequestToStopForDownload_fully_success_false(void **state)
{
    bool ret;
    s_is_force_stop = false;

    // for SysAppDeployGetCancel
    will_return(__wrap_SysAppDeployGetCancel, false);

    ret = SysAppUdIsThisRequestToStopForDownload();

    assert_int_equal(s_is_force_stop, ret);

    return;
}

/*----------------------------------------------------------------------------*/

//
// void SysAppUdCancelDownloadStopRequest(void)
//

/*----------------------------------------------------------------------------*/
static void test_SysAppUdCancelDownloadStopRequest_fully_success(void **state)
{
    s_is_force_stop = true;

    SysAppUdCancelDownloadStopRequest();

    assert_int_equal(s_is_force_stop, false);

    return;
}

/*----------------------------------------------------------------------------*/

//
// void SysAppUdWaitForDownloadToStop(void)
//

/*----------------------------------------------------------------------------*/
static void test_SysAppUdWaitForDownloadToStop_fully_success1(void **state)
{
    struct SYS_client client;

    s_iot_client_ud = &client; // Emulate already initialized.
    s_is_force_stop = false;

    SysAppUdWaitForDownloadToStop();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdWaitForDownloadToStop_fully_success2(void **state)
{
    struct SYS_client client;

    s_iot_client_ud = &client; // Emulate already initialized.
    s_is_force_stop = true;

    expect_value(__wrap_SYS_process_event, c, s_iot_client_ud);
    expect_value(__wrap_SYS_process_event, ms, 1000);
    will_return(__wrap_SYS_process_event, SYS_RESULT_SHOULD_EXIT);

    SysAppUdWaitForDownloadToStop();

    return;
}

/*----------------------------------------------------------------------------*/
static void test_SysAppUdWaitForDownloadToStop_error_notinilialized(void **state)
{
    s_iot_client_ud = NULL; // Emulate not initialized.

    SysAppUdWaitForDownloadToStop();

    return;
}

/*----------------------------------------------------------------------------*/
#define WAIT_FORCE_STOP_RETRY_NUM (60) /* See target source code. */
static void test_SysAppUdWaitForDownloadToStop_error_retry_over(void **state)
{
    struct SYS_client client;

    s_iot_client_ud = &client; // Emulate already initialized.
    s_is_force_stop = true;

    for (int i = 0; i < WAIT_FORCE_STOP_RETRY_NUM; i++) {
        expect_value(__wrap_SYS_process_event, c, s_iot_client_ud);
        expect_value(__wrap_SYS_process_event, ms, 1000);
        will_return(__wrap_SYS_process_event, SYS_RESULT_OK);
    }

    SysAppUdWaitForDownloadToStop();

    return;
}

/*----------------------------------------------------------------------------*/

//
// main()
//

/*----------------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {

        // WaitBlobOperationCallback
        cmocka_unit_test(test_WaitBlobOperationCallback_fully_success),
        cmocka_unit_test(test_WaitBlobOperationCallback_error_noise),
        cmocka_unit_test(test_WaitBlobOperationCallback_error_timedout),
        cmocka_unit_test(test_WaitBlobOperationCallback_error_timedwait),

        // BlobDownloadCb
        cmocka_unit_test(test_BlobDownloadCb_fully_success_more_data),
        cmocka_unit_test(test_BlobDownloadCb_fully_success_finished),
        cmocka_unit_test(test_BlobDownloadCb_success_mutex_lock_retry),
        cmocka_unit_test(test_BlobDownloadCb_error_no_user),
        cmocka_unit_test(test_BlobDownloadCb_error_no_blob),
        cmocka_unit_test(test_BlobDownloadCb_error_more_data_1),
        cmocka_unit_test(test_BlobDownloadCb_error_more_data_2),
        cmocka_unit_test(test_BlobDownloadCb_error_more_data_3),
        cmocka_unit_test(test_BlobDownloadCb_error_more_data_4),
        cmocka_unit_test(test_BlobDownloadCb_error_more_data_5),
        cmocka_unit_test(test_BlobDownloadCb_error_finished_416),
        cmocka_unit_test(test_BlobDownloadCb_error_finished_417),
        cmocka_unit_test(test_BlobDownloadCb_error_timeout),
        cmocka_unit_test(test_BlobDownloadCb_error_error),
        cmocka_unit_test(test_BlobDownloadCb_error_default),
        cmocka_unit_test(test_BlobDownloadCb_error_mutex_lock),
        cmocka_unit_test(test_BlobDownloadCb_error_mutex_lock_retry_max),

        // BlobDownload
        cmocka_unit_test(test_BlobDownload_fully_success1),
        cmocka_unit_test(test_BlobDownload_fully_success2),
        cmocka_unit_test(test_BlobDownload_fully_success3),
        cmocka_unit_test(test_BlobDownload_error_malloc),
        cmocka_unit_test(test_BlobDownload_error_mutex_init),
        cmocka_unit_test(test_BlobDownload_error_cond_init),
        cmocka_unit_test(test_BlobDownload_error_mutex_lock),
        cmocka_unit_test(test_BlobDownload_error_mutex_lock_retry_max),
        cmocka_unit_test(test_BlobDownload_error_SYS_get_blob),
        cmocka_unit_test(test_BlobDownload_error_WaitBlobOperationCallback),

        // SysAppUdInitialize
        cmocka_unit_test(test_SysAppUdInitialize_success_normal),
        cmocka_unit_test(test_SysAppUdInitialize_success_already),

        // SysAppUdFinalize
        cmocka_unit_test(test_SysAppUdFinalize_success_normal),
        cmocka_unit_test(test_SysAppUdFinalize_success_notinitialized),

        // SysAppUdGetImageSize
        cmocka_unit_test(test_SysAppUdGetImageSize_fully_success),
        cmocka_unit_test(test_SysAppUdGetImageSize_fully_success2),
        cmocka_unit_test(test_SysAppUdGetImageSize_error_not_initialized),
        cmocka_unit_test(test_SysAppUdGetImageSize_error_already_downloading),
        cmocka_unit_test(test_SysAppUdGetImageSize_error_http403),
        cmocka_unit_test(test_SysAppUdGetImageSize_BadParams),
        cmocka_unit_test(test_SysAppUdGetImageSize_error_retry_over),
        cmocka_unit_test(test_SysAppUdGetImageSize_no_http_status),
        cmocka_unit_test(test_SysAppUdGetImageSize_min_num_of_read_unit),

        // SysAppUdGetImageData
        cmocka_unit_test(test_SysAppUdGetImageData_fully_success),
        cmocka_unit_test(test_SysAppUdGetImageData_error_not_initialized),
        cmocka_unit_test(test_SysAppUdGetImageData_error_already_downloading),
        cmocka_unit_test(test_SysAppUdGetImageData_error_blob_download),
        cmocka_unit_test(test_SysAppUdGetImageData_fully_stop_deploy),

        // SysAppUdRequestToStopDownload
        cmocka_unit_test(test_SysAppUdRequestToStopDownload_fully_success),

        // SysAppUdIsThisRequestToStopForDownload
        cmocka_unit_test(test_SysAppUdIsThisRequestToStopForDownload_fully_success_true),
        cmocka_unit_test(test_SysAppUdIsThisRequestToStopForDownload_fully_success_false),

        // SysAppUdCancelDownloadStopRequest
        cmocka_unit_test(test_SysAppUdCancelDownloadStopRequest_fully_success),

        // SysAppUdWaitForDownloadToStop
        cmocka_unit_test(test_SysAppUdWaitForDownloadToStop_fully_success1),
        cmocka_unit_test(test_SysAppUdWaitForDownloadToStop_fully_success2),
        cmocka_unit_test(test_SysAppUdWaitForDownloadToStop_error_notinilialized),
        cmocka_unit_test(test_SysAppUdWaitForDownloadToStop_error_retry_over),

    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}

/*----------------------------------------------------------------------------*/
