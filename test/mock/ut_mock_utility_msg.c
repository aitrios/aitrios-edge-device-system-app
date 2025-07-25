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

#include <string.h>
#include <stdlib.h>
#include "utility_msg.h"
#include "system_app_deploy_private.h"
#include "ut_mock_utility_msg.h"

/*----------------------------------------------------------------------------*/
UtilityMsgErrCode __wrap_UtilityMsgInitialize(void)
{
    return mock_type(UtilityMsgErrCode);
}

/*----------------------------------------------------------------------------*/
UtilityMsgErrCode __wrap_UtilityMsgFinalize(void)
{
    return mock_type(UtilityMsgErrCode);
}

/*----------------------------------------------------------------------------*/
UtilityMsgErrCode __wrap_UtilityMsgRecv(int32_t handle, void *buf, uint32_t size,
                                        int32_t timeout_ms, int32_t *recv_size)
{
    check_expected(handle);
    check_expected(size);
    check_expected(timeout_ms);

    *recv_size = mock_type(int32_t);
    void *msg = mock_type(void *);
    if (msg != NULL) {
        memcpy(buf, msg, *recv_size);
    }
    else {
        buf = NULL;
    }

    return mock_type(UtilityMsgErrCode);
}

/*----------------------------------------------------------------------------*/
UtilityMsgErrCode __wrap_UtilityMsgSend(int32_t handle, const void *msg, uint32_t msg_size,
                                        int32_t msg_prio, int32_t *sent_size)
{
    UtilityMsgErrCode ret = mock_type(UtilityMsgErrCode);

    check_expected(handle);
    check_expected(msg_size);
    check_expected(msg_prio);

    switch (mock_type(UtilityMsgSendType)) {
        case UtilityMsgSendTypeDeployMessage: {
            DeployMessage_t *deploy_msg = *((DeployMessage_t **)msg);

            if (deploy_msg == NULL) {
                check_expected_ptr(deploy_msg);
            }
            else {
                check_expected(deploy_msg->topic_id);
                check_expected(deploy_msg->len);
                check_expected_ptr(deploy_msg->config);

                if (ret == kUtilityMsgOk) {
                    free(deploy_msg);
                }
            }
        } break;
        default:
            /* Do Nothing */
            break;
    }

    *sent_size = mock_type(int32_t);

    return ret;
}

/*----------------------------------------------------------------------------*/
UtilityMsgErrCode __wrap_UtilityMsgOpen(int32_t *handle, uint32_t queue_size, uint32_t max_msg_size)
{
    check_expected(queue_size);
    check_expected(max_msg_size);

    *handle = mock_type(int32_t);

    return mock_type(UtilityMsgErrCode);
}

/*----------------------------------------------------------------------------*/
UtilityMsgErrCode __wrap_UtilityMsgClose(int32_t handle)
{
    check_expected(handle);

    return mock_type(UtilityMsgErrCode);
}

/*----------------------------------------------------------------------------*/
