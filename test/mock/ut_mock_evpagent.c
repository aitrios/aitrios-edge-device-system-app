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

#include "sdk_backdoor.h"
#include "evp/sdk_sys.h"
#if defined(__NuttX__)
#include "nuttx/compiler.h"
#endif

static SYS_response_cb s_response_cb = NULL;
static void *s_response_user = NULL;
static int s_response_count = 0;
#ifdef INITIAL_SETTING_APP_PS
static SYS_command_cb s_direct_command_cb = NULL;
static void *s_direct_command_cb_user = NULL;
static bool s_direct_command_cb_callreq = false;
static SYS_config_cb s_configuration_cb = NULL;
static void *s_configuration_cb_user = NULL;
static bool s_configuration_cb_callreq = false;
#endif // INITIAL_SETTING_APP_PS

static SYS_telemetry_cb s_telemetry_cb = NULL;
static void *s_telemetry_user = NULL;
static int s_telemetry_count = 0;
static enum SYS_callback_reason s_telemetry_reason = SYS_REASON_FINISHED;

/*----------------------------------------------------------------------------*/
int __wrap_EVP_undeployModules(void)
{
    function_called();

    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
bool __wrap_EVP_wasm_runtime_register_natives(const char *module_name, NativeSymbol *native_symbols,
                                              uint32_t n_native_symbols)
{
    return mock_type(bool);
}

/*----------------------------------------------------------------------------*/
#if _BSD_SIZE_T_DEFINED_(__NuttX__)
int __wrap_evp_agent_main(int, FAR char **)
{
    return mock_type(int);
}
#endif
/*----------------------------------------------------------------------------*/
enum evp_agent_status __wrap_EVP_getAgentStatus(void)
{
    return mock_type(enum evp_agent_status);
}

/*----------------------------------------------------------------------------*/
int __wrap_EVP_Agent_unregister_sys_client(struct SYS_client *c)
{
    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
struct SYS_client *__wrap_EVP_Agent_register_sys_client(void)
{
    return mock_type(struct SYS_client *);
}

/*----------------------------------------------------------------------------*/
enum SYS_result __wrap_SYS_set_state(struct SYS_client *c, const char *key, const char *value)
{
    return mock_type(enum SYS_result);
}

/*----------------------------------------------------------------------------*/
enum SYS_result __wrap_SYS_send_telemetry(struct SYS_client *c, const char *topic,
                                          const char *value, SYS_telemetry_cb cb, void *user)
{
    check_expected_ptr(c);
    check_expected_ptr(topic);
    check_expected_ptr(value);
    check_expected_ptr(cb);
    check_expected_ptr(user);

    enum SYS_result result = mock_type(enum SYS_result);

    if (result == SYS_RESULT_OK) {
        s_telemetry_count = mock_type(int);
        s_telemetry_reason = mock_type(enum SYS_callback_reason);
        s_telemetry_cb = cb;
        s_telemetry_user = user;
    }

    return result;
}

/*----------------------------------------------------------------------------*/
enum SYS_result __wrap_SYS_process_event(struct SYS_client *c, int ms)
{
    check_expected_ptr(c);
    check_expected(ms);

    if (s_response_cb != NULL) {
        if (s_response_count == 0) {
            s_response_cb(c, SYS_REASON_FINISHED, s_response_user);

            s_response_cb = NULL;
            s_response_user = NULL;
        }
        s_response_count--;
    }

    if (s_telemetry_cb != NULL) {
        if (s_telemetry_count == 0) {
            s_telemetry_cb(c, s_telemetry_reason, s_telemetry_user);

            s_telemetry_cb = NULL;
            s_telemetry_user = NULL;
        }
        s_telemetry_count--;
    }

#ifdef INITIAL_SETTING_APP_PS
    if (s_direct_command_cb != NULL) {
        if (s_direct_command_cb_callreq == true) {
            s_direct_command_cb(c, 12345, "", s_direct_command_cb_user);

            s_direct_command_cb = NULL;
            s_direct_command_cb_user = NULL;

            s_direct_command_cb_callreq = false;
        }
    }

    if (s_configuration_cb != NULL) {
        if (s_configuration_cb_callreq == true) {
            s_configuration_cb(c, "system_settings", "", SYS_CONFIG_HUB, SYS_REASON_FINISHED,
                               s_configuration_cb_user);

            s_configuration_cb = NULL;
            s_configuration_cb_user = NULL;

            s_configuration_cb_callreq = false;
        }
    }
#endif // INITIAL_SETTING_APP_PS

    return mock_type(enum SYS_result);
}

/*----------------------------------------------------------------------------*/
enum SYS_result __wrap_SYS_set_response_cb(struct SYS_client *c, SYS_response_id id,
                                           const char *response, enum SYS_response_status status,
                                           SYS_response_cb cb, void *user)
{
    check_expected_ptr(c);
    check_expected(id);
    check_expected_ptr(response);
    check_expected(status);
    check_expected_ptr(cb);
    check_expected_ptr(user);

    enum SYS_result result = mock_type(enum SYS_result);

    if (result == SYS_RESULT_OK) {
        s_response_count = mock_type(int);
        s_response_cb = cb;
        s_response_user = user;
    }

    return result;
}

/*----------------------------------------------------------------------------*/
enum SYS_result __wrap_SYS_set_configuration_cb(struct SYS_client *c, const char *topic,
                                                SYS_config_cb cb, enum SYS_type_configuration type,
                                                void *user)
{
    check_expected_ptr(c);
    check_expected_ptr(topic);
    check_expected_ptr(cb);
    check_expected(type);
    check_expected_ptr(user);
#ifdef INITIAL_SETTING_APP_PS
    s_configuration_cb_callreq = mock_type(bool);
    s_configuration_cb = cb;
    s_configuration_cb_user = user;
#endif // INITIAL_SETTING_APP_PS

    return mock_type(enum SYS_result);
}

/*----------------------------------------------------------------------------*/
enum SYS_result __wrap_SYS_register_command_cb(struct SYS_client *c, const char *command,
                                               SYS_command_cb cb, void *user)
{
    check_expected_ptr(c);
    check_expected_ptr(command);
    check_expected_ptr(cb);
    check_expected_ptr(user);
#ifdef INITIAL_SETTING_APP_PS
    s_direct_command_cb_callreq = mock_type(bool);
    s_direct_command_cb = cb;
    s_direct_command_cb_user = user;
#endif // INITIAL_SETTING_APP_PS
    return mock_type(enum SYS_result);
}

/*----------------------------------------------------------------------------*/
enum SYS_result __wrap_SYS_get_blob(struct SYS_client *c, const char *url,
                                    const struct SYS_http_header *headers, SYS_blob_cb cb,
                                    void *user)
{
    return mock_type(enum SYS_result);
}

/*----------------------------------------------------------------------------*/
int __wrap_evp_agent_startup(void)
{
    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
void __wrap_evp_agent_shutdown(void)
{
    ;
}
