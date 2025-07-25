/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#if defined(__NuttX__)
#include <nuttx/config.h>
#endif

#include "clock_manager.h"
#include "clock_manager_setting.h"
#include "network_manager.h"
#include "system_manager.h"

#include "system_app_led.h"
#include "initial_setting_app_qrcode.h"
#include "initial_setting_app_qrcode_private.h"
#include "base64/include/base64.h"

extern IsaQrcodePayloadInfo *sp_payload_info;
extern uint8_t s_qr_total_bit;
extern uint8_t s_qr_count_bit;
extern bool s_IsQRFirst;

extern bool IsValidCommonUrl(const char *domain, int max_len);

uint8_t header_encoded[HEADER_STRINGLEN] = "AAIAAAAAAAAAAAAAAAAAAA=="; // for cmocka expect_string

/*----------------------------------------------------------------------------*/
//
// For EsfClockManager API
//
/*----------------------------------------------------------------------------*/
static void CheckEsfClockManagerSetParamsForcibly(const EsfClockManagerParams *data,
                                                  const EsfClockManagerParamsMask *mask,
                                                  EsfClockManagerReturnValue esfcm_result)
{
    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname,
                 mask->connect.hostname);
    if (mask->connect.hostname == 1) {
        expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname,
                      data->connect.hostname);
    }
    will_return(__wrap_EsfClockManagerSetParamsForcibly, esfcm_result);
}

/*----------------------------------------------------------------------------*/
//
// For EsfNetworkManager API
//
/*----------------------------------------------------------------------------*/
static void CheckEsfNetworkManagerSaveParameter(const EsfNetworkManagerParameterMask *mask,
                                                const EsfNetworkManagerParameter *parameter,
                                                EsfNetworkManagerResult esfnm_result)
{
    // Check mask
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.ip,
                 mask->normal_mode.dev_ip.ip);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.subnet_mask,
                 mask->normal_mode.dev_ip.subnet_mask);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.gateway,
                 mask->normal_mode.dev_ip.gateway);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip.dns,
                 mask->normal_mode.dev_ip.dns);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.ip,
                 mask->normal_mode.dev_ip_v6.ip);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.subnet_mask,
                 mask->normal_mode.dev_ip_v6.subnet_mask);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.gateway,
                 mask->normal_mode.dev_ip_v6.gateway);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.dev_ip_v6.dns,
                 mask->normal_mode.dev_ip_v6.dns);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.ssid,
                 mask->normal_mode.wifi_sta.ssid);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.password,
                 mask->normal_mode.wifi_sta.password);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.wifi_sta.encryption,
                 mask->normal_mode.wifi_sta.encryption);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.ip_method,
                 mask->normal_mode.ip_method);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->normal_mode.netif_kind,
                 mask->normal_mode.netif_kind);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.ip,
                 mask->accesspoint_mode.dev_ip.ip);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.subnet_mask,
                 mask->accesspoint_mode.dev_ip.subnet_mask);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.gateway,
                 mask->accesspoint_mode.dev_ip.gateway);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.dev_ip.dns,
                 mask->accesspoint_mode.dev_ip.dns);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.ssid,
                 mask->accesspoint_mode.wifi_ap.ssid);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.password,
                 mask->accesspoint_mode.wifi_ap.password);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.encryption,
                 mask->accesspoint_mode.wifi_ap.encryption);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->accesspoint_mode.wifi_ap.channel,
                 mask->accesspoint_mode.wifi_ap.channel);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.url, mask->proxy.url);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.port, mask->proxy.port);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.username, mask->proxy.username);
    expect_value(__wrap_EsfNetworkManagerSaveParameter, mask->proxy.password, mask->proxy.password);

    // Check parameter. If mask is 0, don't care.
    if (mask->normal_mode.dev_ip.ip == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.dev_ip.ip,
                      parameter->normal_mode.dev_ip.ip);
    }
    if (mask->normal_mode.dev_ip.subnet_mask == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->normal_mode.dev_ip.subnet_mask,
                      parameter->normal_mode.dev_ip.subnet_mask);
    }
    if (mask->normal_mode.dev_ip.gateway == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.dev_ip.gateway,
                      parameter->normal_mode.dev_ip.gateway);
    }
    if (mask->normal_mode.dev_ip.dns == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.dev_ip.dns,
                      parameter->normal_mode.dev_ip.dns);
    }
    if (mask->normal_mode.dev_ip_v6.ip == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.dev_ip_v6.ip,
                      parameter->normal_mode.dev_ip_v6.ip);
    }
    if (mask->normal_mode.dev_ip_v6.subnet_mask == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->normal_mode.dev_ip_v6.subnet_mask,
                      parameter->normal_mode.dev_ip_v6.subnet_mask);
    }
    if (mask->normal_mode.dev_ip_v6.gateway == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->normal_mode.dev_ip_v6.gateway,
                      parameter->normal_mode.dev_ip_v6.gateway);
    }
    if (mask->normal_mode.dev_ip_v6.dns == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.dev_ip_v6.dns,
                      parameter->normal_mode.dev_ip_v6.dns);
    }
    if (mask->normal_mode.wifi_sta.ssid == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.wifi_sta.ssid,
                      parameter->normal_mode.wifi_sta.ssid);
    }
    if (mask->normal_mode.wifi_sta.password == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->normal_mode.wifi_sta.password,
                      parameter->normal_mode.wifi_sta.password);
    }
    if (mask->normal_mode.wifi_sta.encryption == 1) {
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     parameter->normal_mode.wifi_sta.encryption,
                     parameter->normal_mode.wifi_sta.encryption);
    }
    if (mask->normal_mode.ip_method == 1) {
        expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.ip_method,
                     parameter->normal_mode.ip_method);
    }
    if (mask->normal_mode.netif_kind == 1) {
        expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->normal_mode.netif_kind,
                     parameter->normal_mode.netif_kind);
    }
    if (mask->accesspoint_mode.dev_ip.ip == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->accesspoint_mode.dev_ip.ip,
                      parameter->accesspoint_mode.dev_ip.ip);
    }
    if (mask->accesspoint_mode.dev_ip.subnet_mask == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->accesspoint_mode.dev_ip.subnet_mask,
                      parameter->accesspoint_mode.dev_ip.subnet_mask);
    }
    if (mask->accesspoint_mode.dev_ip.gateway == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->accesspoint_mode.dev_ip.gateway,
                      parameter->accesspoint_mode.dev_ip.gateway);
    }
    if (mask->accesspoint_mode.dev_ip.dns == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->accesspoint_mode.dev_ip.dns,
                      parameter->accesspoint_mode.dev_ip.dns);
    }
    if (mask->accesspoint_mode.wifi_ap.ssid == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->accesspoint_mode.wifi_ap.ssid,
                      parameter->accesspoint_mode.wifi_ap.ssid);
    }
    if (mask->accesspoint_mode.wifi_ap.password == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter,
                      parameter->accesspoint_mode.wifi_ap.password,
                      parameter->accesspoint_mode.wifi_ap.password);
    }
    if (mask->accesspoint_mode.wifi_ap.encryption == 1) {
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     parameter->accesspoint_mode.wifi_ap.encryption,
                     parameter->accesspoint_mode.wifi_ap.encryption);
    }
    if (mask->accesspoint_mode.wifi_ap.channel == 1) {
        expect_value(__wrap_EsfNetworkManagerSaveParameter,
                     parameter->accesspoint_mode.wifi_ap.channel,
                     parameter->accesspoint_mode.wifi_ap.channel);
    }
    if (mask->proxy.url == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->proxy.url,
                      parameter->proxy.url);
    }
    if (mask->proxy.port == 1) {
        expect_value(__wrap_EsfNetworkManagerSaveParameter, parameter->proxy.port,
                     parameter->proxy.port);
    }
    if (mask->proxy.username == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->proxy.username,
                      parameter->proxy.username);
    }
    if (mask->proxy.password == 1) {
        expect_string(__wrap_EsfNetworkManagerSaveParameter, parameter->proxy.password,
                      parameter->proxy.password);
    }

    will_return(__wrap_EsfNetworkManagerSaveParameter, esfnm_result);
}

/*----------------------------------------------------------------------------*/
//
// For EsfSystemManager API
//
/*----------------------------------------------------------------------------*/
static void SetEmptyToEsfSystemManagerSetProjectId(EsfSystemManagerResult ret)
{
    expect_memory(__wrap_EsfSystemManagerSetProjectId, data, "", 1);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetProjectId, ret);
    return;
}

/*----------------------------------------------------------------------------*/
static void SetEmptyToEsfSystemManagerSetRegisterToken(EsfSystemManagerResult ret)
{
    expect_memory(__wrap_EsfSystemManagerSetRegisterToken, data, "", 1);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size, 1);
    will_return(__wrap_EsfSystemManagerSetRegisterToken, ret);
    return;
}

/*----------------------------------------------------------------------------*/
//
// Common
//
/*----------------------------------------------------------------------------*/
static void InitializeQRPayloadInfo()
{
    if (sp_payload_info == NULL) {
        sp_payload_info = (IsaQrcodePayloadInfo *)malloc(sizeof(IsaQrcodePayloadInfo));
        memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
    }
}

/*----------------------------------------------------------------------------*/
static void CleanupQRPayloadInfo()
{
    if (sp_payload_info != NULL) {
        free(sp_payload_info);
        sp_payload_info = NULL;
    }
}

/*----------------------------------------------------------------------------*/
static size_t CalcQrInputSize(size_t payload_size)
{
    return payload_size - HEADER_STRINGLEN - MagicNumber_STRINGLEN;
}

/*----------------------------------------------------------------------------*/
// Custom strtok with converting '\;' -> ';'
char *CustomStrToken(char **input)
{
    if (input == NULL || *input == NULL || **input == '\0') {
        return NULL;
    }

    const char *start = *input;
    char *token = NULL;
    int escape = 0;

    while (**input) {
        if (**input == '\\') {
            escape = !escape; // detect escape
            (*input)++;
            continue;
        }

        if (**input == ';' && !escape) {
            size_t length = *input - start;
            token = (char *)malloc(length + 1);
            if (token == NULL) {
                return NULL;
            }
            strncpy(token, start, length);
            token[length] = '\0';

            (*input)++;
            return token;
        }

        escape = 0; // reset escape flag
        (*input)++;
    }

    if (start < *input) {
        size_t length = *input - start;
        token = (char *)malloc(length + 1);
        if (token == NULL) {
            return NULL;
        }
        strncpy(token, start, length);
        token[length] = '\0';

        *input = NULL; // complete to get all token
        return token;
    }

    return NULL; // there are no tokens
}

/*----------------------------------------------------------------------------*/
static void CopyWithBackslashSkip(const char *token, char *expected_string, size_t max_length)
{
    size_t j = 0;
    size_t token_length = strlen(token);

    for (size_t i = 0; i < token_length && j < max_length - 1; i++) {
        if (token[i] == '\\') {
            i++;
            if (i >= token_length)
                break;
        }
        expected_string[j] = token[i];
        j++;
    }
    expected_string[j] = '\0';
}

/*----------------------------------------------------------------------------*/
static void ConfirmUserDataSetPayload(const char *payload)
{
    size_t payload_length = strlen(payload);
    if (payload_length <= (HEADER_STRINGLEN + MagicNumber_STRINGLEN)) {
        // UserData is empty
        return;
    }
    const char *start = payload + HEADER_STRINGLEN; // skip header
    size_t userdata_length = payload_length - HEADER_STRINGLEN -
                             MagicNumber_STRINGLEN; // pick up only UserData

    char *userdata = malloc(userdata_length);
    if (userdata == NULL) {
        return;
    }
    strncpy(userdata, start, userdata_length - 1);
    userdata[userdata_length - 1] = '\0';

    char *token;
    while ((token = CustomStrToken(&userdata)) != NULL) {
        // printf("%s\n", token);
        switch (*token) {
            case QRIndex:
                // skip
                break;
            case EVPHubURL:
                char expected_string_E[sizeof(sp_payload_info->m_evphub_url)];
                CopyWithBackslashSkip(token + 2, expected_string_E,
                                      sizeof(sp_payload_info->m_evphub_url));
                assert_string_equal(sp_payload_info->m_evphub_url, expected_string_E);
                break;

            case EVPHubPort:
                char expected_string_H[sizeof(sp_payload_info->m_evphub_port)];
                CopyWithBackslashSkip(token + 2, expected_string_H,
                                      sizeof(sp_payload_info->m_evphub_port));
                assert_string_equal(sp_payload_info->m_evphub_port, expected_string_H);
                break;

            case EVPMode:
                char expected_string_e[sizeof(sp_payload_info->m_evp_mode)];
                CopyWithBackslashSkip(token + 2, expected_string_e, strlen(token + 2) + 1);
                assert_string_equal(sp_payload_info->m_evp_mode, expected_string_e);
                break;

            case EVPMqttInsecure:
                char expected_string_t[sizeof(sp_payload_info->m_evp_mqtt_insecure)];
                CopyWithBackslashSkip(token + 2, expected_string_t,
                                      sizeof(sp_payload_info->m_evp_mode));
                assert_string_equal(sp_payload_info->m_evp_mqtt_insecure, expected_string_t);
                break;

            case ProjectID:
                char expected_string_A[sizeof(sp_payload_info->m_project_id)];
                CopyWithBackslashSkip(token + 2, expected_string_A,
                                      sizeof(sp_payload_info->m_project_id));
                assert_string_equal(sp_payload_info->m_project_id, expected_string_A);
                break;

            case RegisterToken:
                char expected_string_B[sizeof(sp_payload_info->m_register_token)];
                CopyWithBackslashSkip(token + 2, expected_string_B,
                                      sizeof(sp_payload_info->m_register_token));
                assert_string_equal(sp_payload_info->m_register_token, expected_string_B);
                break;

            case WiFiSSID:
                char expected_string_S[sizeof(sp_payload_info->m_wifi_ssid)];
                CopyWithBackslashSkip(token + 2, expected_string_S,
                                      sizeof(sp_payload_info->m_wifi_ssid));
                assert_string_equal(sp_payload_info->m_wifi_ssid, expected_string_S);
                break;

            case WiFiPassword:
                char expected_string_P[sizeof(sp_payload_info->m_wifi_pass)];
                CopyWithBackslashSkip(token + 2, expected_string_P,
                                      sizeof(sp_payload_info->m_wifi_pass));
                assert_string_equal(sp_payload_info->m_wifi_pass, expected_string_P);
                break;

            case ProxyURL:
                char expected_string_X[sizeof(sp_payload_info->m_proxy_url)];
                CopyWithBackslashSkip(token + 2, expected_string_X,
                                      sizeof(sp_payload_info->m_proxy_url));
                assert_string_equal(sp_payload_info->m_proxy_url, expected_string_X);
                break;

            case ProxyPort:
                char expected_string_O[sizeof(sp_payload_info->m_proxy_port)];
                CopyWithBackslashSkip(token + 2, expected_string_O,
                                      sizeof(sp_payload_info->m_proxy_port));
                assert_string_equal(sp_payload_info->m_proxy_port, expected_string_O);
                break;

            case ProxyUserName:
                char expected_string_U[sizeof(sp_payload_info->m_proxy_user)];
                CopyWithBackslashSkip(token + 2, expected_string_U,
                                      sizeof(sp_payload_info->m_proxy_user));
                assert_string_equal(sp_payload_info->m_proxy_user, expected_string_U);
                break;

            case ProxyPassword:
                char expected_string_W[sizeof(sp_payload_info->m_proxy_pass)];
                CopyWithBackslashSkip(token + 2, expected_string_W,
                                      sizeof(sp_payload_info->m_proxy_pass));
                assert_string_equal(sp_payload_info->m_proxy_pass, expected_string_W);
                break;

            case IPAddress:
                char expected_string_I[sizeof(sp_payload_info->m_static_ip)];
                CopyWithBackslashSkip(token + 2, expected_string_I,
                                      sizeof(sp_payload_info->m_static_ip));
                assert_string_equal(sp_payload_info->m_static_ip, expected_string_I);
                break;

            case IPAddress_v6:
                char expected_string_i[sizeof(sp_payload_info->m_static_ip_v6)];
                CopyWithBackslashSkip(token + 2, expected_string_i,
                                      sizeof(sp_payload_info->m_static_ip_v6));
                assert_string_equal(sp_payload_info->m_static_ip_v6, expected_string_i);
                break;

            case SubnetMask:
                char expected_string_K[sizeof(sp_payload_info->m_static_subnetmask)];
                CopyWithBackslashSkip(token + 2, expected_string_K,
                                      sizeof(sp_payload_info->m_static_subnetmask));
                assert_string_equal(sp_payload_info->m_static_subnetmask, expected_string_K);
                break;

            case SubnetMask_v6:
                char expected_string_k[sizeof(sp_payload_info->m_static_subnetmask_v6)];
                CopyWithBackslashSkip(token + 2, expected_string_k,
                                      sizeof(sp_payload_info->m_static_subnetmask_v6));
                assert_string_equal(sp_payload_info->m_static_subnetmask_v6, expected_string_k);
                break;

            case Gateway:
                char expected_string_G[sizeof(sp_payload_info->m_static_gateway)];
                CopyWithBackslashSkip(token + 2, expected_string_G,
                                      sizeof(sp_payload_info->m_static_gateway));
                assert_string_equal(sp_payload_info->m_static_gateway, expected_string_G);
                break;

            case Gateway_v6:
                char expected_string_g[sizeof(sp_payload_info->m_static_gateway_v6)];
                CopyWithBackslashSkip(token + 2, expected_string_g,
                                      sizeof(sp_payload_info->m_static_gateway_v6));
                assert_string_equal(sp_payload_info->m_static_gateway_v6, expected_string_g);
                break;

            case DNS:
                char expected_string_D[sizeof(sp_payload_info->m_static_dns)];
                CopyWithBackslashSkip(token + 2, expected_string_D,
                                      sizeof(sp_payload_info->m_static_dns));
                assert_string_equal(sp_payload_info->m_static_dns, expected_string_D);
                break;

            case DNS_v6:
                char expected_string_d[sizeof(sp_payload_info->m_static_dns_v6)];
                CopyWithBackslashSkip(token + 2, expected_string_d,
                                      sizeof(sp_payload_info->m_static_dns_v6));
                assert_string_equal(sp_payload_info->m_static_dns_v6, expected_string_d);
                break;

            case NTP:
                char expected_string_T[sizeof(sp_payload_info->m_static_ntp)];
                CopyWithBackslashSkip(token + 2, expected_string_T,
                                      sizeof(sp_payload_info->m_static_ntp));
                assert_string_equal(sp_payload_info->m_static_ntp, expected_string_T);
                break;

            default:
                break;
        }
        free(token);
    }

    free(userdata);
}

/*----------------------------------------------------------------------------*/
static void VerifyQrcodeDecodePayloadPerProperty(const char *input_payload,
                                                 size_t input_payload_size,
                                                 IsaQrcodeDecodeResult expected_result)
{
    IsaQrcodeErrorCode ret;

    size_t payload_size = input_payload_size; /* Remove null string */
    uint8_t header_decoded[HEADER_LEN_BUFFER] = {0x00, 0x02,
                                                 0x00}; // valid format(version and option)

    // Set Parameter for decode
    expect_string(__wrap_EsfCodecBase64Decode, in, header_encoded);
    expect_value(__wrap_EsfCodecBase64Decode, in_size, sizeof(header_encoded));
    will_return(__wrap_EsfCodecBase64Decode, true);
    will_return(__wrap_EsfCodecBase64Decode, header_decoded);
    will_return(__wrap_EsfCodecBase64Decode, sizeof(header_decoded));
    will_return(__wrap_EsfCodecBase64Decode, kEsfCodecBase64ResultSuccess);

    // Simulate malloc success
    expect_value(mock_malloc, __size, CalcQrInputSize(payload_size) + 1);
    will_return(mock_malloc, true); // Check Parameter for malloc
    will_return(mock_malloc, true);

    // Call target function
    IsaQrcodeDecodeResult result = kIsaQrcodeDecode_Invalid;
    uint8_t qr_count = 1;

    // confirm pointer is NULL
    expect_any(mock_free, __ptr);
    will_return(mock_free, true); // Check Parameter

    ret = IsaQrcodeDecodePayload((uint8_t *)input_payload, payload_size, &result, &qr_count);

    // Confirm Userdata only when identified valid payload
    if (expected_result == kIsaQrcodeDecode_PartRecognized ||
        expected_result == kIsaQrcodeDecode_AllRecognized) {
        ConfirmUserDataSetPayload((char *)input_payload);
    }

    // Check return value
    assert_int_equal(result, expected_result);
    assert_int_equal(ret, kIsaQrcode_Success);

    return;
}

/*----------------------------------------------------------------------------*/
static int setup(void **state)
{
    // allocate heap memory
    InitializeQRPayloadInfo();
    assert_non_null(sp_payload_info);
    // initialize static variable
    s_qr_total_bit = 0x00;
    s_qr_count_bit = 0x00;
    s_IsQRFirst = true;

    return 0;
}

/*----------------------------------------------------------------------------*/
static int teardown(void **state)
{
    // free heap memory
    CleanupQRPayloadInfo();
    assert_null(sp_payload_info);

    return 0;
}

/*----------------------------------------------------------------------------*/

//
// IsaQrcodeInit()
//

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeInit_success(void **state)
{
    IsaQrcodeErrorCode ret;

    expect_value(mock_malloc, __size, sizeof(IsaQrcodePayloadInfo));
    will_return(mock_malloc, true); // Check Parameter
    will_return(mock_malloc, true); // Return allocated address

    ret = IsaQrcodeInit();

    assert_int_equal(ret, kIsaQrcode_Success);
    assert_non_null(sp_payload_info);

    IsaQrcodePayloadInfo payload_info = {0};
    assert_memory_equal(sp_payload_info, &payload_info, sizeof(IsaQrcodePayloadInfo));
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeInit_malloc_failure(void **state)
{
    IsaQrcodeErrorCode ret;

    expect_value(mock_malloc, __size, sizeof(IsaQrcodePayloadInfo));
    will_return(mock_malloc, true);  // Check Parameter
    will_return(mock_malloc, false); // Skip memory allocation

    ret = IsaQrcodeInit();

    assert_int_equal(ret, kIsaQrcode_Failed);
    assert_null(sp_payload_info);
    return;
}
/*----------------------------------------------------------------------------*/

//
// IsaQrcodeDecodePayload()
//

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_invalid_payload(void **state)
{
    IsaQrcodeErrorCode ret;

    int32_t payload_size = HEADER_STRINGLEN + 1;
    IsaQrcodeDecodeResult result = kIsaQrcodeDecode_Invalid;
    uint8_t qr_count = 1;

    ret = IsaQrcodeDecodePayload(NULL, payload_size, &result, &qr_count);
    assert_int_equal(ret, kIsaQrcode_InvalidArgument);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_invalid_payload_size(void **state)
{
    IsaQrcodeErrorCode ret;

    const char *payload = "DUMMY";
    int32_t payload_size = HEADER_STRINGLEN; // <= HEADER_STRINGLEN
    IsaQrcodeDecodeResult result = kIsaQrcodeDecode_Invalid;
    uint8_t qr_count = 1;

    ret = IsaQrcodeDecodePayload((uint8_t *)payload, payload_size, &result, &qr_count);
    assert_int_equal(result, kIsaQrcodeDecode_Invalid);
    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_invalid_result(void **state)
{
    IsaQrcodeErrorCode ret;

    const char *payload = "DUMMY";
    int32_t payload_size = HEADER_STRINGLEN + 1;
    uint8_t qr_count = 1;

    ret = IsaQrcodeDecodePayload((uint8_t *)payload, payload_size, NULL, &qr_count);
    assert_int_equal(ret, kIsaQrcode_InvalidArgument);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_invalid_magic_header(void **state)
{
    IsaQrcodeErrorCode ret;

    const char *payload = "DUMMY";
    int32_t payload_size = HEADER_STRINGLEN + 1;
    IsaQrcodeDecodeResult result = kIsaQrcodeDecode_Invalid;
    uint8_t qr_count = 1;

    ret = IsaQrcodeDecodePayload((uint8_t *)payload, payload_size, &result, &qr_count);
    assert_int_equal(result, kIsaQrcodeDecode_Invalid);
    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_b64decode_failed(void **state)
{
    IsaQrcodeErrorCode ret;

    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==;U1FS";

    // Simulate failed decode
    expect_string(__wrap_EsfCodecBase64Decode, in, header_encoded);
    expect_value(__wrap_EsfCodecBase64Decode, in_size, sizeof(header_encoded));
    will_return(__wrap_EsfCodecBase64Decode, false);
    will_return(__wrap_EsfCodecBase64Decode, kEsfCodecBase64ResultOutOfRange);

    // Call function
    int32_t payload_size = strlen(payload);
    IsaQrcodeDecodeResult result = kIsaQrcodeDecode_Invalid;
    uint8_t qr_count = 1;

    ret = IsaQrcodeDecodePayload((uint8_t *)payload, payload_size, &result, &qr_count);

    // Check return value
    assert_int_equal(result, kIsaQrcodeDecode_Invalid);
    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_invalid_qrcode_format_version(void **state)
{
    IsaQrcodeErrorCode ret;

    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==;U1FS";
    uint8_t expected_header_decoded[HEADER_LEN_BUFFER] = {0x00}; // invalid format(version)

    // Set Parameter for decode
    expect_string(__wrap_EsfCodecBase64Decode, in, header_encoded);
    expect_value(__wrap_EsfCodecBase64Decode, in_size, sizeof(header_encoded));
    will_return(__wrap_EsfCodecBase64Decode, true);
    will_return(__wrap_EsfCodecBase64Decode, expected_header_decoded);
    will_return(__wrap_EsfCodecBase64Decode, sizeof(expected_header_decoded));
    will_return(__wrap_EsfCodecBase64Decode, kEsfCodecBase64ResultSuccess);

    // Call function
    int32_t payload_size = strlen(payload);
    IsaQrcodeDecodeResult result = kIsaQrcodeDecode_Invalid;
    uint8_t qr_count = 1;

    ret = IsaQrcodeDecodePayload((uint8_t *)payload, payload_size, &result, &qr_count);
    // Check return value
    assert_int_equal(result, kIsaQrcodeDecode_Invalid);
    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_invalid_qrcode_format_option(void **state)
{
    IsaQrcodeErrorCode ret;

    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==;U1FS";
    uint8_t expected_header_decoded[HEADER_LEN_BUFFER] = {
        0x00, 0x02, 0x01}; // valid format(version), invalid format(option)

    // Set Parameter for decode
    expect_string(__wrap_EsfCodecBase64Decode, in, header_encoded);
    expect_value(__wrap_EsfCodecBase64Decode, in_size, sizeof(header_encoded));
    will_return(__wrap_EsfCodecBase64Decode, true);
    will_return(__wrap_EsfCodecBase64Decode, expected_header_decoded);
    will_return(__wrap_EsfCodecBase64Decode, sizeof(expected_header_decoded));
    will_return(__wrap_EsfCodecBase64Decode, kEsfCodecBase64ResultSuccess);

    // Call function
    int32_t payload_size = strlen(payload);
    IsaQrcodeDecodeResult result = kIsaQrcodeDecode_Invalid;
    uint8_t qr_count = 1;

    ret = IsaQrcodeDecodePayload((uint8_t *)payload, payload_size, &result, &qr_count);
    // Check return value
    assert_int_equal(result, kIsaQrcodeDecode_Invalid);
    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_qr_data_malloc_failure(void **state)
{
    IsaQrcodeErrorCode ret;

    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==;U1FS";
    uint8_t header_decoded[HEADER_LEN_BUFFER] = {0x00, 0x02,
                                                 0x00}; // valid format(version and option)

    // Set Parameter for decode
    expect_string(__wrap_EsfCodecBase64Decode, in, header_encoded);
    expect_value(__wrap_EsfCodecBase64Decode, in_size, sizeof(header_encoded));
    will_return(__wrap_EsfCodecBase64Decode, true);
    will_return(__wrap_EsfCodecBase64Decode, header_decoded);
    will_return(__wrap_EsfCodecBase64Decode, sizeof(header_decoded));
    will_return(__wrap_EsfCodecBase64Decode, kEsfCodecBase64ResultSuccess);

    // Simulate malloc failed
    will_return(mock_malloc, false); // Skip check parameter
    will_return(mock_malloc, false); // Skip memory allocation

    // Call function
    int32_t payload_size = strlen(payload);
    IsaQrcodeDecodeResult result = kIsaQrcodeDecode_Invalid;
    uint8_t qr_count = 1;

    ret = IsaQrcodeDecodePayload((uint8_t *)payload, payload_size, &result, &qr_count);
    // Check return value
    assert_int_equal(result, kIsaQrcodeDecode_ResultNum);
    assert_int_equal(ret, kIsaQrcode_Failed);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_invalid_qr_property(void **state)
{
    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==AU1FS";
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_QRIndex_null(void **state)
{
    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==;U1FS";
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_empty(void **state)
{
    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==N=11;U1FS";
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPHubURL_only(void **state)
{
    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;U1FS"; // EVPHubURL
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPHubURL_Invalid(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com.;U1FS;H=8883;"
        "S=WiFiSSID;P=WiFiPassword;U1FS"; // EVPHubURL_Invaid(tail".")+Required(T3Ws)

    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPHubURL_IP(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=192.168.0.100;H=8883;"
        "S=WiFiSSID;P=WiFiPassword;U1FS"; // EVPHubURL_IP+Required(T3Ws)

    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPHubURL_InvalidIP(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=192.168.0;H=8883;"
        "S=WiFiSSID;P=WiFiPassword;U1FS"; // EVPHubURL_IP+Required(T3Ws)

    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPHubURL_IPv6(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=2001:0db8:85a3:0000:0000:8a2e:0370:7334;H=8883;"
        "S=WiFiSSID;P=WiFiPassword;U1FS"; // EVPHubURL_IPv6+Required(T3Ws)

    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPHubURL_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E= ;H=8883;"
        "S=WiFiSSID;P=WiFiPassword;U1FS"; // EVPHubURL_IPv6+Required(T3Ws)

    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPHubPort_only(void **state)
{
    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==N=11;H=8883;U1FS"; // EVPHubPort
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPHubPort_low(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;"
        "H=0;S=WiFiSSID;P=WiFiPassword;U1FS"; // Required(T3Ws)+EVPHubPort_Invalid

    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPHubPort_high(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;"
        "H=65535;S=WiFiSSID;P=WiFiPassword;U1FS"; // Required(T3Ws)+EVPHubPort_Invalid

    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPHubPort_Invalid_low(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;"
        "H=-1;S=WiFiSSID;P=WiFiPassword;U1FS"; // Required(T3Ws)+EVPHubPort_Invalid

    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPHubPort_Invalid_high(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;"
        "H=65536;S=WiFiSSID;P=WiFiPassword;U1FS"; // Required(T3Ws)+EVPHubPort_Invalid

    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPHubURLPort(void **state)
{
    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;U1FS"; // EVPHubURLPort
    size_t payload_size = strlen(payload);

#if defined(CONFIG_BOARD_WIFI_SMALL_ES) /* T3Ws */
    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
#else
    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
#endif

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPHubURLPortWifiSSID(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;U1FS"; // EVPHubURLPortWiFiSSID
    size_t payload_size = strlen(payload);

#if defined(CONFIG_BOARD_WIFI_SMALL_ES) /* T3Ws */
    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
#else
    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
#endif
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_WifiSSID_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S= ;P=WiFiPassword;U1FS"; // Required(T3Ws)+WiFi SSID(empty)

    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPHubURLPortWifiPassword(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;P=WiFiPassword;U1FS"; // EVPHubURLPortWiFiPassword
    size_t payload_size = strlen(payload);

#if defined(CONFIG_BOARD_WIFI_SMALL_ES) /* T3Ws */
    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
#else
    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
#endif
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_WifiPassword_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P= ;U1FS"; // Required(T3Ws)+WiFi SSID(empty)

    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_RequiredFields(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "U1FS"; // Required(T3Ws)

    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_RequiredFields_noE(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;H=8883;S=WiFiSSID;P=WiFiPassword;U1FS"; // Required(T3Ws)-EVPHub

    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_RequiredFields_noH(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;S=WiFiSSID;P=WiFiPassword;U1FS"; // Required(T3Ws)-EVPPort

    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_RequiredFields_noS(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;P=WiFiPassword;U1FS"; // Required(T3Ws)-WiFiSSID

    size_t payload_size = strlen(payload);
#if defined(CONFIG_BOARD_WIFI_SMALL_ES) /* T3Ws */
    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
#else
    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
#endif
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_RequiredFields_noP(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;U1FS"; // Required(T3Ws)-WiFiPassword

    size_t payload_size = strlen(payload);

#if defined(CONFIG_BOARD_WIFI_SMALL_ES) /* T3Ws */
    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
#else
    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
#endif
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPMqttInsecure_TLSOnly(void **state)
{
    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==N=11;t=0;U1FS"; // EVPMqttInsecure
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPMqttInsecure_TLSEnable(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;t=0;"
        "U1FS"; // EVPMqttInsecure
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPMqttInsecure_TLSDisable(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;t=1;"
        "U1FS"; // EVPMqttInsecure
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPMqttInsecure_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;t= "
        ";U1FS"; // EVPMqttInsecure
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_invalid_EVPMqttInsecure(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;t=2;"
        "U1FS"; // EVPMqttInsecure
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_EVPMode(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;e=TB;"
        "U1FS"; // EVPMode
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProjectID_RegisterTokenOnly(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;A=ProjectID;B=RegisterToken;U1FS"; // ProjectID and
                                                                         // RegisterToken
                                                                         // (combination required)
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProjectID_RegisterToken(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "A=ProjectID;B=RegisterToken;U1FS"; // ProjectID and
                                            // RegisterToken
                                            // (combination required)
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProjectID_RegisterToken_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "A= ;B= ;U1FS"; // ProjectID and
                        // RegisterToken
                        // (combination required) blank
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProjectID_RegisterToken_Oversize(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "A=ProjectIDu1pK1Pg4qralUAe0k8xp4gzC;B=RegisterTokenNdxqg6opqRMVQJUIDZ98544qROT49Eyz;"
        "U1FS"; // ProjectID(33charas) and
                // RegisterToken(45charas)
                // (combination required)
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProjectID_only(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "A=ProjectID;U1FS"; // ProjectID only
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_RegisterToken_only(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "B=RegisterToken;U1FS"; // RegisterToken only
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_WiFiSSID_only(void **state)
{
    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==N=11;S=WiFiSSID;U1FS"; // WiFiSSID
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_WiFiSSID_Oversize(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID4hxOBAMnVc19uOv9tS4OqnefB;"
        "P=WiFiPassword;U1FS"; // WiFiSSID(33charas)
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_WiFiPassword_only(void **state)
{
    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==N=11;P=WiFiPassword;U1FS"; // WiFiPassword
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_WiFiPassword_Oversize(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword8k8Nq63iN0KtSIpA59R6i;U1FS"; // WiFiPassword(33charas)
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyURL_only(void **state)
{
    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==N=11;X=ProxyURL.com;U1FS"; // ProxyURL
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyURL(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword;X=ProxyURL.com;U1FS"; // ProxyURL
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyURL_invalid(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword;X=ProxyURL.com.;U1FS"; // ProxyURL
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyURL_IPv4(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword;X=192.168.1.2;U1FS"; // ProxyURL
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyURL_invalidIPv4(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword;X=192.168.1.;U1FS"; // ProxyURL
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyURL_IPv6(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword;X=2001:0db8:85a3:0000:0000:8a2e:0370:7334;U1FS"; // ProxyURL
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyURL_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword;X= ;U1FS"; // ProxyURL
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyURL_empty(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword;X=;U1FS"; // ProxyURL
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyPort_only(void **state)
{
    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==N=11;O=10080;U1FS"; // ProxyPort
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyPort(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword;O=10080;U1FS"; // ProxyPort
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyPort_low(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=6663;S=WiFiSSID;"
        "P=WiFiPassword;O=0;U1FS"; // ProxyPort
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyPort_high(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword;O=65535;U1FS"; // ProxyPort
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyPort_low_invalid(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword;O=-1;U1FS"; // ProxyPort
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyPort_high_invalid(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword;O=65536;U1FS"; // ProxyPort
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyURLPort(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword;X=ProxyURL.com;O=8883;U1FS"; // ProxyURL Port
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyURLPort_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword;X= ;O=8883;U1FS"; // ProxyURL blank Port
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyUserName_only(void **state)
{
    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==N=11;U=ProxyUserName;U1FS"; // ProxyUserName
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyUserName(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;"
        "P=WiFiPassword;U=ProxyUserName;U1FS"; // ProxyUserName
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyUserName_Oversize(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "U=ProxyUserName1FsNzeZ99RlVkgwdJC7S;U1FS"; // ProxyUserName(33charas)
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyPassword_only(void **state)
{
    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==N=11;W=ProxyPassword;U1FS"; // ProxyPassword
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyPassword(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "W=ProxyPassword;U1FS"; // ProxyPassword
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_ProxyPassword_Oversize(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "W=ProxyPassword0gnv723LobdEwkKlMfbq;U1FS"; // ProxyPassword(33charas)
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_IPAddress(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "I=192.168.1.2;U1FS"; // IPAddress
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_IPAddress_invalid(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "I=192.168.1.;U1FS"; // IPAddress invalid
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_IPAddress_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "I= ;U1FS"; // IPAddress blank
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_IPAddress_v6(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "i=2001:0db8:85a3:0000:0000:8a2e:0370:7334;U1FS"; // IPAddress_v6
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_IPAddress_v6_invalid(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "i=ABCDEFGH;U1FS"; // IPAddress_v6 invalid
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_IPAddress_v6_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "i= ;U1FS"; // IPAddress_v6 blank
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_SubnetMask(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "K=255.255.255.0;U1FS"; // SubnetMask
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_SubnetMask_invalid(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "K=255.255.255;U1FS"; // SubnetMask invalid
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_SubnetMask_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "K= ;U1FS"; // SubnetMask blank
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_SubnetMask_v6(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "k=2001:0db8:85a3:0000:0000:8a2e:0370:0000;U1FS"; // SubnetMask_v6
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_SubnetMask_v6_invalid(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "k=ABCDEFGH;U1FS"; // SubnetMask_v6 invalid
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_SubnetMask_v6_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "k= ;U1FS"; // SubnetMask_v6 blank
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_Gateway(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "G=192.168.1.1;U1FS"; // Gateway
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_Gateway_invalid(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "G=192.168.1;U1FS"; // Gateway invalid
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_Gateway_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "G= ;U1FS"; // Gateway blank
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_Gateway_v6(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "g=fe80::1;U1FS"; // Gateway_v6
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_Gateway_v6_invalid(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "g=ABCDEFGH::1;U1FS"; // Gateway_v6 invalid
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_Gateway_v6_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "g= ;U1FS"; // Gateway_v6 blank
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_DNS(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "D=8.8.8.8;U1FS"; // DNS
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_DNS_invalid(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "D=8.8.8;U1FS"; // DNS invalid
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_DNS_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "D= ;U1FS"; // DNS blank
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_DNS_v6(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "d=2001:4860:4860::8888;U1FS"; // DNS_v6
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_DNS_v6_invalid(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "d=ABCDEFG::8888;U1FS"; // DNS_v6 invalid
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_DNS_v6_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "d= ;U1FS"; // DNS_v6 blank
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_StaticIP(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "I=192.168.1.2;K=255.255.255.0;G=192.168.1.1;D=8.8.8.8;"
        "i=2001:0db8:85a3:0000:0000:8a2e:0370:7334;U1FS"; // StaticIP + IPv6
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_NTP_only(void **state)
{
    const char *payload = "AAIAAAAAAAAAAAAAAAAAAA==N=11;T=pool.ntp.org;U1FS"; // NTP
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_NTP(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "T=pool.ntp.org;U1FS"; // NTP
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_NTP_invalid(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "T=pool.ntp.org.;U1FS"; // invalid NTP
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_NTP_IP(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "T=192.200.100.200;U1FS"; // NTP IP Address
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_NTP_IP_invalid(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "T=192.200.100.;U1FS"; // NTP IP Address
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_NTP_blank(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "T= ;U1FS"; // NTP blank
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_undefined_property(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "a=1;U1FS"; // undefined property
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_all_empty(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=;H=;e=;t=;A=;B=;S=;P=;X=;O=;U=;W=;"
        "I=;i=;K=;k=;G=;g=;D=;d=;T=;U1FS"; // undefined property
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_invalid_QrPayload(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;"
        "O11;U1FS"; // not include '='
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_escape_slash(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;S=hogehoge;P=12\\\\32;U1FS"; // including escape
                                                                   // character
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_UserData_escape_semicolon(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=11;S=hogehoge;P=12\\;32;U1FS"; // including escape
                                                                  // character
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_Halfway(void **state)
{
    const char *payload_first =
        "AAIAAAAAAAAAAAAAAAAAAA==N=21;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;U1FS"; // QR1
    size_t payload_size_first = strlen(payload_first);

    VerifyQrcodeDecodePayloadPerProperty(payload_first, payload_size_first,
                                         kIsaQrcodeDecode_PartRecognized);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_2nd(void **state)
{
    const char *payload_2nd =
        "AAIAAAAAAAAAAAAAAAAAAA==N=22;E=example.com;H=8883;S=WiFiSSID;P=WiFiPassword;U1FS"; // QR2
    size_t payload_size_2nd = strlen(payload_2nd);
    s_qr_total_bit = 0x03; // total num is 2
    s_qr_count_bit = 0x01; // take assumption read N=21 previously
    s_IsQRFirst = false;

    VerifyQrcodeDecodePayloadPerProperty(payload_2nd, payload_size_2nd, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_Required(void **state)
{
    const char *payload_first =
        "AAIAAAAAAAAAAAAAAAAAAA==N=21;E=example.com;S=WiFiSSID;P=WiFiPassword;U1FS"; // QR1
    size_t payload_size_first = strlen(payload_first);

    VerifyQrcodeDecodePayloadPerProperty(payload_first, payload_size_first,
                                         kIsaQrcodeDecode_PartRecognized);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_Required_2nd(void **state)
{
    const char *payload_2nd = "AAIAAAAAAAAAAAAAAAAAAA==N=22;H=8883;U1FS"; // QR2
    size_t payload_size_2nd = strlen(payload_2nd);
    s_qr_total_bit = 0x03; // total num is 2
    s_qr_count_bit = 0x01; // take assumption read N=21 previously
    s_IsQRFirst = false;

    VerifyQrcodeDecodePayloadPerProperty(payload_2nd, payload_size_2nd, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_multi3_1st(void **state)
{
    const char *payload_first =
        "AAIAAAAAAAAAAAAAAAAAAA==N=33;E=example.com;S=WiFiSSID;P=WiFiPassword;U1FS"; // QR1
    size_t payload_size_first = strlen(payload_first);

    VerifyQrcodeDecodePayloadPerProperty(payload_first, payload_size_first,
                                         kIsaQrcodeDecode_PartRecognized);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_multi3_2nd(void **state)
{
    const char *payload_2nd = "AAIAAAAAAAAAAAAAAAAAAA==N=32;H=8883;X=ProxyURL.com;U1FS"; // QR2
    size_t payload_size_2nd = strlen(payload_2nd);
    s_qr_total_bit = 0x07; // total num is 3
    s_qr_count_bit = 0x04; // take assumption read N=33 previously
    s_IsQRFirst = false;

    VerifyQrcodeDecodePayloadPerProperty(payload_2nd, payload_size_2nd,
                                         kIsaQrcodeDecode_PartRecognized);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_multi3_3rd(void **state)
{
    const char *payload_3rd = "AAIAAAAAAAAAAAAAAAAAAA==N=31;O=8883;U1FS"; // QR3
    size_t payload_size_3rd = strlen(payload_3rd);
    s_qr_total_bit = 0x07; // total num is 3
    s_qr_count_bit = 0x06; // take assumption read N=32 previously
    s_IsQRFirst = false;

    VerifyQrcodeDecodePayloadPerProperty(payload_3rd, payload_size_3rd, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_multi8_1st(void **state)
{
    const char *payload_first =
        "AAIAAAAAAAAAAAAAAAAAAA==N=83;E=example.com;S=WiFiSSID;P=WiFiPassword;U1FS"; // QR1
    size_t payload_size_first = strlen(payload_first);

    VerifyQrcodeDecodePayloadPerProperty(payload_first, payload_size_first,
                                         kIsaQrcodeDecode_PartRecognized);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_multi8_2nd(void **state)
{
    const char *payload_2nd = "AAIAAAAAAAAAAAAAAAAAAA==N=82;H=8883;X=ProxyURL.com;U1FS"; // QR2
    size_t payload_size_2nd = strlen(payload_2nd);
    s_qr_total_bit = 0xFF; // total num is 8
    s_qr_count_bit = 0x04; // take assumption read N=83 previously
    s_IsQRFirst = false;

    VerifyQrcodeDecodePayloadPerProperty(payload_2nd, payload_size_2nd,
                                         kIsaQrcodeDecode_PartRecognized);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_multi8_3rd(void **state)
{
    const char *payload_3rd = "AAIAAAAAAAAAAAAAAAAAAA==N=81;O=8883;U1FS"; // QR3
    size_t payload_size_3rd = strlen(payload_3rd);
    s_qr_total_bit = 0xFF; // total num is 8
    s_qr_count_bit = 0x06; // take assumption read N=82 previously
    s_IsQRFirst = false;

    VerifyQrcodeDecodePayloadPerProperty(payload_3rd, payload_size_3rd,
                                         kIsaQrcodeDecode_PartRecognized);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_multi8_4th(void **state)
{
    const char *payload_4th = "AAIAAAAAAAAAAAAAAAAAAA==N=84;A=ProjectID;U1FS"; // QR4
    size_t payload_size_4th = strlen(payload_4th);
    s_qr_total_bit = 0xFF; // total num is 8
    s_qr_count_bit = 0x07; // take assumption read N=81 previously
    s_IsQRFirst = false;

    VerifyQrcodeDecodePayloadPerProperty(payload_4th, payload_size_4th,
                                         kIsaQrcodeDecode_PartRecognized);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_multi8_5th(void **state)
{
    const char *payload_5th = "AAIAAAAAAAAAAAAAAAAAAA==N=85;B=RegisterToken;U1FS"; // QR5
    size_t payload_size_5th = strlen(payload_5th);
    s_qr_total_bit = 0xFF; // total num is 8
    s_qr_count_bit = 0x0F; // take assumption read N=84 previously
    s_IsQRFirst = false;

    VerifyQrcodeDecodePayloadPerProperty(payload_5th, payload_size_5th,
                                         kIsaQrcodeDecode_PartRecognized);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_multi8_6th(void **state)
{
    const char *payload_6th = "AAIAAAAAAAAAAAAAAAAAAA==N=86;I=192.168.1.2;U1FS"; // QR6
    size_t payload_size_6th = strlen(payload_6th);
    s_qr_total_bit = 0xFF; // total num is 8
    s_qr_count_bit = 0x1F; // take assumption read N=85 previously
    s_IsQRFirst = false;

    VerifyQrcodeDecodePayloadPerProperty(payload_6th, payload_size_6th,
                                         kIsaQrcodeDecode_PartRecognized);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_multi8_7th(void **state)
{
    const char *payload_7th = "AAIAAAAAAAAAAAAAAAAAAA==N=87;K=255.255.255.0;U1FS"; // QR7
    size_t payload_size_7th = strlen(payload_7th);
    s_qr_total_bit = 0xFF; // total num is 8
    s_qr_count_bit = 0x3F; // take assumption read N=86 previously
    s_IsQRFirst = false;

    VerifyQrcodeDecodePayloadPerProperty(payload_7th, payload_size_7th,
                                         kIsaQrcodeDecode_PartRecognized);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_multi8_8th(void **state)
{
    const char *payload_8th = "AAIAAAAAAAAAAAAAAAAAAA==N=88;G=192.168.1.1;D=8.8.8.8;U1FS"; // QR8
    size_t payload_size_8th = strlen(payload_8th);
    s_qr_total_bit = 0xFF; // total num is 8
    s_qr_count_bit = 0x7F; // take assumption read N=87 previously
    s_IsQRFirst = false;

    VerifyQrcodeDecodePayloadPerProperty(payload_8th, payload_size_8th, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_OverTotalNumber(void **state)
{
    const char *payload =
        "AAIAAAAAAAAAAAAAAAAAAA==N=91;E=example.com;S=WiFiSSID;P=WiFiPassword;U1FS";
    size_t payload_size = strlen(payload);

    VerifyQrcodeDecodePayloadPerProperty(payload, payload_size, kIsaQrcodeDecode_Invalid);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_ErrorRetry(void **state)
{
    const char *payload_first =
        "AAIAAAAAAAAAAAAAAAAAAA==N=33;E=example.com;S=WiFiSSID;P=WiFiPassword;U1FS"; // QR1
    size_t payload_size_first = strlen(payload_first);
    const char *payload_2nd_error =
        "AAIAAAAAAAAAAAAAAAAAAA==N=32;H=65536;X=ProxyURL.com;U1FS"; // QR2 Error
    size_t payload_size_2nd_error = strlen(payload_2nd_error);
    const char *payload_2nd = "AAIAAAAAAAAAAAAAAAAAAA==N=32;H=8883;X=ProxyURL.com;U1FS"; // QR2
    size_t payload_size_2nd = strlen(payload_2nd);
    const char *payload_3rd = "AAIAAAAAAAAAAAAAAAAAAA==N=31;O=8883;U1FS"; // QR3
    size_t payload_size_3rd = strlen(payload_3rd);

    VerifyQrcodeDecodePayloadPerProperty(payload_first, payload_size_first,
                                         kIsaQrcodeDecode_PartRecognized);
    VerifyQrcodeDecodePayloadPerProperty(payload_2nd_error, payload_size_2nd_error,
                                         kIsaQrcodeDecode_Invalid);
    IsaClearMultiQRParam();

    VerifyQrcodeDecodePayloadPerProperty(payload_2nd, payload_size_2nd,
                                         kIsaQrcodeDecode_PartRecognized);
    VerifyQrcodeDecodePayloadPerProperty(payload_3rd, payload_size_3rd,
                                         kIsaQrcodeDecode_PartRecognized);
    VerifyQrcodeDecodePayloadPerProperty(payload_first, payload_size_first, kIsaQrcode_Success);

    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeDecodePayload_PartRecognized_Same(void **state)
{
    const char *payload_first =
        "AAIAAAAAAAAAAAAAAAAAAA==N=33;E=example.com;S=WiFiSSID;P=WiFiPassword;U1FS"; // QR1
    size_t payload_size_first = strlen(payload_first);
    const char *payload_2nd = "AAIAAAAAAAAAAAAAAAAAAA==N=32;H=8883;X=ProxyURL.com;U1FS"; // QR2
    size_t payload_size_2nd = strlen(payload_2nd);
    const char *payload_3rd = "AAIAAAAAAAAAAAAAAAAAAA==N=31;O=8883;U1FS"; // QR3
    size_t payload_size_3rd = strlen(payload_3rd);

    VerifyQrcodeDecodePayloadPerProperty(payload_first, payload_size_first,
                                         kIsaQrcodeDecode_PartRecognized);
    VerifyQrcodeDecodePayloadPerProperty(payload_2nd, payload_size_2nd,
                                         kIsaQrcodeDecode_PartRecognized);
    VerifyQrcodeDecodePayloadPerProperty(payload_first, payload_size_first,
                                         kIsaQrcodeDecode_PartRecognized); // Same
    VerifyQrcodeDecodePayloadPerProperty(payload_3rd, payload_size_3rd, kIsaQrcode_Success);

    return;
}

/*----------------------------------------------------------------------------*/

// IsaWriteQrcodePayloadToFlash
//

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_SetEmptyProjectId_failed(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultEmptyData);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_SetEmptyRegisterToken_failed(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultEmptyData);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_EvpHubUrl_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_evphub_url, "example.com",
            sizeof(sp_payload_info->m_evphub_url) - 1);
    sp_payload_info->m_evphub_url[sizeof(sp_payload_info->m_evphub_url) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data, sp_payload_info->m_evphub_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 sizeof(sp_payload_info->m_evphub_url));
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_EvpHubUrl_blank(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_evphub_url, " ", sizeof(sp_payload_info->m_evphub_url) - 1);
    sp_payload_info->m_evphub_url[sizeof(sp_payload_info->m_evphub_url) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data, sp_payload_info->m_evphub_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 sizeof(sp_payload_info->m_evphub_url));
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_EvpHubUrl_SysMgrSet_failed(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_evphub_url, "example.com",
            sizeof(sp_payload_info->m_evphub_url) - 1);
    sp_payload_info->m_evphub_url[sizeof(sp_payload_info->m_evphub_url) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data, sp_payload_info->m_evphub_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 sizeof(sp_payload_info->m_evphub_url));
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultParamError);

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_EvpHubUrl_NwkMgrSave_failed(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_evphub_url, "example.com",
            sizeof(sp_payload_info->m_evphub_url) - 1);
    sp_payload_info->m_evphub_url[sizeof(sp_payload_info->m_evphub_url) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data, sp_payload_info->m_evphub_url);
    expect_value(__wrap_EsfSystemManagerSetEvpHubUrl, data_size,
                 sizeof(sp_payload_info->m_evphub_url));
    will_return(__wrap_EsfSystemManagerSetEvpHubUrl, kEsfSystemManagerResultOk);

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultInvalidParameter);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_EvpHubPort_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_evphub_port, "8883", sizeof(sp_payload_info->m_evphub_port) - 1);
    sp_payload_info->m_evphub_url[sizeof(sp_payload_info->m_evphub_port) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data, sp_payload_info->m_evphub_port);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 sizeof(sp_payload_info->m_evphub_port));
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_EvpHubPort_SysMgrSet_failed(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_evphub_port, "8883", sizeof(sp_payload_info->m_evphub_port) - 1);
    sp_payload_info->m_evphub_url[sizeof(sp_payload_info->m_evphub_port) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data, sp_payload_info->m_evphub_port);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 sizeof(sp_payload_info->m_evphub_port));
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultParamError);

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_EvpHubPort_NwkMgrSave_failed(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_evphub_port, "8883", sizeof(sp_payload_info->m_evphub_port) - 1);
    sp_payload_info->m_evphub_url[sizeof(sp_payload_info->m_evphub_port) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data, sp_payload_info->m_evphub_port);
    expect_value(__wrap_EsfSystemManagerSetEvpHubPort, data_size,
                 sizeof(sp_payload_info->m_evphub_port));
    will_return(__wrap_EsfSystemManagerSetEvpHubPort, kEsfSystemManagerResultOk);

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultInvalidParameter);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_EvpMode_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_evp_mode, "TB", sizeof(sp_payload_info->m_evp_mode) - 1);
    sp_payload_info->m_evp_mode[sizeof(sp_payload_info->m_evp_mode) - 1] = '\0';

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_EvpMQTTInsecure_TlsEnable_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_evp_mqtt_insecure, "0",
            sizeof(sp_payload_info->m_evp_mqtt_insecure));
    sp_payload_info->m_evp_mqtt_insecure[sizeof(sp_payload_info->m_evp_mqtt_insecure) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetEvpTls, data, kEsfSystemManagerEvpTlsEnable);
    will_return(__wrap_EsfSystemManagerSetEvpTls, kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_EvpMQTTInsecure_TlsEnable_SysMgrSet_failed(
    void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_evp_mqtt_insecure, "0",
            sizeof(sp_payload_info->m_evp_mqtt_insecure));
    sp_payload_info->m_evp_mqtt_insecure[sizeof(sp_payload_info->m_evp_mqtt_insecure) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetEvpTls, data, kEsfSystemManagerEvpTlsEnable);
    will_return(__wrap_EsfSystemManagerSetEvpTls, kEsfSystemManagerResultParamError);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_EvpMQTTInsecure_TlsEnable_NwkMgrSave_failed(
    void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_evp_mqtt_insecure, "0",
            sizeof(sp_payload_info->m_evp_mqtt_insecure));
    sp_payload_info->m_evp_mqtt_insecure[sizeof(sp_payload_info->m_evp_mqtt_insecure) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetEvpTls, data, kEsfSystemManagerEvpTlsEnable);
    will_return(__wrap_EsfSystemManagerSetEvpTls, kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultInvalidParameter);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_EvpMQTTInsecure_TlsDisable_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_evp_mqtt_insecure, "1",
            sizeof(sp_payload_info->m_evp_mqtt_insecure));
    sp_payload_info->m_evp_mqtt_insecure[sizeof(sp_payload_info->m_evp_mqtt_insecure) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetEvpTls, data, kEsfSystemManagerEvpTlsDisable);
    will_return(__wrap_EsfSystemManagerSetEvpTls, kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_EvpMQTTInsecure_TlsDisable_SysMgrSet_failed(
    void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_evp_mqtt_insecure, "1",
            sizeof(sp_payload_info->m_evp_mqtt_insecure));
    sp_payload_info->m_evp_mqtt_insecure[sizeof(sp_payload_info->m_evp_mqtt_insecure) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetEvpTls, data, kEsfSystemManagerEvpTlsDisable);
    will_return(__wrap_EsfSystemManagerSetEvpTls, kEsfSystemManagerResultParamError);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_EvpMQTTInsecure_TlsDisable_NwkMgrSave_failed(
    void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_evp_mqtt_insecure, "1",
            sizeof(sp_payload_info->m_evp_mqtt_insecure));
    sp_payload_info->m_evp_mqtt_insecure[sizeof(sp_payload_info->m_evp_mqtt_insecure) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetEvpTls, data, kEsfSystemManagerEvpTlsDisable);
    will_return(__wrap_EsfSystemManagerSetEvpTls, kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultInvalidParameter);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_ProjectId_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_project_id, "ProjectId", sizeof(sp_payload_info->m_project_id) - 1);
    sp_payload_info->m_project_id[sizeof(sp_payload_info->m_project_id) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetProjectId, data, sp_payload_info->m_project_id);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size,
                 sizeof(sp_payload_info->m_project_id));
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_ProjectId_SysMgrSet_failed(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_project_id, "ProjectId", sizeof(sp_payload_info->m_project_id) - 1);
    sp_payload_info->m_project_id[sizeof(sp_payload_info->m_project_id) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetProjectId, data, sp_payload_info->m_project_id);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size,
                 sizeof(sp_payload_info->m_project_id));
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultParamError);

    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_ProjectId_NwkMgrSave_failed(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_project_id, "ProjectId", sizeof(sp_payload_info->m_project_id) - 1);
    sp_payload_info->m_project_id[sizeof(sp_payload_info->m_project_id) - 1] = '\0';

    expect_value(__wrap_EsfSystemManagerSetProjectId, data, sp_payload_info->m_project_id);
    expect_value(__wrap_EsfSystemManagerSetProjectId, data_size,
                 sizeof(sp_payload_info->m_project_id));
    will_return(__wrap_EsfSystemManagerSetProjectId, kEsfSystemManagerResultOk);

    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultInvalidParameter);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_RegisterToken_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_register_token, "RegisterToken",
            sizeof(sp_payload_info->m_register_token) - 1);
    sp_payload_info->m_register_token[sizeof(sp_payload_info->m_register_token) - 1] = '\0';

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);

    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data, sp_payload_info->m_register_token);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size,
                 sizeof(sp_payload_info->m_register_token));
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_RegisterToken_SysMgrSet_failed(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_register_token, "RegisterToken",
            sizeof(sp_payload_info->m_register_token) - 1);
    sp_payload_info->m_register_token[sizeof(sp_payload_info->m_register_token) - 1] = '\0';

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);

    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data, sp_payload_info->m_register_token);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size,
                 sizeof(sp_payload_info->m_register_token));
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultParamError);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_RegisterToken_NwkMgrSave_failed(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    strncpy(sp_payload_info->m_register_token, "RegisterToken",
            sizeof(sp_payload_info->m_register_token) - 1);
    sp_payload_info->m_register_token[sizeof(sp_payload_info->m_register_token) - 1] = '\0';

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);

    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data, sp_payload_info->m_register_token);
    expect_value(__wrap_EsfSystemManagerSetRegisterToken, data_size,
                 sizeof(sp_payload_info->m_register_token));
    will_return(__wrap_EsfSystemManagerSetRegisterToken, kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultInvalidParameter);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_WiFiSSID_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_wifi_ssid, "WiFiSSID", sizeof(sp_payload_info->m_wifi_ssid) - 1);
    sp_payload_info->m_wifi_ssid[sizeof(sp_payload_info->m_wifi_ssid) - 1] = '\0';

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, sp_payload_info->m_wifi_ssid,
           sizeof(sp_payload_info->m_wifi_ssid));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_WiFiSSID_empty_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_wifi_ssid, " ", sizeof(sp_payload_info->m_wifi_ssid) - 1);
    sp_payload_info->m_wifi_ssid[sizeof(sp_payload_info->m_wifi_ssid) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_WiFiPass_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_wifi_pass, "WiFiPass", sizeof(sp_payload_info->m_wifi_pass) - 1);
    sp_payload_info->m_wifi_pass[sizeof(sp_payload_info->m_wifi_pass) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, sp_payload_info->m_wifi_pass,
           sizeof(sp_payload_info->m_wifi_pass));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_ProxyURL_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_proxy_url, "example.proxy.com",
            sizeof(sp_payload_info->m_proxy_url) - 1);
    sp_payload_info->m_proxy_url[sizeof(sp_payload_info->m_proxy_url) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, sp_payload_info->m_proxy_url,
           sizeof(sp_payload_info->m_proxy_url));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_ProxyURL_blank(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_proxy_url, " ", sizeof(sp_payload_info->m_proxy_url) - 1);
    sp_payload_info->m_proxy_url[sizeof(sp_payload_info->m_proxy_url) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, sp_payload_info->m_proxy_url,
           sizeof(sp_payload_info->m_proxy_url));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_ProxyPort_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_proxy_port, "10080", sizeof(sp_payload_info->m_proxy_port));
    sp_payload_info->m_proxy_port[sizeof(sp_payload_info->m_proxy_port) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_param.proxy.port = 10080;
    expected_esfnm_mask.proxy.port = 1;

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_ProxyURLPort(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_proxy_url, "example.proxy.com",
            sizeof(sp_payload_info->m_proxy_url) - 1);
    sp_payload_info->m_proxy_url[sizeof(sp_payload_info->m_proxy_url) - 1] = '\0';

    strncpy(sp_payload_info->m_proxy_port, "10080", sizeof(sp_payload_info->m_proxy_port));
    sp_payload_info->m_proxy_port[sizeof(sp_payload_info->m_proxy_port) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, sp_payload_info->m_proxy_url,
           sizeof(sp_payload_info->m_proxy_url));
    expected_esfnm_param.proxy.port = 10080;
    expected_esfnm_mask.proxy.port = 1;

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_ProxyPort_illegal_below_minimum(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_proxy_port, "-1", sizeof(sp_payload_info->m_proxy_port) - 1);
    sp_payload_info->m_proxy_port[sizeof(sp_payload_info->m_proxy_port) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.proxy.port = 0;

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_ProxyPort_illegal_exceed_maximum(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_proxy_port, "65536", sizeof(sp_payload_info->m_proxy_port));
    sp_payload_info->m_proxy_port[sizeof(sp_payload_info->m_proxy_port) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.proxy.port = 0;

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_ProxyUser_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_proxy_user, "ProxyUser", sizeof(sp_payload_info->m_proxy_user) - 1);
    sp_payload_info->m_proxy_user[sizeof(sp_payload_info->m_proxy_user) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, sp_payload_info->m_proxy_user,
           sizeof(sp_payload_info->m_proxy_user));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_ProxyPass_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_proxy_pass, "ProxyPass", sizeof(sp_payload_info->m_proxy_pass) - 1);
    sp_payload_info->m_proxy_pass[sizeof(sp_payload_info->m_proxy_pass) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, sp_payload_info->m_proxy_pass,
           sizeof(sp_payload_info->m_proxy_pass));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_StaticIP_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_static_ip, "192.168.1.2", sizeof(sp_payload_info->m_static_ip) - 1);
    sp_payload_info->m_static_ip[sizeof(sp_payload_info->m_static_ip) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, sp_payload_info->m_static_ip,
           sizeof(sp_payload_info->m_static_ip));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_StaticIPv6_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_static_ip_v6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            sizeof(sp_payload_info->m_static_ip_v6));
    sp_payload_info->m_static_ip_v6[sizeof(sp_payload_info->m_static_ip_v6) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, sp_payload_info->m_static_ip_v6,
           sizeof(sp_payload_info->m_static_ip_v6));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_StaticSubnetMask_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_static_subnetmask, "255.255.255.0",
            sizeof(sp_payload_info->m_static_subnetmask) - 1);
    sp_payload_info->m_static_subnetmask[sizeof(sp_payload_info->m_static_subnetmask) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.dev_ip.subnet_mask = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.subnet_mask,
           sp_payload_info->m_static_subnetmask, sizeof(sp_payload_info->m_static_subnetmask));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_StaticSubnetMaskv6_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_static_subnetmask_v6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            sizeof(sp_payload_info->m_static_subnetmask_v6));
    sp_payload_info->m_static_subnetmask_v6[sizeof(sp_payload_info->m_static_subnetmask_v6) - 1] =
        '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.dev_ip_v6.subnet_mask = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.subnet_mask,
           sp_payload_info->m_static_subnetmask_v6,
           sizeof(sp_payload_info->m_static_subnetmask_v6));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_StaticGateway_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_static_gateway, "192.168.1.1",
            sizeof(sp_payload_info->m_static_gateway) - 1);
    sp_payload_info->m_static_gateway[sizeof(sp_payload_info->m_static_gateway) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.dev_ip.gateway = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.gateway, sp_payload_info->m_static_gateway,
           sizeof(sp_payload_info->m_static_gateway));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_StaticGatewayv6_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_static_gateway_v6, "fe80::1",
            sizeof(sp_payload_info->m_static_gateway_v6) - 1);
    sp_payload_info->m_static_gateway_v6[sizeof(sp_payload_info->m_static_gateway_v6) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.dev_ip_v6.gateway = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.gateway, sp_payload_info->m_static_gateway_v6,
           sizeof(sp_payload_info->m_static_gateway_v6));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_StaticDNS_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_static_dns, "8.8.8.8", sizeof(sp_payload_info->m_static_dns) - 1);
    sp_payload_info->m_static_dns[sizeof(sp_payload_info->m_static_dns) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.dev_ip.dns = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.dns, sp_payload_info->m_static_dns,
           sizeof(sp_payload_info->m_static_dns));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_StaticDNSv6_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_static_dns_v6, "2001:4860:4860::8888",
            sizeof(sp_payload_info->m_static_dns_v6) - 1);
    sp_payload_info->m_static_dns_v6[sizeof(sp_payload_info->m_static_dns_v6) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));
    expected_esfnm_mask.normal_mode.dev_ip_v6.dns = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.dns, sp_payload_info->m_static_dns_v6,
           sizeof(sp_payload_info->m_static_dns_v6));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_IPMethodv4_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Save Network Parameter for ip,subnetmask,gateway,dns
    strncpy(sp_payload_info->m_static_ip, "192.168.1.2", sizeof(sp_payload_info->m_static_ip) - 1);
    sp_payload_info->m_static_ip[sizeof(sp_payload_info->m_static_ip) - 1] = '\0';
    strncpy(sp_payload_info->m_static_subnetmask, "255.255.255.0",
            sizeof(sp_payload_info->m_static_subnetmask) - 1);
    sp_payload_info->m_static_subnetmask[sizeof(sp_payload_info->m_static_subnetmask) - 1] = '\0';
    strncpy(sp_payload_info->m_static_gateway, "192.168.1.1",
            sizeof(sp_payload_info->m_static_gateway) - 1);
    sp_payload_info->m_static_gateway[sizeof(sp_payload_info->m_static_gateway) - 1] = '\0';
    strncpy(sp_payload_info->m_static_dns, "8.8.8.8", sizeof(sp_payload_info->m_static_dns) - 1);
    sp_payload_info->m_static_dns[sizeof(sp_payload_info->m_static_dns) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    // Save Network Parameter for ip_method
    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, sp_payload_info->m_static_ip,
           sizeof(sp_payload_info->m_static_ip));
    expected_esfnm_mask.normal_mode.dev_ip.subnet_mask = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.subnet_mask,
           sp_payload_info->m_static_subnetmask, sizeof(sp_payload_info->m_static_subnetmask));
    expected_esfnm_mask.normal_mode.dev_ip.gateway = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.gateway, sp_payload_info->m_static_gateway,
           sizeof(sp_payload_info->m_static_gateway));
    expected_esfnm_mask.normal_mode.dev_ip.dns = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.dns, sp_payload_info->m_static_dns,
           sizeof(sp_payload_info->m_static_dns));

    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;
    expected_esfnm_param.normal_mode.ip_method = 1;
    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_IPMethodv4_NwkMgrSave_failed(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Save Network Parameter for ip,subnetmask,gateway,dns
    strncpy(sp_payload_info->m_static_ip, "192.168.1.2", sizeof(sp_payload_info->m_static_ip) - 1);
    sp_payload_info->m_static_ip[sizeof(sp_payload_info->m_static_ip) - 1] = '\0';
    strncpy(sp_payload_info->m_static_subnetmask, "255.255.255.0",
            sizeof(sp_payload_info->m_static_subnetmask) - 1);
    sp_payload_info->m_static_subnetmask[sizeof(sp_payload_info->m_static_subnetmask) - 1] = '\0';
    strncpy(sp_payload_info->m_static_gateway, "192.168.1.1",
            sizeof(sp_payload_info->m_static_gateway) - 1);
    sp_payload_info->m_static_gateway[sizeof(sp_payload_info->m_static_gateway) - 1] = '\0';
    strncpy(sp_payload_info->m_static_dns, "8.8.8.8", sizeof(sp_payload_info->m_static_dns) - 1);
    sp_payload_info->m_static_dns[sizeof(sp_payload_info->m_static_dns) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    // Save Network Parameter for ip_method
    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, sp_payload_info->m_static_ip,
           sizeof(sp_payload_info->m_static_ip));
    expected_esfnm_mask.normal_mode.dev_ip.subnet_mask = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.subnet_mask,
           sp_payload_info->m_static_subnetmask, sizeof(sp_payload_info->m_static_subnetmask));
    expected_esfnm_mask.normal_mode.dev_ip.gateway = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.gateway, sp_payload_info->m_static_gateway,
           sizeof(sp_payload_info->m_static_gateway));
    expected_esfnm_mask.normal_mode.dev_ip.dns = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.dns, sp_payload_info->m_static_dns,
           sizeof(sp_payload_info->m_static_dns));

    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;
    expected_esfnm_param.normal_mode.ip_method = 1;
    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultInvalidParameter);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_IPMethodv4_Not_specified_gateway(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Save Network Parameter for ip,subnetmask,dns
    strncpy(sp_payload_info->m_static_ip, "192.168.1.2", sizeof(sp_payload_info->m_static_ip) - 1);
    sp_payload_info->m_static_ip[sizeof(sp_payload_info->m_static_ip) - 1] = '\0';
    strncpy(sp_payload_info->m_static_subnetmask, "255.255.255.0",
            sizeof(sp_payload_info->m_static_subnetmask) - 1);
    sp_payload_info->m_static_subnetmask[sizeof(sp_payload_info->m_static_subnetmask) - 1] = '\0';
    strncpy(sp_payload_info->m_static_dns, "8.8.8.8", sizeof(sp_payload_info->m_static_dns) - 1);
    sp_payload_info->m_static_dns[sizeof(sp_payload_info->m_static_dns) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    // Save Network Parameter (ip_method = 0)
    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, sp_payload_info->m_static_ip,
           sizeof(sp_payload_info->m_static_ip));
    expected_esfnm_mask.normal_mode.dev_ip.subnet_mask = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.subnet_mask,
           sp_payload_info->m_static_subnetmask, sizeof(sp_payload_info->m_static_subnetmask));
    expected_esfnm_mask.normal_mode.dev_ip.gateway = 0; // gateway is not specified
    expected_esfnm_mask.normal_mode.dev_ip.dns = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.dns, sp_payload_info->m_static_dns,
           sizeof(sp_payload_info->m_static_dns));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_IPMethodv4_Not_specified_dns(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Save Network Parameter for ip,subnetmask,gateway
    strncpy(sp_payload_info->m_static_ip, "192.168.1.2", sizeof(sp_payload_info->m_static_ip) - 1);
    sp_payload_info->m_static_ip[sizeof(sp_payload_info->m_static_ip) - 1] = '\0';
    strncpy(sp_payload_info->m_static_subnetmask, "255.255.255.0",
            sizeof(sp_payload_info->m_static_subnetmask) - 1);
    sp_payload_info->m_static_subnetmask[sizeof(sp_payload_info->m_static_subnetmask) - 1] = '\0';
    strncpy(sp_payload_info->m_static_gateway, "192.168.1.1",
            sizeof(sp_payload_info->m_static_gateway) - 1);
    sp_payload_info->m_static_gateway[sizeof(sp_payload_info->m_static_gateway) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    // Save Network Parameter (ip_method = 0)
    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, sp_payload_info->m_static_ip,
           sizeof(sp_payload_info->m_static_ip));
    expected_esfnm_mask.normal_mode.dev_ip.subnet_mask = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.subnet_mask,
           sp_payload_info->m_static_subnetmask, sizeof(sp_payload_info->m_static_subnetmask));
    expected_esfnm_mask.normal_mode.dev_ip.gateway = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.gateway, sp_payload_info->m_static_gateway,
           sizeof(sp_payload_info->m_static_gateway));
    expected_esfnm_mask.normal_mode.dev_ip.dns = 0; // dns is not specified

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_StaticNTP_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;
    EsfClockManagerParamsMask expected_cm_mask;
    EsfClockManagerParams expected_cm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_static_ntp, "pool.ntp.org",
            sizeof(sp_payload_info->m_static_ntp) - 1);
    sp_payload_info->m_static_ntp[sizeof(sp_payload_info->m_static_ntp) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Initialize & set ClockManager parameter
    memset(&expected_cm_mask, 0, sizeof(EsfClockManagerParamsMask));
    memset(&expected_cm_param, 0, sizeof(EsfClockManagerParams));
    expected_cm_mask.connect.hostname = 1;
    memcpy(expected_cm_param.connect.hostname, sp_payload_info->m_static_ntp,
           sizeof(sp_payload_info->m_static_ntp));

    CheckEsfClockManagerSetParamsForcibly(&expected_cm_param, &expected_cm_mask,
                                          kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_StaticNTP_NwkMgrSave_failed(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;
    EsfClockManagerParamsMask expected_cm_mask;
    EsfClockManagerParams expected_cm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_static_ntp, "pool.ntp.org",
            sizeof(sp_payload_info->m_static_ntp) - 1);
    sp_payload_info->m_static_ntp[sizeof(sp_payload_info->m_static_ntp) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Initialize & set ClockManager parameter
    memset(&expected_cm_mask, 0, sizeof(EsfClockManagerParamsMask));
    memset(&expected_cm_param, 0, sizeof(EsfClockManagerParams));
    expected_cm_mask.connect.hostname = 1;
    memcpy(expected_cm_param.connect.hostname, sp_payload_info->m_static_ntp,
           sizeof(sp_payload_info->m_static_ntp));

    CheckEsfClockManagerSetParamsForcibly(&expected_cm_param, &expected_cm_mask,
                                          kClockManagerParamError);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_StaticNTP_empty_NwkMgrSave_failed(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;
    EsfClockManagerParamsMask expected_cm_mask;
    EsfClockManagerParams expected_cm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    strncpy(sp_payload_info->m_static_ntp, "\0", sizeof(sp_payload_info->m_static_ntp));

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    // Initialize & set ClockManager parameter
    memset(&expected_cm_mask, 0, sizeof(EsfClockManagerParamsMask));
    memset(&expected_cm_param, 0, sizeof(EsfClockManagerParams));
    expected_cm_mask.connect.hostname = 1;
    memcpy(expected_cm_param.connect.hostname, sp_payload_info->m_static_ntp,
           sizeof(sp_payload_info->m_static_ntp));

    CheckEsfClockManagerSetParamsForcibly(&expected_cm_param, &expected_cm_mask,
                                          kClockManagerParamError);

    expect_value(__wrap_SysAppLedSetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedSetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);
    expect_value(__wrap_SysAppLedUnsetAppStatus, type, LedTypePower);
    expect_value(__wrap_SysAppLedUnsetAppStatus, app_state, LedAppStatusErrorDataFlashFailed);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_IPMethodv6_success(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Save Network Parameter for ip,subnetmask,gateway,dns
    strncpy(sp_payload_info->m_static_ip_v6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            sizeof(sp_payload_info->m_static_ip_v6));
    sp_payload_info->m_static_ip_v6[sizeof(sp_payload_info->m_static_ip_v6) - 1] = '\0';
    strncpy(sp_payload_info->m_static_subnetmask_v6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            sizeof(sp_payload_info->m_static_subnetmask_v6));
    sp_payload_info->m_static_subnetmask_v6[sizeof(sp_payload_info->m_static_subnetmask_v6) - 1] =
        '\0';
    strncpy(sp_payload_info->m_static_gateway_v6, "fe80::1",
            sizeof(sp_payload_info->m_static_gateway_v6) - 1);
    sp_payload_info->m_static_gateway_v6[sizeof(sp_payload_info->m_static_gateway_v6) - 1] = '\0';
    strncpy(sp_payload_info->m_static_dns_v6, "2001:4860:4860::8888",
            sizeof(sp_payload_info->m_static_dns_v6) - 1);
    sp_payload_info->m_static_dns_v6[sizeof(sp_payload_info->m_static_dns_v6) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    // Save Network Parameter for ip_method
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, sp_payload_info->m_static_ip_v6,
           sizeof(sp_payload_info->m_static_ip_v6));
    expected_esfnm_mask.normal_mode.dev_ip_v6.subnet_mask = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.subnet_mask,
           sp_payload_info->m_static_subnetmask_v6, sizeof(sp_payload_info->m_static_subnetmask));
    expected_esfnm_mask.normal_mode.dev_ip_v6.gateway = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.gateway, sp_payload_info->m_static_gateway_v6,
           sizeof(sp_payload_info->m_static_gateway));
    expected_esfnm_mask.normal_mode.dev_ip_v6.dns = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.dns, sp_payload_info->m_static_dns_v6,
           sizeof(sp_payload_info->m_static_dns));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;
    expected_esfnm_param.normal_mode.ip_method = 0;
    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_IPMethodv6_blank(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Save Network Parameter for ip,subnetmask,gateway,dns
    strncpy(sp_payload_info->m_static_ip_v6, " ", sizeof(sp_payload_info->m_static_ip_v6));
    sp_payload_info->m_static_ip_v6[sizeof(sp_payload_info->m_static_ip_v6) - 1] = '\0';
    strncpy(sp_payload_info->m_static_subnetmask_v6, " ",
            sizeof(sp_payload_info->m_static_subnetmask_v6));
    sp_payload_info->m_static_subnetmask_v6[sizeof(sp_payload_info->m_static_subnetmask_v6) - 1] =
        '\0';
    strncpy(sp_payload_info->m_static_gateway_v6, " ",
            sizeof(sp_payload_info->m_static_gateway_v6) - 1);
    sp_payload_info->m_static_gateway_v6[sizeof(sp_payload_info->m_static_gateway_v6) - 1] = '\0';
    strncpy(sp_payload_info->m_static_dns_v6, " ", sizeof(sp_payload_info->m_static_dns_v6) - 1);
    sp_payload_info->m_static_dns_v6[sizeof(sp_payload_info->m_static_dns_v6) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    // Save Network Parameter for ip_method
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.subnet_mask = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.subnet_mask, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.gateway = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.gateway, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.dns = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.dns, "", 1);

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;
    expected_esfnm_param.normal_mode.ip_method = 0;
    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_All_empty(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_IPMethodv4_Not_specified_ip_str(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Save Network Parameter for ip,subnetmask,gateway,dns
    strncpy(sp_payload_info->m_static_ip, " ", sizeof(sp_payload_info->m_static_ip) - 1);
    sp_payload_info->m_static_ip[sizeof(sp_payload_info->m_static_ip) - 1] = '\0';
    strncpy(sp_payload_info->m_static_subnetmask, "1",
            sizeof(sp_payload_info->m_static_subnetmask) - 1);
    sp_payload_info->m_static_subnetmask[sizeof(sp_payload_info->m_static_subnetmask) - 1] = '\0';
    strncpy(sp_payload_info->m_static_gateway, "1", sizeof(sp_payload_info->m_static_gateway) - 1);
    sp_payload_info->m_static_gateway[sizeof(sp_payload_info->m_static_gateway) - 1] = '\0';
    strncpy(sp_payload_info->m_static_dns, "1", sizeof(sp_payload_info->m_static_dns) - 1);
    sp_payload_info->m_static_dns[sizeof(sp_payload_info->m_static_dns) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.subnet_mask = 1;
    expected_esfnm_mask.normal_mode.dev_ip.gateway = 1;
    expected_esfnm_mask.normal_mode.dev_ip.dns = 1;

    memcpy(expected_esfnm_param.normal_mode.dev_ip.subnet_mask,
           sp_payload_info->m_static_subnetmask, sizeof(sp_payload_info->m_static_subnetmask));
    memcpy(expected_esfnm_param.normal_mode.dev_ip.gateway, sp_payload_info->m_static_gateway,
           sizeof(sp_payload_info->m_static_gateway));
    memcpy(expected_esfnm_param.normal_mode.dev_ip.dns, sp_payload_info->m_static_dns,
           sizeof(sp_payload_info->m_static_dns));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;
    expected_esfnm_param.normal_mode.ip_method = 0;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_IPMethodv4_Not_specified_subnetmask_str(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Save Network Parameter for ip,subnetmask,gateway,dns
    strncpy(sp_payload_info->m_static_ip, "1", sizeof(sp_payload_info->m_static_ip) - 1);
    sp_payload_info->m_static_ip[sizeof(sp_payload_info->m_static_ip) - 1] = '\0';
    strncpy(sp_payload_info->m_static_subnetmask, " ",
            sizeof(sp_payload_info->m_static_subnetmask) - 1);
    sp_payload_info->m_static_subnetmask[sizeof(sp_payload_info->m_static_subnetmask) - 1] = '\0';
    strncpy(sp_payload_info->m_static_gateway, "1", sizeof(sp_payload_info->m_static_gateway) - 1);
    sp_payload_info->m_static_gateway[sizeof(sp_payload_info->m_static_gateway) - 1] = '\0';
    strncpy(sp_payload_info->m_static_dns, "1", sizeof(sp_payload_info->m_static_dns) - 1);
    sp_payload_info->m_static_dns[sizeof(sp_payload_info->m_static_dns) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.subnet_mask = 1;
    expected_esfnm_mask.normal_mode.dev_ip.gateway = 1;
    expected_esfnm_mask.normal_mode.dev_ip.dns = 1;

    memcpy(expected_esfnm_param.normal_mode.dev_ip.gateway, sp_payload_info->m_static_gateway,
           sizeof(sp_payload_info->m_static_gateway));
    memcpy(expected_esfnm_param.normal_mode.dev_ip.dns, sp_payload_info->m_static_dns,
           sizeof(sp_payload_info->m_static_dns));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;
    expected_esfnm_param.normal_mode.ip_method = 0;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_IPMethodv4_Not_specified_gateway_str(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Save Network Parameter for ip,subnetmask,gateway,dns
    strncpy(sp_payload_info->m_static_ip, "1", sizeof(sp_payload_info->m_static_ip) - 1);
    sp_payload_info->m_static_ip[sizeof(sp_payload_info->m_static_ip) - 1] = '\0';
    strncpy(sp_payload_info->m_static_subnetmask, "1",
            sizeof(sp_payload_info->m_static_subnetmask) - 1);
    sp_payload_info->m_static_subnetmask[sizeof(sp_payload_info->m_static_subnetmask) - 1] = '\0';
    strncpy(sp_payload_info->m_static_gateway, " ", sizeof(sp_payload_info->m_static_gateway) - 1);
    sp_payload_info->m_static_gateway[sizeof(sp_payload_info->m_static_gateway) - 1] = '\0';
    strncpy(sp_payload_info->m_static_dns, "1", sizeof(sp_payload_info->m_static_dns) - 1);
    sp_payload_info->m_static_dns[sizeof(sp_payload_info->m_static_dns) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.subnet_mask = 1;
    expected_esfnm_mask.normal_mode.dev_ip.gateway = 1;
    expected_esfnm_mask.normal_mode.dev_ip.dns = 1;

    memcpy(expected_esfnm_param.normal_mode.dev_ip.subnet_mask,
           sp_payload_info->m_static_subnetmask, sizeof(sp_payload_info->m_static_subnetmask));
    memcpy(expected_esfnm_param.normal_mode.dev_ip.dns, sp_payload_info->m_static_dns,
           sizeof(sp_payload_info->m_static_dns));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;
    expected_esfnm_param.normal_mode.ip_method = 0;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_IPMethodv4_Not_specified_dns_str(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Save Network Parameter for ip,subnetmask,gateway,dns
    strncpy(sp_payload_info->m_static_ip, "1", sizeof(sp_payload_info->m_static_ip) - 1);
    sp_payload_info->m_static_ip[sizeof(sp_payload_info->m_static_ip) - 1] = '\0';
    strncpy(sp_payload_info->m_static_subnetmask, "1",
            sizeof(sp_payload_info->m_static_subnetmask) - 1);
    sp_payload_info->m_static_subnetmask[sizeof(sp_payload_info->m_static_subnetmask) - 1] = '\0';
    strncpy(sp_payload_info->m_static_gateway, "1", sizeof(sp_payload_info->m_static_gateway) - 1);
    sp_payload_info->m_static_gateway[sizeof(sp_payload_info->m_static_gateway) - 1] = '\0';
    strncpy(sp_payload_info->m_static_dns, " ", sizeof(sp_payload_info->m_static_dns) - 1);
    sp_payload_info->m_static_dns[sizeof(sp_payload_info->m_static_dns) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    expected_esfnm_mask.normal_mode.dev_ip.subnet_mask = 1;
    expected_esfnm_mask.normal_mode.dev_ip.gateway = 1;
    expected_esfnm_mask.normal_mode.dev_ip.dns = 1;

    memcpy(expected_esfnm_param.normal_mode.dev_ip.subnet_mask,
           sp_payload_info->m_static_subnetmask, sizeof(sp_payload_info->m_static_subnetmask));
    memcpy(expected_esfnm_param.normal_mode.dev_ip.gateway, sp_payload_info->m_static_gateway,
           sizeof(sp_payload_info->m_static_gateway));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;
    expected_esfnm_param.normal_mode.ip_method = 0;

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_IPMethodv6_Not_specified_ip_str(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Save Network Parameter for ip,subnetmask,gateway,dns
    strncpy(sp_payload_info->m_static_ip_v6, " ", sizeof(sp_payload_info->m_static_ip_v6));
    sp_payload_info->m_static_ip_v6[sizeof(sp_payload_info->m_static_ip_v6) - 1] = '\0';
    strncpy(sp_payload_info->m_static_subnetmask_v6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            sizeof(sp_payload_info->m_static_subnetmask_v6));
    sp_payload_info->m_static_subnetmask_v6[sizeof(sp_payload_info->m_static_subnetmask_v6) - 1] =
        '\0';
    strncpy(sp_payload_info->m_static_gateway_v6, "fe80::1",
            sizeof(sp_payload_info->m_static_gateway_v6) - 1);
    sp_payload_info->m_static_gateway_v6[sizeof(sp_payload_info->m_static_gateway_v6) - 1] = '\0';
    strncpy(sp_payload_info->m_static_dns_v6, "2001:4860:4860::8888",
            sizeof(sp_payload_info->m_static_dns_v6) - 1);
    sp_payload_info->m_static_dns_v6[sizeof(sp_payload_info->m_static_dns_v6) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    // Save Network Parameter for ip_method
    expected_esfnm_mask.normal_mode.dev_ip_v6.subnet_mask = 1;
    expected_esfnm_mask.normal_mode.dev_ip_v6.gateway = 1;
    expected_esfnm_mask.normal_mode.dev_ip_v6.dns = 1;

    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.subnet_mask,
           sp_payload_info->m_static_subnetmask_v6,
           sizeof(sp_payload_info->m_static_subnetmask_v6));
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.gateway, sp_payload_info->m_static_gateway_v6,
           sizeof(sp_payload_info->m_static_gateway_v6));
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.dns, sp_payload_info->m_static_dns_v6,
           sizeof(sp_payload_info->m_static_dns_v6));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;
    expected_esfnm_param.normal_mode.ip_method = 0;
    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_IPMethodv6_Not_specified_subnetmask_str(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Save Network Parameter for ip,subnetmask,gateway,dns
    strncpy(sp_payload_info->m_static_ip_v6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            sizeof(sp_payload_info->m_static_ip_v6));
    sp_payload_info->m_static_ip_v6[sizeof(sp_payload_info->m_static_ip_v6) - 1] = '\0';
    strncpy(sp_payload_info->m_static_subnetmask_v6, " ",
            sizeof(sp_payload_info->m_static_subnetmask_v6));
    sp_payload_info->m_static_subnetmask_v6[sizeof(sp_payload_info->m_static_subnetmask_v6) - 1] =
        '\0';
    strncpy(sp_payload_info->m_static_gateway_v6, "fe80::1",
            sizeof(sp_payload_info->m_static_gateway_v6) - 1);
    sp_payload_info->m_static_gateway_v6[sizeof(sp_payload_info->m_static_gateway_v6) - 1] = '\0';
    strncpy(sp_payload_info->m_static_dns_v6, "2001:4860:4860::8888",
            sizeof(sp_payload_info->m_static_dns_v6) - 1);
    sp_payload_info->m_static_dns_v6[sizeof(sp_payload_info->m_static_dns_v6) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    // Save Network Parameter for ip_method

    expected_esfnm_mask.normal_mode.dev_ip_v6.subnet_mask = 1;
    expected_esfnm_mask.normal_mode.dev_ip_v6.gateway = 1;
    expected_esfnm_mask.normal_mode.dev_ip_v6.dns = 1;

    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.gateway, sp_payload_info->m_static_gateway_v6,
           sizeof(sp_payload_info->m_static_gateway_v6));
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.dns, sp_payload_info->m_static_dns_v6,
           sizeof(sp_payload_info->m_static_dns_v6));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;
    expected_esfnm_param.normal_mode.ip_method = 0;
    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_IPMethodv6_Not_specified_gateway_str(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Save Network Parameter for ip,subnetmask,gateway,dns
    strncpy(sp_payload_info->m_static_ip_v6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            sizeof(sp_payload_info->m_static_ip_v6));
    sp_payload_info->m_static_ip_v6[sizeof(sp_payload_info->m_static_ip_v6) - 1] = '\0';
    strncpy(sp_payload_info->m_static_subnetmask_v6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            sizeof(sp_payload_info->m_static_subnetmask_v6));
    sp_payload_info->m_static_subnetmask_v6[sizeof(sp_payload_info->m_static_subnetmask_v6) - 1] =
        '\0';
    strncpy(sp_payload_info->m_static_gateway_v6, " ",
            sizeof(sp_payload_info->m_static_gateway_v6) - 1);
    sp_payload_info->m_static_gateway_v6[sizeof(sp_payload_info->m_static_gateway_v6) - 1] = '\0';
    strncpy(sp_payload_info->m_static_dns_v6, "2001:4860:4860::8888",
            sizeof(sp_payload_info->m_static_dns_v6) - 1);
    sp_payload_info->m_static_dns_v6[sizeof(sp_payload_info->m_static_dns_v6) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    // Save Network Parameter for ip_method
    expected_esfnm_mask.normal_mode.dev_ip_v6.subnet_mask = 1;
    expected_esfnm_mask.normal_mode.dev_ip_v6.gateway = 1;
    expected_esfnm_mask.normal_mode.dev_ip_v6.dns = 1;

    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.subnet_mask,
           sp_payload_info->m_static_subnetmask_v6,
           sizeof(sp_payload_info->m_static_subnetmask_v6));
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.dns, sp_payload_info->m_static_dns_v6,
           sizeof(sp_payload_info->m_static_dns_v6));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;
    expected_esfnm_param.normal_mode.ip_method = 0;
    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaWriteQrcodePayloadToFlash_IPMethodv6_Not_specified_dns_str(void **state)
{
    IsaQrcodeErrorCode ret;
    EsfNetworkManagerParameterMask expected_esfnm_mask;
    EsfNetworkManagerParameter expected_esfnm_param;

    SetEmptyToEsfSystemManagerSetProjectId(kEsfSystemManagerResultOk);
    SetEmptyToEsfSystemManagerSetRegisterToken(kEsfSystemManagerResultOk);

    // Save Network Parameter for ip,subnetmask,gateway,dns
    strncpy(sp_payload_info->m_static_ip_v6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            sizeof(sp_payload_info->m_static_ip_v6));
    sp_payload_info->m_static_ip_v6[sizeof(sp_payload_info->m_static_ip_v6) - 1] = '\0';
    strncpy(sp_payload_info->m_static_subnetmask_v6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            sizeof(sp_payload_info->m_static_subnetmask_v6));
    sp_payload_info->m_static_subnetmask_v6[sizeof(sp_payload_info->m_static_subnetmask_v6) - 1] =
        '\0';
    strncpy(sp_payload_info->m_static_gateway_v6, "fe80::1",
            sizeof(sp_payload_info->m_static_gateway_v6) - 1);
    sp_payload_info->m_static_gateway_v6[sizeof(sp_payload_info->m_static_gateway_v6) - 1] = '\0';
    strncpy(sp_payload_info->m_static_dns_v6, " ", sizeof(sp_payload_info->m_static_dns_v6) - 1);
    sp_payload_info->m_static_dns_v6[sizeof(sp_payload_info->m_static_dns_v6) - 1] = '\0';

    // Initialize & set NetworkManager parameter
    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    memset(&expected_esfnm_param, 0, sizeof(EsfNetworkManagerParameter));

    // Save Network Parameter for ip_method
    expected_esfnm_mask.normal_mode.dev_ip_v6.subnet_mask = 1;
    expected_esfnm_mask.normal_mode.dev_ip_v6.gateway = 1;
    expected_esfnm_mask.normal_mode.dev_ip_v6.dns = 1;

    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.subnet_mask,
           sp_payload_info->m_static_subnetmask_v6,
           sizeof(sp_payload_info->m_static_subnetmask_v6));
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.gateway, sp_payload_info->m_static_gateway_v6,
           sizeof(sp_payload_info->m_static_gateway_v6));

    expected_esfnm_mask.normal_mode.dev_ip.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip.ip, "", 1);
    expected_esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    memcpy(expected_esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.ssid = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    expected_esfnm_mask.normal_mode.wifi_sta.password = 1;
    memcpy(expected_esfnm_param.normal_mode.wifi_sta.password, "", 1);
    expected_esfnm_mask.proxy.url = 1;
    memcpy(expected_esfnm_param.proxy.url, "", 1);
    expected_esfnm_mask.proxy.port = 1;
    expected_esfnm_param.proxy.port = 0;
    expected_esfnm_mask.proxy.username = 1;
    memcpy(expected_esfnm_param.proxy.username, "", 1);
    expected_esfnm_mask.proxy.password = 1;
    memcpy(expected_esfnm_param.proxy.password, "", 1);

    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    memset(&expected_esfnm_mask, 0, sizeof(EsfNetworkManagerParameterMask));
    expected_esfnm_mask.normal_mode.ip_method = 1;
    expected_esfnm_param.normal_mode.ip_method = 0;
    CheckEsfNetworkManagerSaveParameter(&expected_esfnm_mask, &expected_esfnm_param,
                                        kEsfNetworkManagerResultSuccess);

    expect_value(__wrap_EsfClockManagerSetParamsForcibly, mask->connect.hostname, 1);
    expect_string(__wrap_EsfClockManagerSetParamsForcibly, data->connect.hostname, "");
    will_return(__wrap_EsfClockManagerSetParamsForcibly, kClockManagerSuccess);

    ret = IsaWriteQrcodePayloadToFlash();

    assert_int_equal(ret, kIsaQrcode_Success);
    return;
}

/*----------------------------------------------------------------------------*/
//
// IsaClearMultiQRParam()
//

/*----------------------------------------------------------------------------*/
static void test_IsaClearMultiQRParam_success(void **state)
{
    s_qr_total_bit = 0xFF;
    s_qr_count_bit = 0xFF;
    s_IsQRFirst = false;

    IsaClearMultiQRParam();

    assert_int_equal(s_qr_total_bit, 0);
    assert_int_equal(s_qr_count_bit, 0);
    assert_true(s_IsQRFirst);
    return;
}

/*----------------------------------------------------------------------------*/
//
// IsaQrcodeExit()
//

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeExit_success(void **state)
{
    IsaQrcodeErrorCode ret;

    IsaQrcodePayloadInfo *allocated_ptr = sp_payload_info;
    expect_value(mock_free, __ptr, allocated_ptr);
    will_return(mock_free, true); // Check Parameter

    ret = IsaQrcodeExit();

    assert_int_equal(ret, kIsaQrcode_Success);
    assert_null(sp_payload_info);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsaQrcodeExit_malloc_failure(void **state)
{
    IsaQrcodeErrorCode ret;
    sp_payload_info = NULL;

    ret = IsaQrcodeExit();

    assert_int_equal(ret, kIsaQrcode_Success);
    assert_null(sp_payload_info);
    return;
}

/*----------------------------------------------------------------------------*/

//
// IsValidCommonUrl()
//

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_blank(void **state)
{
    bool ret;
    char *url = " ";

    ret = IsValidCommonUrl(url, 256);

    assert_int_equal(ret, true);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_ErrorUrlLength2(void **state)
{
    char *url = "ab";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, false);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_ErrorUrlLength254(void **state)
{
    char *url =
        "o123456789abcde.o123456789abcde.o123456789abcde.o123456789abcde."
        "o123456789abcde.o123456789abcde.o123456789abcde.o123456789abcde."
        "o123456789abcde.o123456789abcde.o123456789abcde.o123456789abcde."
        "o123456789abcde.o123456789abcde.o123456789abcde.o1234567abc.jp";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, false);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_SuccessMinLength1(void **state)
{
    char *url = "p.n.org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, true);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_SuccessMaxLength63(void **state)
{
    char *url = "p.L2345678901234567890L2345678901234567890L2345678901234567890123.org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, true);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_ErrorMinLength0(void **state)
{
    char *url = "p..org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, false);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_ErrorMaxLength64(void **state)
{
    char *url = "p.L2345678901234567890L2345678901234567890L23456789012345678901234.org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, false);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_Success1stCharAlpha(void **state)
{
    char *url = "pool.ntp.org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, true);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_Success1stCharDigit(void **state)
{
    char *url = "pool.1tp.org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, true);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_Error1stCharHyphen(void **state)
{
    char *url = "pool.-tp.org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, false);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_SuccessLastCharAlpha(void **state)
{
    char *url = "pool.ntp.org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, true);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_SuccessLastCharDigit(void **state)
{
    char *url = "pool.nt0.org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, true);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_ErrorLastCharHyphen(void **state)
{
    char *url = "pool.nt-.org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, false);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_SuccessMidCharAlpha(void **state)
{
    char *url = "pool.ntp.org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, true);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_SuccessMidCharDigit(void **state)
{
    char *url = "pool.n5p.org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, true);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_SuccessMidCharHyphen(void **state)
{
    char *url = "pool.n5p.org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, true);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_ErrorMidCharOther(void **state)
{
    char *url = "pool.n_p.org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, false);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_ErrorDotCount(void **state)
{
    char *url = "pool-ntp-org";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, false);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_ErrorTldLength(void **state)
{
    char *url = "pool.ntp.o";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, false);
    return;
}

/*----------------------------------------------------------------------------*/
static void test_IsValidCommonUrl_ErrorInvalidIPv4(void **state)
{
    char *url = "777.888.999.000";
    bool ret = IsValidCommonUrl(url, 256);
    assert_int_equal(ret, false);
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
        // IsaQrcodeInit()
        cmocka_unit_test_setup_teardown(test_IsaQrcodeInit_success, NULL, teardown),
        cmocka_unit_test(test_IsaQrcodeInit_malloc_failure),

        // IsaQrcodeDecodePayload()
        cmocka_unit_test(test_IsaQrcodeDecodePayload_invalid_payload),
        cmocka_unit_test(test_IsaQrcodeDecodePayload_invalid_payload_size),
        cmocka_unit_test(test_IsaQrcodeDecodePayload_invalid_result),
        cmocka_unit_test(test_IsaQrcodeDecodePayload_invalid_magic_header),
        cmocka_unit_test(test_IsaQrcodeDecodePayload_b64decode_failed),
        cmocka_unit_test(test_IsaQrcodeDecodePayload_invalid_qrcode_format_version),
        cmocka_unit_test(test_IsaQrcodeDecodePayload_invalid_qrcode_format_option),
        cmocka_unit_test(test_IsaQrcodeDecodePayload_qr_data_malloc_failure),

        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_invalid_qr_property, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_QRIndex_null, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_empty, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_EVPHubURL_only, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_EVPHubURL_Invalid,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_EVPHubURL_IP, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_EVPHubURL_InvalidIP,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_EVPHubURL_IPv6, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_EVPHubURL_blank, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_EVPHubPort_only, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_EVPHubPort_Invalid_low,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaQrcodeDecodePayload_UserData_EVPHubPort_Invalid_high, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_EVPHubPort_low, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_EVPHubPort_high, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_EVPHubURLPort, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_EVPHubURLPortWifiSSID,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_WifiSSID_blank, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaQrcodeDecodePayload_UserData_EVPHubURLPortWifiPassword, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_WifiPassword_blank,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_RequiredFields, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_RequiredFields_noE,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_RequiredFields_noH,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_RequiredFields_noS,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_RequiredFields_noP,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaQrcodeDecodePayload_UserData_EVPMqttInsecure_TLSOnly, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaQrcodeDecodePayload_UserData_EVPMqttInsecure_TLSEnable, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaQrcodeDecodePayload_UserData_EVPMqttInsecure_TLSDisable, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_EVPMqttInsecure_blank,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaQrcodeDecodePayload_UserData_invalid_EVPMqttInsecure, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_EVPMode, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaQrcodeDecodePayload_UserData_ProjectID_RegisterTokenOnly, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaQrcodeDecodePayload_UserData_ProjectID_RegisterToken, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaQrcodeDecodePayload_UserData_ProjectID_RegisterToken_blank, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaQrcodeDecodePayload_UserData_ProjectID_RegisterToken_Oversize, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProjectID_only, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_RegisterToken_only,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_WiFiSSID_only, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_WiFiSSID_Oversize,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_WiFiPassword_only,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_WiFiPassword_Oversize,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyURL_only, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyURL, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyURL_invalid,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyURL_IPv4, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyURL_invalidIPv4,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyURL_IPv6, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyURL_blank, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyURL_empty, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyPort_only, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyPort, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyPort_low, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyPort_high, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyPort_low_invalid,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyPort_high_invalid,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyURLPort, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyURLPort_blank,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyUserName_only,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyUserName, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyUserName_Oversize,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyPassword_only,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyPassword, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_ProxyPassword_Oversize,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_IPAddress, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_IPAddress_invalid,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_IPAddress_blank, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_IPAddress_v6, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_IPAddress_v6_invalid,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_IPAddress_v6_blank,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_SubnetMask, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_SubnetMask_invalid,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_SubnetMask_blank,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_SubnetMask_v6, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_SubnetMask_v6_invalid,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_SubnetMask_v6_blank,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_Gateway, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_Gateway_invalid, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_Gateway_blank, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_Gateway_v6, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_Gateway_v6_invalid,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_Gateway_v6_blank,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_DNS, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_DNS_invalid, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_DNS_blank, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_DNS_v6, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_DNS_v6_invalid, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_DNS_v6_blank, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_StaticIP, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_NTP_only, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_NTP, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_NTP_invalid, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_NTP_IP, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_NTP_IP_invalid, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_NTP_blank, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_undefined_property,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_all_empty, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_invalid_QrPayload,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_escape_slash, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_UserData_escape_semicolon,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_Halfway, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_2nd, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_Required, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_Required_2nd,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_multi3_1st,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_multi3_2nd,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_multi3_3rd,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_multi8_1st,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_multi8_2nd,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_multi8_3rd,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_multi8_4th,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_multi8_5th,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_multi8_6th,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_multi8_7th,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_multi8_8th,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_OverTotalNumber, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_ErrorRetry,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaQrcodeDecodePayload_PartRecognized_Same, setup,
                                        teardown),

        // IsaWriteQrcodePayloadToFlash()
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_SetEmptyProjectId_failed,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_SetEmptyRegisterToken_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_EvpHubUrl_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_EvpHubUrl_blank, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_EvpHubUrl_SysMgrSet_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_EvpHubUrl_NwkMgrSave_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_EvpHubPort_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_EvpHubPort_SysMgrSet_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_EvpHubPort_NwkMgrSave_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_EvpMode_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_EvpMQTTInsecure_TlsEnable_success, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_EvpMQTTInsecure_TlsEnable_SysMgrSet_failed, setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_EvpMQTTInsecure_TlsEnable_NwkMgrSave_failed, setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_EvpMQTTInsecure_TlsDisable_success, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_EvpMQTTInsecure_TlsDisable_SysMgrSet_failed, setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_EvpMQTTInsecure_TlsDisable_NwkMgrSave_failed, setup,
            teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_ProjectId_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_ProjectId_SysMgrSet_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_ProjectId_NwkMgrSave_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_RegisterToken_success,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_RegisterToken_SysMgrSet_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_RegisterToken_NwkMgrSave_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_WiFiSSID_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_WiFiSSID_empty_success,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_WiFiPass_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_ProxyURL_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_ProxyURL_blank, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_ProxyPort_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_ProxyURLPort, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_ProxyPort_illegal_below_minimum, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_ProxyPort_illegal_exceed_maximum, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_ProxyUser_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_ProxyPass_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_StaticIP_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_StaticIPv6_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_StaticSubnetMask_success,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_StaticSubnetMaskv6_success, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_StaticGateway_success,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_StaticGatewayv6_success,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_StaticDNS_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_StaticDNSv6_success,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_IPMethodv4_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_IPMethodv4_NwkMgrSave_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_IPMethodv4_Not_specified_gateway, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_IPMethodv4_Not_specified_dns, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_StaticNTP_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_StaticNTP_NwkMgrSave_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_StaticNTP_empty_NwkMgrSave_failed, setup, teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_IPMethodv6_success, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_IPMethodv6_blank, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(test_IsaWriteQrcodePayloadToFlash_All_empty, setup,
                                        teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_IPMethodv4_Not_specified_ip_str, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_IPMethodv4_Not_specified_subnetmask_str, setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_IPMethodv4_Not_specified_gateway_str, setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_IPMethodv4_Not_specified_dns_str, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_IPMethodv6_Not_specified_ip_str, setup, teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_IPMethodv6_Not_specified_subnetmask_str, setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_IPMethodv6_Not_specified_gateway_str, setup,
            teardown),
        cmocka_unit_test_setup_teardown(
            test_IsaWriteQrcodePayloadToFlash_IPMethodv6_Not_specified_dns_str, setup, teardown),

        // IsaClearMultiQRParam()
        cmocka_unit_test_setup_teardown(test_IsaClearMultiQRParam_success, setup, NULL),

        // IsaQrcodeExit()
        cmocka_unit_test_setup_teardown(test_IsaQrcodeExit_success, setup, NULL),
        cmocka_unit_test(test_IsaQrcodeExit_malloc_failure),

        // IsaQrcodeExit()
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_blank, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_ErrorUrlLength2, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_ErrorUrlLength254, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_SuccessMinLength1, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_SuccessMaxLength63, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_ErrorMinLength0, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_ErrorMaxLength64, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_Success1stCharAlpha, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_Success1stCharDigit, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_Error1stCharHyphen, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_SuccessLastCharAlpha, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_SuccessLastCharDigit, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_ErrorLastCharHyphen, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_SuccessMidCharAlpha, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_SuccessMidCharDigit, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_SuccessMidCharHyphen, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_ErrorMidCharOther, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_ErrorDotCount, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_ErrorTldLength, setup, NULL),
        cmocka_unit_test_setup_teardown(test_IsValidCommonUrl_ErrorInvalidIPv4, setup, NULL),

    };

    return (((cmocka_run_group_tests(tests, NULL, NULL)) == 0) ? 0 : 1);
}
