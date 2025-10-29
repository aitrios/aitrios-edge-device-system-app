/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "network_manager.h"
#include "clock_manager.h"
#include "clock_manager_setting.h"
#include "system_manager.h"
#include "initial_setting_app_qrcode.h"
#include "initial_setting_app_log.h"
#include "system_app_led.h"
#include "initial_setting_app_qrcode_private.h"
#include "initial_setting_app_util.h"
#include "base64/include/base64.h"

STATIC IsaQrcodePayloadInfo *sp_payload_info = NULL;
STATIC uint8_t s_qr_total_bit = 0x00;
STATIC uint8_t s_qr_count_bit = 0x00;
STATIC bool s_IsQRFirst = true;

/* PlainText format is {0x00, 0x02}. */
static const uint8_t sc_qr_version_plain[QRVersion_LEN] = {0x00, 0x02};

/* plainText format option */
static const uint8_t sc_qr_option_plain[Option_LEN] = {
    0x00, /* ServiceQRCode(0) or DeviceQRCode(1) */
    0x00, /* Not supported. */
    0x00, /* Not supported. */
    0x00, /* Not supported. */
    0x00, /* Not supported. */
    0x00  /* Not supported. */
};

/* Base64 encoded magic number "SQR". */
static const uint8_t sc_qr_magic_number_b64[MagicNumber_STRINGLEN] = {'U', '1', 'F', 'S'};

static char *ParseQrPayloadIndex(char *p_tok, char *p_prop, uint16_t maxsize);
static IsaQrcodeDecodeResult SetQrInfo(char *p_input, uint8_t *p_qr_count);
static void WrapCopyData(char *dst, char *src, uint32_t max_data_size);
static bool IsValidDomain(const char *domain, int max_len);
STATIC bool IsValidEvpHubUrl(const char *domain);
STATIC bool IsValidCommonUrl(const char *domain, int max_len);
static IpVer CheckIpAddressType(const char *ip_string);

IsaQrcodeErrorCode IsaQrcodeInit(void)
{
    IsaQrcodeErrorCode ret = kIsaQrcode_Failed;

    do {
        /* malloc */

        sp_payload_info = (IsaQrcodePayloadInfo *)malloc(sizeof(IsaQrcodePayloadInfo));

        if (sp_payload_info == NULL) {
            ISA_CRIT("sp_payload_info malloc failed. size=%zu", sizeof(IsaQrcodePayloadInfo));
            break;
        }

        memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));

        ret = kIsaQrcode_Success;
    } while (0);

    if (ret == kIsaQrcode_Failed) {
        IsaQrcodeExit();
    }

    return ret;
}

IsaQrcodeErrorCode IsaQrcodeDecodePayload(uint8_t *payload, int32_t payload_size,
                                          IsaQrcodeDecodeResult *result, uint8_t *qr_count)
{
    IsaQrcodeErrorCode ret = kIsaQrcode_Success;

    /*
   * QR Code Payload fomat is below. 
   * Header-b64-encoded string (24 characters)
   * + UserData
   * + MagicNumber (always "U1FS")
   * 
   * Header = Version  (2 Byte) 
   *          + Option (6 Byte)
   *          + SIerID (8 Byte)
   * SIerID is all 0
   * 
   * sample : AAIAAAAAAAAAAAAAAAAAAA==N=11;E=aaa;H=bbb;U1FS
   *          <---Header b64string---><----UserData---><-->
   */

    do {
        /* NULL Check */

        if (payload == NULL || result == NULL) {
            ret = kIsaQrcode_InvalidArgument;
            break;
        }

        *result = kIsaQrcodeDecode_ResultNum;

        /* Payload size Check */

        if (payload_size <= HEADER_STRINGLEN) {
            ISA_ERR("Invalid QR Code format. no header");
            *result = kIsaQrcodeDecode_Invalid;
            break;
        }

        /* Check MagicNumber. "SQR" (= "U1FS") */

        if (memcmp(payload + payload_size - sizeof(sc_qr_magic_number_b64), sc_qr_magic_number_b64,
                   sizeof(sc_qr_magic_number_b64)) != 0) {
            ISA_ERR("Invalid QR Code format. magic number");
            *result = kIsaQrcodeDecode_Invalid;
            break;
        }

        /* Decode Header */

        uint8_t header_encoded[HEADER_STRINGLEN];
        uint8_t header_decoded[HEADER_LEN_BUFFER];
        size_t out_size = sizeof(header_decoded);

        memcpy(header_encoded, payload, HEADER_STRINGLEN);
        memset(header_decoded, 0, sizeof(header_decoded));

        EsfCodecBase64ResultEnum ret_b64codec = kEsfCodecBase64ResultSuccess;

        ret_b64codec = EsfCodecBase64Decode((const char *)header_encoded, sizeof(header_encoded),
                                            header_decoded, &out_size);

        if (ret_b64codec != kEsfCodecBase64ResultSuccess) {
            ISA_ERR("EsfCodecBase64Decode(%d)", ret_b64codec);
            *result = kIsaQrcodeDecode_Invalid;
            break;
        }

        if (memcmp(header_decoded, sc_qr_version_plain, QRVersion_LEN) != 0) {
            ISA_ERR("Invalid QR Code format. version");
            *result = kIsaQrcodeDecode_Invalid;
            break;
        }

        /* PlainText format supports only the first byte. */

        if (memcmp(header_decoded + QRVersion_LEN, sc_qr_option_plain, 1) != 0) {
            ISA_ERR("Invalid QR Code format. option");
            *result = kIsaQrcodeDecode_Invalid;
            break;
        }

        size_t qr_input_size = payload_size - HEADER_STRINGLEN - MagicNumber_STRINGLEN;
        char *p_qr_data_plain = (char *)malloc(qr_input_size + 1); /* +1 for '\0' */

        if (!p_qr_data_plain) {
            ISA_ERR("malloc() failed");
            ret = kIsaQrcode_Failed;
            break;
        }

        memset(p_qr_data_plain, 0, qr_input_size + 1); /* +1 for '\0' */
        memcpy(p_qr_data_plain, payload + HEADER_STRINGLEN, qr_input_size);

        char *end = strrchr(p_qr_data_plain, ';');

        if (end == NULL) {
            ISA_ERR("Invalid QR Property");
            free(p_qr_data_plain);
            p_qr_data_plain = NULL;
            *result = kIsaQrcodeDecode_Invalid;
            break;
        }

        // Note : The string passed to SetQrInfo() must contain at least one ";".
        //        Also, the last character must be ";".

        p_qr_data_plain[end - p_qr_data_plain + 1] = '\0';
        ISA_DBG("p_qr_data_plain : %s", p_qr_data_plain);

        /* Set QR Info to be written to Flash */

        *result = SetQrInfo(p_qr_data_plain, qr_count);

        free(p_qr_data_plain);
        p_qr_data_plain = NULL;
    } while (0);

    return ret;
}

/*----------------------------------------------------------------------*/
IsaQrcodeErrorCode IsaWriteQrcodePayloadToFlash(void)
{
    IsaQrcodeErrorCode ret = kIsaQrcode_Success;
    bool is_flash_write_error = false;

    /* Write EVP data to flash */

    EsfSystemManagerResult esfsm_ret;

    /* EVP Hub URL */

    if (*sp_payload_info->m_evphub_url != '\0') {
        ISA_DBG("evphub url = %s", sp_payload_info->m_evphub_url);

        char *endpoint_url = (char *)sp_payload_info->m_evphub_url;
        esfsm_ret = EsfSystemManagerSetEvpHubUrl(endpoint_url,
                                                 sizeof(sp_payload_info->m_evphub_url));
        if (esfsm_ret != kEsfSystemManagerResultOk) {
            ISA_ERR("EsfSystemManagerSetEvpHubUrl failed %d", esfsm_ret);
            is_flash_write_error = true;
        }
    }

    /* EVP Port */

    if (*sp_payload_info->m_evphub_port != '\0') {
        ISA_DBG("evphub port = %s", sp_payload_info->m_evphub_port);

        char *endpoint_port = (char *)sp_payload_info->m_evphub_port;
        esfsm_ret = EsfSystemManagerSetEvpHubPort(endpoint_port,
                                                  sizeof(sp_payload_info->m_evphub_port));
        if (esfsm_ret != kEsfSystemManagerResultOk) {
            ISA_ERR("EsfSystemManagerSetEvpHubPort failed %d", esfsm_ret);
            is_flash_write_error = true;
        }
    }

    /* EVP Mode */

    if (*sp_payload_info->m_evp_mode != '\0') {
        ISA_DBG("evp mode = %s", sp_payload_info->m_evp_mode);
        /* TBD. Not defined in ESF */
    }

    /* EVP MQTT TLS */

    if (*sp_payload_info->m_evp_mqtt_insecure != '\0') {
        ISA_DBG("evp mqtt insecure = %s", sp_payload_info->m_evp_mqtt_insecure);

        int mqtt_insecure = 0; // Enable
        EsfSystemManagerEvpTlsValue esfmqtt_insecure = kEsfSystemManagerEvpTlsEnable;
        mqtt_insecure = atoi(sp_payload_info->m_evp_mqtt_insecure);

        if (mqtt_insecure == 0) {
            esfmqtt_insecure = kEsfSystemManagerEvpTlsEnable;
        }
        else {
            esfmqtt_insecure = kEsfSystemManagerEvpTlsDisable;
        }

        esfsm_ret = EsfSystemManagerSetEvpTls(esfmqtt_insecure);
        if (esfsm_ret != kEsfSystemManagerResultOk) {
            ISA_ERR("EsfSystemManagerSetEvpTls failed %d", esfsm_ret);
            is_flash_write_error = true;
        }
    }

    /* Project ID */

    if (*sp_payload_info->m_project_id != '\0') {
        ISA_DBG("project id = %s", sp_payload_info->m_project_id);

        char *project_id = (char *)sp_payload_info->m_project_id;
        esfsm_ret = EsfSystemManagerSetProjectId(project_id, sizeof(sp_payload_info->m_project_id));
        if (esfsm_ret != kEsfSystemManagerResultOk) {
            ISA_ERR("EsfSystemManagerSetProjectId failed %d", esfsm_ret);
            is_flash_write_error = true;
        }
    }
    else {
        esfsm_ret = EsfSystemManagerSetProjectId("", 1);
        if (esfsm_ret != kEsfSystemManagerResultOk) {
            ISA_ERR("EsfSystemManagerSetProjectId failed %d", esfsm_ret);
            is_flash_write_error = true;
        }
    }

    /* Register Token */

    if (*sp_payload_info->m_register_token != '\0') {
        ISA_DBG("register token = %s", sp_payload_info->m_register_token);

        char *register_token = (char *)sp_payload_info->m_register_token;
        esfsm_ret = EsfSystemManagerSetRegisterToken(register_token,
                                                     sizeof(sp_payload_info->m_register_token));
        if (esfsm_ret != kEsfSystemManagerResultOk) {
            ISA_ERR("EsfSystemManagerSetRegisterToken failed %d", esfsm_ret);
            is_flash_write_error = true;
        }
    }
    else {
        esfsm_ret = EsfSystemManagerSetRegisterToken("", 1);
        if (esfsm_ret != kEsfSystemManagerResultOk) {
            ISA_ERR("EsfSystemManagerSetRegisterToken failed %d", esfsm_ret);
            is_flash_write_error = true;
        }
    }

    /* Write Network data to flash */

    EsfNetworkManagerParameterMask esfnm_mask = {0};
    EsfNetworkManagerParameter esfnm_param = {0};

    /* WiFi SSID */

    if (*sp_payload_info->m_wifi_ssid != '\0') {
        ISA_DBG("wifi ssid = %s", sp_payload_info->m_wifi_ssid);

        esfnm_mask.normal_mode.wifi_sta.ssid = 1;
        WrapCopyData(esfnm_param.normal_mode.wifi_sta.ssid, sp_payload_info->m_wifi_ssid,
                     sizeof(sp_payload_info->m_wifi_ssid));
    }
    else {
        /* Delete Wifi SSID */
        esfnm_mask.normal_mode.wifi_sta.ssid = 1;
        memcpy(esfnm_param.normal_mode.wifi_sta.ssid, "", 1);
    }

    /* WiFi Password */

    if (*sp_payload_info->m_wifi_pass != '\0') {
        ISA_DBG("wifi pass = %s", sp_payload_info->m_wifi_pass);

        esfnm_mask.normal_mode.wifi_sta.password = 1;
        WrapCopyData(esfnm_param.normal_mode.wifi_sta.password, sp_payload_info->m_wifi_pass,
                     sizeof(sp_payload_info->m_wifi_pass));
    }
    else {
        /* Delete Wifi Password */
        esfnm_mask.normal_mode.wifi_sta.password = 1;
        memcpy(esfnm_param.normal_mode.wifi_sta.password, "", 1);
    }

    bool exist_proxy_url = false;
    bool exist_proxy_port = false;

    /* Proxy URL */

    if (*sp_payload_info->m_proxy_url != '\0') {
        ISA_DBG("proxy url = %s", sp_payload_info->m_proxy_url);

        esfnm_mask.proxy.url = 1;

        /* Exist Proxy URL */
        /* Blank Space means "Delete Proxy URL" */
        if (*sp_payload_info->m_proxy_url != ' ') {
            exist_proxy_url = true;
        }

        WrapCopyData(esfnm_param.proxy.url, sp_payload_info->m_proxy_url,
                     sizeof(sp_payload_info->m_proxy_url));
    }
    else {
        esfnm_mask.proxy.url = 0;
    }

    /* Proxy Port */

    if (*sp_payload_info->m_proxy_port != '\0') {
        ISA_DBG("proxy port = %s", sp_payload_info->m_proxy_port);

        int proxy_port = 0;
        proxy_port = atoi(sp_payload_info->m_proxy_port);

        if ((proxy_port >= 0) && (proxy_port <= 65535)) {
            esfnm_param.proxy.port = proxy_port;
            esfnm_mask.proxy.port = 1;
            exist_proxy_port = true;
        }
        else {
            ISA_ERR("Invalid Proxy Port %d", proxy_port);
            esfnm_mask.proxy.port = 0;
        }
    }
    else {
        esfnm_mask.proxy.port = 0;
    }

    /* Proxy User Name */

    if (*sp_payload_info->m_proxy_user != '\0') {
        ISA_DBG("proxy user = %s", sp_payload_info->m_proxy_user);

        esfnm_mask.proxy.username = 1;
        WrapCopyData(esfnm_param.proxy.username, sp_payload_info->m_proxy_user,
                     sizeof(sp_payload_info->m_proxy_user));
    }
    else {
        esfnm_mask.proxy.username = 0;
    }

    /* Proxy Password */

    if (*sp_payload_info->m_proxy_pass != '\0') {
        ISA_DBG("proxy pass = %s", sp_payload_info->m_proxy_pass);

        esfnm_mask.proxy.password = 1;
        WrapCopyData(esfnm_param.proxy.password, sp_payload_info->m_proxy_pass,
                     sizeof(sp_payload_info->m_proxy_pass));
    }
    else {
        esfnm_mask.proxy.password = 0;
    }

    // Delete Proxy setting not to exist Proxy URL or Proxy Port
    if (!exist_proxy_url || !exist_proxy_port) {
        /* Clear Proxy Setting */
        memcpy(esfnm_param.proxy.url, "", 1);
        esfnm_param.proxy.port = 0;
        memcpy(esfnm_param.proxy.username, "", 1);
        memcpy(esfnm_param.proxy.password, "", 1);

        esfnm_mask.proxy.url = 1;
        esfnm_mask.proxy.port = 1;
        esfnm_mask.proxy.username = 1;
        esfnm_mask.proxy.password = 1;
    }

    bool exist_ip = false;
    bool exist_ip_v6 = false;
    bool exist_subnet = false;
    bool exist_subnet_v6 = false;
    bool exist_gateway = false;
    bool exist_gateway_v6 = false;
    bool exist_dns = false;
    bool exist_dns_v6 = false;

    /* IP Address */

    if (*sp_payload_info->m_static_ip != '\0') {
        ISA_DBG("static ip = %s", sp_payload_info->m_static_ip);

        /* Exist IP Address */
        /* Blank Space means "Delete IP Address" */
        if (*sp_payload_info->m_static_ip != ' ') {
            exist_ip = true;
        }

        esfnm_mask.normal_mode.dev_ip.ip = 1;
        WrapCopyData(esfnm_param.normal_mode.dev_ip.ip, sp_payload_info->m_static_ip,
                     sizeof(sp_payload_info->m_static_ip));
    }
    else {
        esfnm_mask.normal_mode.dev_ip.ip = 0;
    }

    /* IP Address IPv6 */

    if (*sp_payload_info->m_static_ip_v6 != '\0') {
        ISA_DBG("static ip for v6 = %s", sp_payload_info->m_static_ip_v6);

        /* Exist IPv6 Address */
        /* Blank Space means "Delete IPv6 Address" */
        if (*sp_payload_info->m_static_ip_v6 != ' ') {
            exist_ip_v6 = true;
        }

        esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
        WrapCopyData(esfnm_param.normal_mode.dev_ip_v6.ip, sp_payload_info->m_static_ip_v6,
                     sizeof(sp_payload_info->m_static_ip_v6));
    }
    else {
        esfnm_mask.normal_mode.dev_ip_v6.ip = 0;
    }

    /* Subnet Mask */

    if (*sp_payload_info->m_static_subnetmask != '\0') {
        ISA_DBG("static subnetmask = %s", sp_payload_info->m_static_subnetmask);

        /* Exist Subnet Mask */
        /* Blank Space means "Delete Subnet Mask" */
        if (*sp_payload_info->m_static_subnetmask != ' ') {
            exist_subnet = true;
        }

        esfnm_mask.normal_mode.dev_ip.subnet_mask = 1;
        WrapCopyData(esfnm_param.normal_mode.dev_ip.subnet_mask,
                     sp_payload_info->m_static_subnetmask,
                     sizeof(sp_payload_info->m_static_subnetmask));
    }
    else {
        esfnm_mask.normal_mode.dev_ip.subnet_mask = 0;
    }

    /* Subnet Mask IPv6 */

    if (*sp_payload_info->m_static_subnetmask_v6 != '\0') {
        ISA_DBG("static subnetmask for v6 = %s", sp_payload_info->m_static_subnetmask_v6);

        /* Exist Subnet Mask IPv6 */
        /* Blank Space means "Delete Subnet Mask IPv6" */
        if (*sp_payload_info->m_static_subnetmask_v6 != ' ') {
            exist_subnet_v6 = true;
        }

        esfnm_mask.normal_mode.dev_ip_v6.subnet_mask = 1;
        WrapCopyData(esfnm_param.normal_mode.dev_ip_v6.subnet_mask,
                     sp_payload_info->m_static_subnetmask_v6,
                     sizeof(sp_payload_info->m_static_subnetmask_v6));
    }
    else {
        esfnm_mask.normal_mode.dev_ip_v6.subnet_mask = 0;
    }

    /* Gateway */

    if (*sp_payload_info->m_static_gateway != '\0') {
        ISA_DBG("static gateway = %s", sp_payload_info->m_static_gateway);

        /* Exist Gateway */
        /* Blank Space means "Delete Gateway" */
        if (*sp_payload_info->m_static_gateway != ' ') {
            exist_gateway = true;
        }

        esfnm_mask.normal_mode.dev_ip.gateway = 1;
        WrapCopyData(esfnm_param.normal_mode.dev_ip.gateway, sp_payload_info->m_static_gateway,
                     sizeof(sp_payload_info->m_static_gateway));
    }
    else {
        esfnm_mask.normal_mode.dev_ip.gateway = 0;
    }

    /* Gateway IPv6 */

    if (*sp_payload_info->m_static_gateway_v6 != '\0') {
        ISA_DBG("static gateway for v6 = %s", sp_payload_info->m_static_gateway_v6);

        /* Exist Gateway IPv6 */
        /* Blank Space means "Delete Gateway IPv6" */
        if (*sp_payload_info->m_static_gateway_v6 != ' ') {
            exist_gateway_v6 = true;
        }

        esfnm_mask.normal_mode.dev_ip_v6.gateway = 1;
        WrapCopyData(esfnm_param.normal_mode.dev_ip_v6.gateway,
                     sp_payload_info->m_static_gateway_v6,
                     sizeof(sp_payload_info->m_static_gateway_v6));
    }
    else {
        esfnm_mask.normal_mode.dev_ip_v6.gateway = 0;
    }

    /* DNS */

    if (*sp_payload_info->m_static_dns != '\0') {
        ISA_DBG("static dns = %s", sp_payload_info->m_static_dns);

        /* Exist DNS */
        /* Blank Space means "Delete DNS" */
        if (*sp_payload_info->m_static_dns != ' ') {
            exist_dns = true;
        }

        esfnm_mask.normal_mode.dev_ip.dns = 1;
        WrapCopyData(esfnm_param.normal_mode.dev_ip.dns, sp_payload_info->m_static_dns,
                     sizeof(sp_payload_info->m_static_dns));
    }
    else {
        esfnm_mask.normal_mode.dev_ip.dns = 0;
    }

    /* DNS IPv6 */

    if (*sp_payload_info->m_static_dns_v6 != '\0') {
        ISA_DBG("static gateway for v6 = %s", sp_payload_info->m_static_dns_v6);

        /* Exist DNS IPv6 */
        /* Blank Space means "Delete DNS IPv6" */
        if (*sp_payload_info->m_static_dns_v6 != ' ') {
            exist_dns_v6 = true;
        }

        esfnm_mask.normal_mode.dev_ip_v6.dns = 1;
        WrapCopyData(esfnm_param.normal_mode.dev_ip_v6.dns, sp_payload_info->m_static_dns_v6,
                     sizeof(sp_payload_info->m_static_dns_v6));
    }
    else {
        esfnm_mask.normal_mode.dev_ip_v6.dns = 0;
    }

    bool enable_static_ip = false;
    bool enable_static_ip_v6 = false;

    /* Check if static ip is enable. */
    if (exist_ip && exist_subnet && exist_gateway && exist_dns) {
        enable_static_ip = true;
    }
    else {
        /* Delete ip address setting. */
        memcpy(esfnm_param.normal_mode.dev_ip.ip, "", 1);
        esfnm_mask.normal_mode.dev_ip.ip = 1;
    }

    /* Check if static ip(IPv6) is enable. */
    if (exist_ip_v6 && exist_subnet_v6 && exist_gateway_v6 && exist_dns_v6) {
        enable_static_ip_v6 = true;
    }
    else {
        /* Delete ip address IPv6 setting. */
        memcpy(esfnm_param.normal_mode.dev_ip_v6.ip, "", 1);
        esfnm_mask.normal_mode.dev_ip_v6.ip = 1;
    }

    EsfNetworkManagerResult esfnm_ret = EsfNetworkManagerSaveParameter(&esfnm_mask, &esfnm_param);
    if (esfnm_ret != kEsfNetworkManagerResultSuccess) {
        ISA_ERR("EsfNetworkManagerSaveParameter failed %d", esfnm_ret);
        is_flash_write_error = true;
    }

    /* ip_method : DHCP or Static IP */

    esfnm_param.normal_mode.ip_method = 0 /* DHCP */;

    if (esfnm_ret == kEsfNetworkManagerResultSuccess) {
        // If IP addresses were in the QR code and all of them were written successfully,
        // set ip_method to use StaticIP.

        if (enable_static_ip) {
            ISA_DBG("Enable static ip IPv4");
            esfnm_param.normal_mode.ip_method = 1 /*StaticIP*/;
        }

        if (enable_static_ip_v6) {
            ISA_DBG("Enable static ip IPv6");
#if 0 //TODO:Currently IPv6 is not effective.
      esfnm_param.normal_mode.ip_method = 1/*StaticIP*/
#endif
        }
    }

    memset(&esfnm_mask, 0, sizeof(esfnm_mask));

    esfnm_mask.normal_mode.ip_method = 1;

    esfnm_ret = EsfNetworkManagerSaveParameter(&esfnm_mask, &esfnm_param);
    if (esfnm_ret != kEsfNetworkManagerResultSuccess) {
        ISA_ERR("EsfNetworkManagerSaveParameter failed %d", esfnm_ret);
        is_flash_write_error = true;
    }

    /* Write NTP data to flash.*/

    EsfClockManagerParams cm_param = {0};

    /* NTP */

    if (*sp_payload_info->m_static_ntp != '\0') {
        ISA_DBG("static ntp = %s", sp_payload_info->m_static_ntp);

        EsfClockManagerParamsMask cm_mask = {.connect.hostname = 1};
        WrapCopyData(cm_param.connect.hostname, sp_payload_info->m_static_ntp,
                     sizeof(sp_payload_info->m_static_ntp));

        EsfClockManagerReturnValue esfcm_ret = EsfClockManagerSetParamsForcibly(&cm_param,
                                                                                &cm_mask);
        if (esfcm_ret != kClockManagerSuccess) {
            ISA_ERR("EsfClockManagerSetParamsForcibly failed %d", esfcm_ret);
            is_flash_write_error = true;
        }
    }
    else {
        EsfClockManagerParamsMask cm_mask = {.connect.hostname = 1};
        /* Delete NTP Setting */
        memcpy(cm_param.connect.hostname, "", 1);

        EsfClockManagerReturnValue esfcm_ret = EsfClockManagerSetParamsForcibly(&cm_param,
                                                                                &cm_mask);
        if (esfcm_ret != kClockManagerSuccess) {
            ISA_ERR("EsfClockManagerSetParamsForcibly failed %d", esfcm_ret);
            is_flash_write_error = true;
        }
    }

    /* If writing to Flash fails, the error LED will light for 5 seconds. */

    if (is_flash_write_error) {
        SysAppLedSetAppStatus(LedTypePower, LedAppStatusErrorDataFlashFailed);
        sleep(5);
        SysAppLedUnsetAppStatus(LedTypePower, LedAppStatusErrorDataFlashFailed);
        ret = kIsaQrcode_Failed;
    }

    return ret;
}

/*----------------------------------------------------------------------*/
IsaQrcodeErrorCode IsaQrcodeExit(void)
{
    IsaQrcodeErrorCode ret = kIsaQrcode_Success;

    /* free */

    if (sp_payload_info != NULL) {
        free(sp_payload_info);
        sp_payload_info = NULL;
    }

    return ret;
}

/*----------------------------------------------------------------------*/
void IsaClearMultiQRParam(void)
{
    s_qr_total_bit = 0x00;
    s_qr_count_bit = 0x00;
    s_IsQRFirst = true;
    return;
}

/*----------------------------------------------------------------------*/
static char *ParseQrPayloadIndex(char *p_tok, char *p_prop, uint16_t maxsize)
{
    if (p_tok[1] != '=') {
        return NULL;
    }

    char *p = p_tok + 2;
    int index = 0;

    for (; *p != ';' && index < maxsize - 1; index++, p++) {
        if (*p == '\\') {
            p++;
        }

        p_prop[index] = *p;
    }

    p_prop[index] = '\0';

    while (*p != ';') p++; // in case of exceeding maxsize

    return p + 1;
}

/*----------------------------------------------------------------------*/
static IsaQrcodeDecodeResult SetQrInfo(char *p_input, uint8_t *p_qr_count)
{
    char *ptr = p_input;
    IsaQrcodeDecodeResult ret = kIsaQrcodeDecode_Invalid;
    static bool contain_evphub_url;
    static bool contain_evphub_port;
#if defined(CONFIG_BOARD_WIFI_SMALL_ES) /* T3Ws */
    static bool contain_wifi_ssid;
#endif
    static bool contain_project_id;
    static bool contain_register_token;
    static bool contain_ipv6;
    static uint32_t num_of_ipv4_element;

    if (*ptr == QRIndex) {
        ptr += 2;

        if (s_IsQRFirst) {
            if ((*ptr - '0') > MULTI_QR_NUM_MAX) {
                ISA_ERR("QR Total Number is illigal %d", *ptr - '0');
                memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                return ret;
            }

            ISA_INFO("QR Total Number is %d", *ptr - '0');
            for (int i = 0; i < *ptr - '0'; i++) {
                s_qr_total_bit |= (1 << i);
            }
            s_IsQRFirst = false;
            contain_evphub_url = false;
            contain_evphub_port = false;
#if defined(CONFIG_BOARD_WIFI_SMALL_ES) /* T3Ws */
            contain_wifi_ssid = false;
#endif
            contain_project_id = false;
            contain_register_token = false;
            contain_ipv6 = false;
            num_of_ipv4_element = 0;
        }

        ISA_INFO("QR %d Read", *(ptr + 1) - '0');
        s_qr_count_bit |= (1 << (*(ptr + 1) - '0' - 1));

        uint8_t count = 0;
        uint8_t temp_qr_count_bit = s_qr_count_bit;
        for (; temp_qr_count_bit != 0; temp_qr_count_bit &= temp_qr_count_bit - 1) {
            count++;
        }
        *p_qr_count = count;

        ptr += 3;
    }
    else {
        memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
        return ret;
    }

    IpVer ip_check = -1;

    while (*ptr != '\0') {
        switch (*ptr) {
            case EVPHubURL:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_evphub_url,
                                          sizeof(sp_payload_info->m_evphub_url));

                if (*sp_payload_info->m_evphub_url != '\0') {
                    ip_check = CheckIpAddressType((const char *)sp_payload_info->m_evphub_url);
                    if (ip_check == IPv4) {
                        contain_evphub_url = true;
                    }
                    else if (IsValidEvpHubUrl((const char *)sp_payload_info->m_evphub_url)) {
                        contain_evphub_url = true;
                    }
                    else {
                        ISA_ERR("Invalid EVP Hub URL %s", sp_payload_info->m_evphub_url);
                        memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                        return ret;
                    }
                }
                break;

            case EVPHubPort:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_evphub_port,
                                          sizeof(sp_payload_info->m_evphub_port));

                if (*sp_payload_info->m_evphub_port != '\0') {
                    int evphub_port = 0;
                    evphub_port = atoi(sp_payload_info->m_evphub_port);

                    if ((evphub_port >= 0) && (evphub_port <= 65535)) {
                        contain_evphub_port = true;
                    }
                    else {
                        ISA_ERR("Invalid EVP Hub Port %d", evphub_port);
                        memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                        return ret;
                    }
                }
                break;

            case EVPMqttInsecure:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_evp_mqtt_insecure,
                                          sizeof(sp_payload_info->m_evp_mqtt_insecure));

                /* EVP MQTT insecure support "0", "1", " " */

                if ((strncmp(sp_payload_info->m_evp_mqtt_insecure, "0", sizeof("0")) != 0) &&
                    (strncmp(sp_payload_info->m_evp_mqtt_insecure, "1", sizeof("1")) != 0) &&
                    (strncmp(sp_payload_info->m_evp_mqtt_insecure, " ", sizeof(" ")) != 0)) {
                    ISA_ERR("Invalid MQTT insecure code '%02X'",
                            sp_payload_info->m_evp_mqtt_insecure[0]);
                    memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                    return ret;
                }

                break;

            case EVPMode:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_evp_mode,
                                          sizeof(sp_payload_info->m_evp_mode));
                break;

            case ProjectID:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_project_id,
                                          sizeof(sp_payload_info->m_project_id));
                contain_project_id = true;
                break;

            case RegisterToken:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_register_token,
                                          sizeof(sp_payload_info->m_register_token));
                contain_register_token = true;
                break;

            case WiFiSSID:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_wifi_ssid,
                                          sizeof(sp_payload_info->m_wifi_ssid));
#if defined(CONFIG_BOARD_WIFI_SMALL_ES) /* T3Ws */
                contain_wifi_ssid = true;
#endif
                break;

            case WiFiPassword:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_wifi_pass,
                                          sizeof(sp_payload_info->m_wifi_pass));

                // Validate WiFi password length (reject 1-7 character passwords, except single space)
                if (*sp_payload_info->m_wifi_pass != '\0') {
                    int password_len = strnlen(sp_payload_info->m_wifi_pass,
                                               sizeof(sp_payload_info->m_wifi_pass));
                    // Allow single space as valid password, reject other 1-7 character passwords
                    if (password_len >= 1 && password_len < 8 &&
                        !(password_len == 1 && sp_payload_info->m_wifi_pass[0] == ' ')) {
                        ISA_ERR(
                            "Invalid QR Code: WiFi password length must be 0 (open), single space, "
                            "or 8+ "
                            "characters (encrypted), got %d",
                            password_len);
                        memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                        return ret;
                    }
                }
                break;

            case ProxyURL:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_proxy_url,
                                          sizeof(sp_payload_info->m_proxy_url));

                if (*sp_payload_info->m_proxy_url != '\0') {
                    ip_check = CheckIpAddressType((const char *)sp_payload_info->m_proxy_url);
                    if ((ip_check != IPv4) && (ip_check != IPBlank)) {
                        if (!IsValidCommonUrl((const char *)sp_payload_info->m_proxy_url, 256)) {
                            ISA_ERR("Invalid Proxy URL %s", sp_payload_info->m_proxy_url);
                            memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                            return ret;
                        }
                    }
                }
                break;

            case ProxyPort:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_proxy_port,
                                          sizeof(sp_payload_info->m_proxy_port));

                if (*sp_payload_info->m_proxy_port != '\0') {
                    int m_proxy_port = 0;
                    m_proxy_port = atoi(sp_payload_info->m_proxy_port);

                    if ((m_proxy_port >= 0) && (m_proxy_port <= 65535)) {
                        /* Valid Proxy Port */
                    }
                    else {
                        ISA_ERR("Invalid Proxy Port %d", m_proxy_port);
                        memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                        return ret;
                    }
                }
                break;

            case ProxyUserName:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_proxy_user,
                                          sizeof(sp_payload_info->m_proxy_user));
                break;

            case ProxyPassword:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_proxy_pass,
                                          sizeof(sp_payload_info->m_proxy_pass));
                break;

            case IPAddress:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_static_ip,
                                          sizeof(sp_payload_info->m_static_ip));
                ip_check = CheckIpAddressType((const char *)sp_payload_info->m_static_ip);
                if ((ip_check != IPv4) && (ip_check != IPBlank)) {
                    ISA_ERR("Invalid IPAddress %s", sp_payload_info->m_static_ip);
                    memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                    return ret;
                }
                num_of_ipv4_element++;
                break;

            case IPAddress_v6:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_static_ip_v6,
                                          sizeof(sp_payload_info->m_static_ip_v6));
                ip_check = CheckIpAddressType((const char *)sp_payload_info->m_static_ip_v6);
                if ((ip_check != IPv6) && (ip_check != IPBlank)) {
                    ISA_ERR("Invalid IPAddress_v6 %s", sp_payload_info->m_static_ip_v6);
                    memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                    return ret;
                }
                if (ip_check != IPBlank) {
                    contain_ipv6 = true;
                }
                break;

            case SubnetMask:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_static_subnetmask,
                                          sizeof(sp_payload_info->m_static_subnetmask));
                ip_check = CheckIpAddressType((const char *)sp_payload_info->m_static_subnetmask);
                if ((ip_check != IPv4) && (ip_check != IPBlank)) {
                    ISA_ERR("Invalid SubnetMask %s", sp_payload_info->m_static_subnetmask);
                    memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                    return ret;
                }
                num_of_ipv4_element++;
                break;

            case SubnetMask_v6:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_static_subnetmask_v6,
                                          sizeof(sp_payload_info->m_static_subnetmask_v6));
                ip_check =
                    CheckIpAddressType((const char *)sp_payload_info->m_static_subnetmask_v6);
                if ((ip_check != IPv6) && (ip_check != IPBlank)) {
                    ISA_ERR("Invalid SubnetMask_v6 %s", sp_payload_info->m_static_subnetmask_v6);
                    memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                    return ret;
                }
                if (ip_check != IPBlank) {
                    contain_ipv6 = true;
                }
                break;

            case Gateway:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_static_gateway,
                                          sizeof(sp_payload_info->m_static_gateway));
                ip_check = CheckIpAddressType((const char *)sp_payload_info->m_static_gateway);
                if ((ip_check != IPv4) && (ip_check != IPBlank)) {
                    ISA_ERR("Invalid Gateway %s", sp_payload_info->m_static_gateway);
                    memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                    return ret;
                }
                num_of_ipv4_element++;
                break;

            case Gateway_v6:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_static_gateway_v6,
                                          sizeof(sp_payload_info->m_static_gateway_v6));
                ip_check = CheckIpAddressType((const char *)sp_payload_info->m_static_gateway_v6);
                if ((ip_check != IPv6) && (ip_check != IPBlank)) {
                    ISA_ERR("Invalid Gateway_v6 %s", sp_payload_info->m_static_gateway_v6);
                    memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                    return ret;
                }
                if (ip_check != IPBlank) {
                    contain_ipv6 = true;
                }
                break;

            case DNS:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_static_dns,
                                          sizeof(sp_payload_info->m_static_dns));
                ip_check = CheckIpAddressType((const char *)sp_payload_info->m_static_dns);
                if ((ip_check != IPv4) && (ip_check != IPBlank)) {
                    ISA_ERR("Invalid DNS %s", sp_payload_info->m_static_dns);
                    memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                    return ret;
                }
                num_of_ipv4_element++;
                break;

            case DNS_v6:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_static_dns_v6,
                                          sizeof(sp_payload_info->m_static_dns_v6));
                ip_check = CheckIpAddressType((const char *)sp_payload_info->m_static_dns_v6);
                if ((ip_check != IPv6) && (ip_check != IPBlank)) {
                    ISA_ERR("Invalid DNS_v6 %s", sp_payload_info->m_static_dns_v6);
                    memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                    return ret;
                }
                if (ip_check != IPBlank) {
                    contain_ipv6 = true;
                }
                break;

            case NTP:
                ptr = ParseQrPayloadIndex(ptr, sp_payload_info->m_static_ntp,
                                          sizeof(sp_payload_info->m_static_ntp));
                ip_check = CheckIpAddressType((const char *)sp_payload_info->m_static_ntp);
                if ((ip_check != IPv4) && (ip_check != IPBlank)) {
                    if (!IsValidCommonUrl((const char *)sp_payload_info->m_static_ntp, 64)) {
                        ISA_ERR("Invalid NTP %s", sp_payload_info->m_static_ntp);
                        memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                        return ret;
                    }
                }
                break;

            default:
                ISA_ERR("Unknown key word '%c' (0x%x)", *ptr, *ptr);
                memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
                return ret;
        }

        if (ptr == NULL) {
            memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
            return ret;
        }
    }

    if (s_qr_total_bit == s_qr_count_bit) {
        /* Check if mandatory parameters are missing. */

#if defined(CONFIG_BOARD_WIFI_SMALL_ES) /* T3Ws */
        if (!contain_evphub_url || !contain_evphub_port || !contain_wifi_ssid) {
            ISA_ERR("Mandatory parameters are missing.");
            memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
            return ret;
        }
#else /* T5/T3P */
        if (!contain_evphub_url || !contain_evphub_port) {
            ISA_ERR("Mandatory parameters are missing.");
            memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
            return ret;
        }
#endif

        if ((contain_project_id && !contain_register_token) ||
            (!contain_project_id && contain_register_token)) {
            ISA_ERR("ProjectID and RegisterToken must be to be a set.");
            memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
            return ret;
        }

        if ((contain_ipv6 == true) && (num_of_ipv4_element < IPv4Elemet_NUM)) {
            ISA_ERR("IPv6 cannot be set because IPv4 is not set.");
            memset(sp_payload_info, '\0', sizeof(IsaQrcodePayloadInfo));
            return ret;
        }

        ret = kIsaQrcodeDecode_AllRecognized;
    }
    else {
        ret = kIsaQrcodeDecode_PartRecognized;
    }

    return ret;
}

static void WrapCopyData(char *dst, char *src, uint32_t max_data_size)
{
    if (*src != ' ') {
        size_t write_size = 0;

        write_size = strnlen(src, max_data_size - 1) + 1; /* Add NULL string. */

        memcpy(dst, src, write_size);
    }
    else {
        /* Write NULL string when space is specified. */

        memcpy(dst, "", 1);
    }
}

static bool IsValidDomain(const char *domain, int max_len)
{
    bool isalpha_flag = false;

    /* Length check : Depends on domain name rules. */
    int len = strnlen(domain, max_len);
    if ((len < CFGST_ENDPOINT_DOMAIN_LEN_MIN) || (len > 253)) {
        ISA_ERR("Invalid Domain length %d", len);
        return false; // Domain length is invalid
    }

    /* Check labels position. */
    int dot_count = 0;
    int label_start = 0;
    int label_last = 0;

    for (int i = 0; i <= len; i++) {
        if ((domain[i] == '.') || (domain[i] == '\0')) {
            label_last = i;

            if (domain[i] == '.') {
                dot_count++;
            }

            /* Check label length. */

            int label_length = label_last - label_start;
            if ((label_length < CFGST_ENDPOINT_LABEL_LEN_MIN) ||
                (label_length > CFGST_ENDPOINT_LABEL_LEN_MAX)) {
                ISA_ERR("Invalid URL label length %d", label_length);
                return false; // Invalid label length 1..63
            }

            /* Check label characters. 1-st char. */

            char char_1st = domain[label_start];
            if (!isalnum(char_1st)) {
                ISA_ERR("Invalid URL label 1st char. '%c' Must be AlNum", char_1st);
                return false; // Invalid label 1st character.
            }

            /* Check label characters. Last char. */

            if (label_length >= 2) {
                char char_last = domain[label_last - 1];
                if (!isalnum(char_last)) {
                    ISA_ERR("Invalid URL label last char. '%c' Must be AlNum", char_last);
                    return false; // Invalid label last character.
                }
            }

            /* Check label characters. Mid char. */

            if (label_length >= 3) {
                for (int j = 1; j < label_length - 1; j++) {
                    char char_mid = domain[label_start + j];
                    if ((!isalnum(char_mid)) && (char_mid != '-')) {
                        ISA_ERR("Invalid URL label mid char. '%c' Must be AlNum or '-'", char_mid);
                        return false; // Invalid character
                    }
                }
            }

            /* Next label token */
            label_start = i + 1;
        }
        else if ((isalpha(domain[i])) || (domain[i] == '-')) {
            /* Treat "number only pattern" as error , for example, "777.888.999.000" and more. */

            isalpha_flag = true;
        }

    } /* for */

    if (dot_count == 0) {
        ISA_ERR("URL format, not found '.' : %s", domain);
        return false; // No dot found
    }

    /* Check the last part. TLD: Top level domain. (Usually represents a country.) */

    const char *tld = strrchr(domain, '.') + 1;
    int tld_len = strnlen(tld, max_len);

    if (tld_len < 2) {
        ISA_ERR("URL format, invalid TLD length : %s", tld);
        return false; // TLD length is invalid
    }

    if (isalpha_flag == false) {
        ISA_ERR("Invalid domain format, but it may be IP address. : %s", domain);
        return false; // invalid IPv4
    }

    return true; // Domain is valid
}

STATIC bool IsValidEvpHubUrl(const char *domain)
{
    return IsValidDomain(domain, 64);
}

STATIC bool IsValidCommonUrl(const char *domain, int max_len)
{
    /* " " is valid. */
    if (strncmp(domain, " ", max_len) == 0) {
        return true;
    }

    return IsValidDomain(domain, max_len);
}

/*----------------------------------------------------------------------*/
static IpVer CheckIpAddressType(const char *ip_string)
{
    int inet_ret = 0;

    // Accept blank space string.

    if (ip_string[0] == ' ') {
        return IPBlank; // Blank space
    }

    // Check ip_string describes IPv4 or not.

    struct in_addr ipv4;

    inet_ret = inet_pton(AF_INET, ip_string, &ipv4);

    if (inet_ret == 1) {
        return IPv4; // IPv4.
    }
    // Check ip_string describes IPv6 or not.

    struct in6_addr ipv6;

    inet_ret = inet_pton(AF_INET6, ip_string, &ipv6);

    if (inet_ret == 1) {
        return IPv6; // IPv6.
    }

    return IPvInvalid;
}
