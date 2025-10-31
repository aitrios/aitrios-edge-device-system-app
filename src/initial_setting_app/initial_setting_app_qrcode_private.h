/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _INITIAL_SETTING_APP_QRCODE_PRIVATE_H_
#define _INITIAL_SETTING_APP_QRCODE_PRIVATE_H_

#define QRIndex 'N'
#define EVPHubURL 'E'
#define EVPHubPort 'H'
#define EVPMode 'e'
#define EVPMqttInsecure 't'
#define ProjectID 'A'
#define RegisterToken 'B'
#define WiFiSSID 'S'
#define WiFiPassword 'P'
#define ProxyURL 'X'
#define ProxyPort 'O'
#define ProxyUserName 'U'
#define ProxyPassword 'W'
#define IPAddress 'I'
#define IPAddress_v6 'i'
#define SubnetMask 'K'
#define SubnetMask_v6 'k'
#define Gateway 'G'
#define Gateway_v6 'g'
#define DNS 'D'
#define DNS2 'n'
#define DNS_v6 'd'
#define NTP 'T'
#define NTP2 'p'
#define HEADER_STRINGLEN (24)
#define HEADER_LEN (16)
#define HEADER_LEN_BUFFER (18) /* HEADER_STRINGLEN * 3 / 4 */
#define IV_STRINGLEN (24)
#define IV_LEN (16)
#define QRVersion_LEN (2)
#define Option_LEN (6)
#define SIerID_LEN (8)
#define MagicNumber_STRINGLEN (4)
#define IPv4Elemet_NUM (4) /* IP, Subnet, Gateway, DNS */

/* QR Code payload information */

typedef struct {
    char m_evphub_url[65];           /* EVP Hub URL, up to 64 characters. */
    char m_evphub_port[6];           /* EVP Hub URL, up to 5 characters. */
    char m_evp_mode[33];             /* EVP Mode, up to 32 characters. */
    char m_evp_mqtt_insecure[2];     /* EVP MQTT insecure option, up to 1 characters. */
    char m_project_id[33];           /* ProjectID, up to 32 characters. */
    char m_register_token[45];       /* RegisterToken, up to 44 characters.*/
    char m_wifi_ssid[33];            /* WiFi SSID, up to 32 characters */
    char m_wifi_pass[33];            /* WiFi Password, up to 32 characters */
    char m_proxy_url[257];           /* Proxy URL, up to 256 characters */
    char m_proxy_port[6];            /* Proxy Port, up to 5 characters */
    char m_proxy_user[33];           /* Proxy User Name, up to 32 characters */
    char m_proxy_pass[33];           /* Proxy Password, up to 32 characters */
    char m_static_ip[40];            /* Static IP, up to 39 characters */
    char m_static_ip_v6[40];         /* Static IP for IPv6, up to 39 characters */
    char m_static_subnetmask[40];    /* Subnetmask, up to 39 characters */
    char m_static_subnetmask_v6[40]; /* Subnetmask for IPv6, up to 39 characters */
    char m_static_gateway[40];       /* Gateway, up to 39 characters */
    char m_static_gateway_v6[40];    /* Gateway for IPv6, up to 39 characters */
    char m_static_dns[40];           /* DNS, up to 39 characters */
    char m_static_dns2[16];          /* DNS2, up to 15 characters (DNS2 only supports IPv4.) */
    char m_static_dns_v6[40];        /* DNS for IPv6, up to 39 characters */
    char m_static_ntp[65];           /* NTP, up to 64 characters */
    char m_static_ntp2[65];          /* NTP2, up to 64 characters */
} IsaQrcodePayloadInfo;

typedef enum { IPvInvalid = -1, IPBlank = 0, IPv4 = 1, IPv6 = 2 } IpVer;

#endif // _INITIAL_SETTING_APP_QRCODE_PRIVATE_H_
