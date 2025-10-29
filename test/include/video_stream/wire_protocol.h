/*
 * SPDX-FileCopyrightText: 2025 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file wire_protocol.h
 * @brief Wire protocol definitions shared between client and server
 * 
 * This header contains only the binary protocol definitions that are
 * transmitted over the socket. Both client and server can include this
 * without dependency conflicts.
 */

#ifndef WIRE_PROTOCOL_H
#define WIRE_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>

/* Protocol version for compatibility checking */
#define WIRE_PROTOCOL_VERSION 1

/* File recording constants */
#define WIRE_MAX_FILE_DURATION_HOURS 24       /* Maximum file duration limit (24 hours) */
#define WIRE_DEFAULT_FILE_DURATION_MINUTES 30 /* Default file duration (30 minutes) */

/* Message types transmitted over the wire */
typedef enum {
    WIRE_MSG_START_STREAM = 1,
    WIRE_MSG_STOP_STREAM = 2,
    WIRE_MSG_SET_VIDEO_FORMAT = 3,
    WIRE_MSG_SET_RTP_CLOCK_RATE = 4,
    WIRE_MSG_SET_RTP_PAYLOAD_TYPE = 5,
    WIRE_MSG_SET_RTP_CHANNEL = 6,
    WIRE_MSG_SET_RTP_JITTER_BUFFER_SIZE = 7,
    WIRE_MSG_SET_RTP_PACKETIZATION_INTERVAL = 8,
    WIRE_MSG_SET_RTP_MULTICAST_MODE = 9,
    WIRE_MSG_SET_NFS_CONFIG = 10, // Consolidated NFS protocol
    WIRE_MSG_SET_OPERATING_MODE = 11,
    WIRE_MSG_SET_RTP_DESTINATION = 12,
    WIRE_MSG_RESET_RTP_SEQUENCE = 13,
    WIRE_MSG_SET_RTSP_SERVER_CONFIG = 14,
    WIRE_MSG_SET_RTSP_AUTH = 15,
    WIRE_MSG_GET_STREAM_STATUS = 16,
    WIRE_MSG_GET_OPERATING_MODE = 17,
    WIRE_MSG_GET_RTP_CONFIG = 18,
    WIRE_MSG_GET_NFS_CONFIG = 19,
    WIRE_MSG_GET_SERVER_STATUS = 20,
    WIRE_MSG_GET_RTSP_CONFIG = 21,
    WIRE_MSG_UNMOUNT_NFS = 22,
    WIRE_MSG_SET_LOCAL_MOUNT_POINT = 23,
    WIRE_MSG_GET_LOCAL_MOUNT_POINT = 24
} wire_message_type_t;

/* Response codes transmitted over the wire */
typedef enum {
    WIRE_RESPONSE_SUCCESS = 0,
    WIRE_RESPONSE_ERROR = 1,
    WIRE_RESPONSE_INVALID_COMMAND = 2,
    WIRE_RESPONSE_INVALID_PARAMETER = 3,
    WIRE_RESPONSE_INVALID_STATE = 4,
    WIRE_RESPONSE_SYSTEM_ERROR = 5
} wire_response_code_t;

/* Operating modes transmitted over the wire */
typedef enum {
    WIRE_MODE_STREAM_ONLY = 0,
    WIRE_MODE_RECORD_ONLY = 1,
    WIRE_MODE_STREAM_AND_RECORD = 2
} wire_operating_mode_t;

/* Stream status transmitted over the wire */
typedef enum { WIRE_STREAM_STOPPED = 0, WIRE_STREAM_STARTED = 1 } wire_stream_status_t;

/* Fatal error types transmitted over the wire */
typedef enum {
    WIRE_FATAL_ERROR_NONE = 0,
    WIRE_FATAL_ERROR_NETWORK_DISCONNECTED = 1,
    WIRE_FATAL_ERROR_STORAGE_FULL = 2,
    WIRE_FATAL_ERROR_PIPELINE_CRITICAL = 3,
    WIRE_FATAL_ERROR_NFS_MOUNT_LOST = 4,
    WIRE_FATAL_ERROR_WRITE_FAILED = 5,
    WIRE_FATAL_ERROR_GENERIC = 99
} wire_fatal_error_type_t;

/* Wire protocol structures - these are the exact binary layouts */

/**
 * @brief Message header transmitted over the wire
 */
typedef struct {
    uint32_t type;      /* wire_message_type_t */
    uint32_t data_size; /* Size of following data */
} __attribute__((packed)) wire_message_header_t;

/**
 * @brief Response header transmitted over the wire
 */
typedef struct {
    uint32_t response_code; /* wire_response_code_t */
    uint32_t data_size;     /* Size of following data */
} __attribute__((packed)) wire_response_header_t;

/**
 * @brief NFS configuration transmitted over the wire (consolidated protocol)
 */
typedef struct {
    char server_ip[256];        /* NFS server IP address or hostname */
    char mount_point[256];      /* Remote NFS path to mount */
    uint32_t nfs_version;       /* NFS version (3 or 4) */
    uint8_t use_tcp;            /* Protocol: 0 = UDP, 1 = TCP */
    char record_filename[1024]; /* Current recording filename */
    uint32_t record_time;       /* Recording time in seconds, 0 if not recording */

    /* Timestamp-based file recording settings */
    uint8_t use_timestamp_files;    /* 0/1 - Enable timestamp-based file naming */
    uint32_t file_duration_minutes; /* File duration in minutes (1-1440, max 24h) */
    uint8_t padding[3];             /* Explicit padding for alignment */
} __attribute__((packed)) wire_nfs_config_t;

/**
 * @brief Video format configuration transmitted over the wire
 */
typedef struct {
    uint32_t width;     /* Video width in pixels (320-3840) */
    uint32_t height;    /* Video height in pixels (240-2160) */
    uint32_t framerate; /* Video framerate in fps (5-60) */
} __attribute__((packed)) wire_video_format_t;

/**
 * @brief RTP destination configuration transmitted over the wire
 */
typedef struct {
    char destination[256]; /* IPv4 address (e.g., "192.168.1.100") */
    uint32_t port;         /* RTP port number (1024-65535) */
} __attribute__((packed)) wire_rtp_destination_t;

/**
 * @brief RTP configuration transmitted over the wire
 */
typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t framerate;
    uint32_t clock_rate;
    uint32_t payload_type;
    uint32_t channel;
    uint32_t jitter_buffer_size;
    uint32_t packetization_interval;
    uint8_t multicast_mode; /* 0 = disabled, 1 = enabled */
    uint8_t padding[3];     /* Explicit padding for alignment */
    char destination[256];  /* RTP destination IP address */
    uint32_t port;          /* RTP destination port */
} __attribute__((packed)) wire_rtp_config_t;

/**
 * @brief RTSP server configuration transmitted over the wire
 */
typedef struct {
    char server_ip[256];  /* RTSP server bind address */
    uint32_t server_port; /* RTSP server port */
    char stream_name[64]; /* Stream name */
    uint32_t max_clients; /* Maximum concurrent clients */
} __attribute__((packed)) wire_rtsp_server_config_t;

/**
 * @brief RTSP authentication configuration transmitted over the wire
 */
typedef struct {
    uint8_t auth_enabled; /* 0 = disabled, 1 = enabled */
    uint8_t padding[3];   /* Explicit padding for alignment */
    char username[64];    /* Authentication username */
    char password[128];   /* Authentication password */
} __attribute__((packed)) wire_rtsp_auth_config_t;

/**
 * @brief RTSP status transmitted over the wire
 */
typedef struct {
    char server_ip[256];      /* Current server IP */
    uint32_t server_port;     /* Current server port */
    char stream_name[64];     /* Current stream name */
    char username[64];        /* Current username */
    uint8_t auth_enabled;     /* Authentication status */
    uint8_t password_set;     /* Password configured indicator */
    uint8_t server_running;   /* Server operational status */
    uint8_t padding;          /* Explicit padding for alignment */
    uint32_t current_clients; /* Currently connected clients */
    uint32_t max_clients;     /* Maximum client limit */
    char stream_url[512];     /* Full RTSP URL */
} __attribute__((packed)) wire_rtsp_config_t;

/**
 * @brief Local mount point data transmitted over the wire
 */
typedef struct {
    char local_mount_point[512]; /* Local mount point path */
} __attribute__((packed)) wire_local_mount_point_t;

/**
 * @brief Server status transmitted over the wire
 */
typedef struct {
    uint32_t stream_status;  /* 0 = stopped, 1 = started */
    uint32_t operating_mode; /* wire_operating_mode_t */
    wire_rtp_config_t rtp_config;
    wire_nfs_config_t nfs_config;
    wire_rtsp_config_t rtsp_config;
    uint32_t fatal_error_type;     /* wire_fatal_error_type_t */
    char fatal_error_message[256]; /* Error message if fatal_error_type != NONE */
} __attribute__((packed)) wire_server_status_t;

/* Helper macros for protocol validation */
#define WIRE_PROTOCOL_MAGIC 0x56534352 /* "VSCR" in little-endian */

#endif /* WIRE_PROTOCOL_H */
