# SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

system_app_sources += files([
	'initial_setting_app_button.c',
	'initial_setting_app_ps.c',
	'initial_setting_app_qr_decode_internal.c',
	'initial_setting_app_qr_decode.c',
	'initial_setting_app_qrcode.c',
	'initial_setting_app_timer.c',
	'main.c'
])

if systemapps_config_h.has('CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION') and systemapps_config_h.get('CONFIG_EXTERNAL_ISAPP_ENABLE_QR_QUALITY_OPTIMIZATION')
    system_app_sources += files('../private/qr_quality_optimization.c')
endif
