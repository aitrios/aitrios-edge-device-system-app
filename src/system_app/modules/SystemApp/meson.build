# SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

system_app_sources += files([
	'system_app_additional_info.c',
	'system_app_button.c',
	'system_app_common.c',
	'system_app_configuration.c',
	'system_app_deploy.c',
	'system_app_direct_command.c',
	'system_app_led.c',
	'system_app_log.c',
	'system_app_main.c',
	'system_app_state.c',
	'system_app_timer.c',
	'system_app_ud_main.c'
])

# Add video stream interface manager only when the feature is enabled
if systemapps_config_h.has('CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING') and systemapps_config_h.get('CONFIG_EXTERNAL_SYSTEMAPP_VIDEO_STREAMING')
	system_app_sources += files(['system_app_vsc_manager.c'])
endif
