# SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

keyval = import('keyval')

target_config_file_path = 'configs/@0@.config'.format(get_option('target'))
target_config_data = keyval.load(meson.current_source_dir() / target_config_file_path)

systemapps_config_h = configuration_data()

# Parse each Kconfig.
foreach dir_name: [ 'system_app', 'initial_setting_app' ]
	dot_config_file_name = '.' + dir_name + '.config'
	dot_config_file_path = meson.current_build_dir() / dot_config_file_name

	# Generate `.config` from `Kconfig` and config file.
	run_command(
		'python3', '-m', 'genconfig',
		'--config-out', dot_config_file_path,
		'--header-path', '/dev/null',
		'src/' + dir_name + '/Kconfig',
		env: { 'KCONFIG_CONFIG': target_config_file_path },
		check: true)

	# Load `.config` file.
	dot_config_data = keyval.load(dot_config_file_path)

	# Merge target config data into `.config` data.
	# NOTE: Some Kconfig exist on the out of this repository
	#       and it cannot be accessed from `genconfig`.
	#       So we need merge some data in `target config` into `.dot config` data here.
	foreach key, value : target_config_data
		if not dot_config_data.has_key(key)
			dot_config_data += { key: value }
		endif
	endforeach

	# Parse `.config` data.
	foreach key, value : dot_config_data
		if is_variable('config_h') and config_h.has(key)
			# Skip this key if `config_h`(project global configuration) already has it
			# to avoid confliction of definitions between `config_h` and `systemapps_config_h`.
			continue
		endif

		# Translate `CONFIG_XXX=y|n` into boolean.
		# NOTE: `CONFIG_XXX="y"` and `CONFIG_XXX="n"` will not replaced.
		if value == 'y' or value == 'n'
			if value == 'y'
				value = true
			else
				value = false
			endif
		endif

		# Add entry.
		systemapps_config_h.set(key, value)
	endforeach
endforeach

subdir('src')

configure_file(output : 'systemapps_config.h',
	configuration : systemapps_config_h,
)

systemapps_arguments = [
	'-include', meson.current_build_dir() / 'systemapps_config.h'
]
