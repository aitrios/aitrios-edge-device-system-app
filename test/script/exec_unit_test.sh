#!/bin/bash
# SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

function set_src_root_path() {
  src_root_sa_dir="$(pwd -P)/../src/system_app/modules/SystemApp"
  src_root_isa_dir="$(pwd -P)/../src/initial_setting_app"
}

function check_cmd_ret() {
  if [ $? -ne 0 ]; then
    test_failed=1
  fi
}

function check_device() {
  if [ "$1" = "T5" ] || [ "$1" = "T3P" ] || [ "$1" = "T3Ws" ] || [ "$1" = "Raspi" ]; then

    # Check device OK
    return 0
  else

    # Check device NG
    return 1
  fi
}

function change_config() {
  if [ -e ./include/nuttx/$1/config.h ]; then
    cp -f ./include/nuttx/$1/config.h ./include/nuttx
  elif [ -e ./include/linux/$1/config.h ]; then
    echo Raspi Config
  else
    echo "Nothing $1 Config file"
    exit 1
  fi
}

function build() {
  if check_device $1 ; then
    change_config $1
  else
    echo "[build_test] Invalid device"
    exit 1
  fi
  echo "==================== $1 Build ===================="

  if [ -e build/$1 ]; then
    rm -rf build/$1
  fi

  mkdir -p build/$1

  pushd build/$1
  if [ "$1" = "Raspi" ]; then
    cmake -DDEVICE_TYPE=$1 -DCMAKE_C_FLAGS="-include $(pwd -P)/../../include/linux/$1/config.h" ../..
  else
    cmake -DDEVICE_TYPE=$1 ../..
  fi

  if [ $? -ne 0 ]; then
    echo "[$1][exec_unit_test.sh] cmake error"
    exit 1
  fi

  make -j $(nproc)
  if [ $? -ne 0 ]; then
    echo "[$1][exec_unit_test.sh] build error"
    exit 1
  fi
  popd
}

function exec_test() {
  if check_device $1 ; then

    echo "==================== $1 Test Run ===================="

    # Init Unit Test Result Flag
    test_failed=0

    # SystemApp
    echo "************ SystemApp ************"
    echo "============ system_app_state.c ============"
    build/$1/system_app/system_app_state/ut_system_app_state
    check_cmd_ret

    echo "============ system_app_button.c ============"
    build/$1/system_app/system_app_button/ut_system_app_button
    check_cmd_ret

    echo "============ system_app_main.c ============"
    build/$1/system_app/system_app_main/ut_system_app_main
    check_cmd_ret

    echo "============ system_app_common.c ============"
    build/$1/system_app/system_app_common/ut_system_app_common
    check_cmd_ret

    echo "============ system_app_led.c ============"
    build/$1/system_app/system_app_led/ut_system_app_led
    check_cmd_ret

    echo "============ system_app_log.c ============"
    build/$1/system_app/system_app_log/ut_system_app_log
    check_cmd_ret

    echo "============ system_app_timer.c ============"
    build/$1/system_app/system_app_timer/ut_system_app_timer
    check_cmd_ret

    echo "============ system_app_ud_main.c ============"
    build/$1/system_app/system_app_ud_main/ut_system_app_ud_main
    check_cmd_ret

    echo "============ system_app_configuration.c ============"
    build/$1/system_app/system_app_configuration/ut_system_app_configuration
    check_cmd_ret

    echo "============ system_app_deploy.c ============"
    build/$1/system_app/system_app_deploy/ut_system_app_deploy
    check_cmd_ret

    echo "============ system_app_direct_command.c ============"
    build/$1/system_app/system_app_direct_command/ut_system_app_direct_command
    check_cmd_ret

    echo ""   # This is line break for separator

    # InitialSettingApp
    echo "************ InitialSettingApp ************"
    echo "============ initial_setting_app_qrcode.c ============"
    build/$1/initial_setting_app/initial_setting_app_qrcode/ut_initial_setting_app_qrcode
    check_cmd_ret

    echo "============ main.c ============"
    build/$1/initial_setting_app/main/ut_main
    check_cmd_ret

    echo "============ initial_setting_app_ps.c ============"
    build/$1/initial_setting_app/initial_setting_app_ps/ut_initial_setting_app_ps
    check_cmd_ret

    echo "============ initial_setting_app_ps_stub.c ============"
    build/$1/initial_setting_app/initial_setting_app_ps_stub/ut_initial_setting_app_ps_stub
    check_cmd_ret

    echo "============ initial_setting_app_qr_decode.c ============"
    build/$1/initial_setting_app/initial_setting_app_qr_decode/ut_initial_setting_app_qr_decode
    check_cmd_ret

    echo "============ initial_setting_app_qr_decode_internal.c ============"
    build/$1/initial_setting_app/initial_setting_app_qr_decode_internal/ut_initial_setting_app_qr_decode_internal
    check_cmd_ret

    echo "============ initial_setting_app_button.c ============"
    build/$1/initial_setting_app/initial_setting_app_button/ut_initial_setting_app_button
    check_cmd_ret

    echo "============ initial_setting_app_timer.c ============"
    build/$1/initial_setting_app/initial_setting_app_timer/ut_initial_setting_app_timer
    check_cmd_ret

    if [ -d "../test/private" ]; then
      if [ $1 = "T3P" ] || [ $1 = "T3Ws" ]; then
        echo ""   # This is line break for separator

        # Private
        echo "************ Private ************"
        echo "============ qr_quality_optimization.c ============"
        build/$1/private/qr_quality_optimization/ut_qr_quality_optimization
        check_cmd_ret

        if [ $test_failed -eq 1 ]; then
          exit 1
        fi
      fi
    fi

  else
    echo "[exec_test] Invalid device"
    exit 1
  fi
}

function set_path_and_option() {
  if check_device $2 ; then

    # Set root path and coverage path
    if [ $1 = "system_app" ]; then
      src_root_dir="$(pwd -P)/../src/system_app/modules/SystemApp"
      coverage_search_path="$(pwd -P)/coverage/$2/system_app"
      exclude_pattern_array=('') # relative to $src_root_dir
    elif [ $1 = "initial_setting_app" ]; then
      src_root_dir="$(pwd -P)/../src/initial_setting_app"
      coverage_search_path="$(pwd -P)/coverage/$2/initial_setting_app"
      exclude_pattern_array=('') # relative to $src_root_dir
    elif [ $1 = "private" ]; then
      src_root_dir="$(pwd -P)/../src"
      coverage_search_path="$(pwd -P)/coverage/$2/private"
      exclude_pattern_array=('') # relative to $src_root_dir
    else
      echo "[set_coverage] Invalid argument"
      src_root_dir="$(pwd -P)/../src/system_app/modules/SystemApp"
      coverage_search_path="$(pwd -P)/coverage/system_app"
      exclude_pattern_array=('') # relative to $src_root_dir
    fi

    # Set ex option
    ex_option=""
    for ex_pat in ${exclude_pattern_array[@]};
    do
      ex_option="$ex_option -e $ex_pat"
    done
  else
    echo "[set_path_and_option] Invalid device"
    exit 1
  fi
}

function collect_coverage_files() {
  if check_device $1 ; then

    echo "==================== $1 Collect Coverage ===================="

    if [ -e coverage/$1 ]; then
      rm -rf coverage/$1
    fi

    mkdir -p coverage/$1/system_app
    mkdir -p coverage/$1/initial_setting_app
    if [ -d "../test/private" ]; then
      mkdir -p coverage/$1/private
    fi

    # Collect coverage files in system_app build directories
    find ./build/$1/system_app -not -name "ut_*.gcda" -name "*.gcda" -exec cp {} ./coverage/$1/system_app \;
    find ./build/$1/system_app -not -name "ut_*.gcno" -name "*.gcno" -exec cp {} ./coverage/$1/system_app \;

    # Collect coverage files in initial_setting_app build directories
    find ./build/$1/initial_setting_app -not -name "ut_*.gcda" -name "*.gcda" -exec cp {} ./coverage/$1/initial_setting_app \;
    find ./build/$1/initial_setting_app -not -name "ut_*.gcno" -name "*.gcno" -exec cp {} ./coverage/$1/initial_setting_app \;

    # Collect coverage files in private build directories
    if [ -d "../test/private" ]; then
      find ./build/$1/private -not -name "ut_*.gcda" -name "*.gcda" -exec cp {} ./coverage/$1/private \;
      find ./build/$1/private -not -name "ut_*.gcno" -name "*.gcno" -exec cp {} ./coverage/$1/private \;
    fi
  else
    echo "[collect_coverage_files] Invalid device"
    exit 1
  fi
}

function exec_coverage_line() {
  # Set each src root path
  set_src_root_path

  echo "==================== Display C0 Coverage Result ===================="

  # Merge c0 result
  gcovr    -r $src_root_sa_dir  --add-tracefile "./coverage/tracefile_SA_*.json"  --merge-mode-functions=separate
  gcovr    -r $src_root_isa_dir --add-tracefile "./coverage/tracefile_ISA_*.json" --merge-mode-functions=separate
}

function exec_coverage_branch() {
  # Set each src root path
  set_src_root_path

  echo "==================== Display C1 Coverage Result ===================="

  # Merge c1 result
  gcovr -b -r $src_root_sa_dir  --add-tracefile "./coverage/tracefile_SA_*.json"  --merge-mode-functions=separate
  gcovr -b -r $src_root_isa_dir --add-tracefile "./coverage/tracefile_ISA_*.json" --merge-mode-functions=separate
}

function generate_tracefile() {
if [ $1 = "SA" ] || [ $1 = "ISA" ] || [ $1 = "private" ]; then
  if check_device $2 ; then
    if [ -e tracefile_$1_$2.json ]; then
      rm -rf tracefile_$1_$2.json
    fi

    # Generate tracefile for merge
    gcovr    -r $src_root_dir --json ./coverage/tracefile_$1_$2.json --json-base $src_root_dir --json-pretty $ex_option $coverage_search_path
  else
    echo "[generate_tracefile] Invalid argument $2"
    exit 1
  fi
else
  echo "[generate_tracefile] Invalid argument $1
  exit 1"
fi
}

if [ $# -eq 0 ]; then
  echo "Not specified argument"
  exit 1
elif [ $1 = "build" ]; then
  if [ $# -ge 2 ]; then
    build $2
  else
    echo "Not specified device"
    exit 1
  fi
elif [ $1 = "test" ]; then
  if [ $# -ge 2 ]; then
    exec_test $2
  else
    echo "Not specified device"
    exit 1
  fi
elif [ $1 = "collect" ]; then
  if [ $# -ge 2 ]; then
    collect_coverage_files $2
    set_path_and_option system_app $2
    generate_tracefile SA $2
    set_path_and_option initial_setting_app $2
    generate_tracefile ISA $2
    if [ -d "../test/private" ]; then
      if [ $2 = "T3P" ] || [ $2 = "T3Ws" ]; then
        set_path_and_option private $2
        generate_tracefile private $2
      fi
    fi
  else
    echo "Not specified device"
    exit 1
  fi
elif [ $1 = "c0" ]; then
  exec_coverage_line
elif [ $1 = "c1" ]; then
  exec_coverage_branch
else
  echo "Invalid argument"
  exit 1
fi

