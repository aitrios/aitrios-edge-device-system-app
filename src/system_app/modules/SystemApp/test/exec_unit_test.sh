#!/bin/bash
# SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

function link_header() {
    root_dir="$(pwd -P)"
    target="t3s3"
    if [ $# -ne 0 ]; then
        target=$1
    fi
    target_dir=$root_dir/../../../../../actions/$target
    # echo $target_dir
    rm -f $root_dir/include/nuttx
    rm -f $root_dir/include/arch
    ln -s $target_dir/include/nuttx $root_dir/include/nuttx
    ln -s $target_dir/include/arch $root_dir/include/arch
}

function build_test() {
    if [ -e build ]; then
      rm -rf build
    fi

    mkdir build

    pushd build
    cmake $@ ..
    make -j $(nproc)
    if [ $? -ne 0 ]; then
      echo "[exec_unit_test.sh] build error"
      exit 1
    fi
    popd
}

function exec_test() {
    # Test
    export LD_LIBRARY_PATH="../lib:$LD_LIBRARY_PATH"
    build/src/unit_test
}

function set_coverage() {
    # Coverage
    cd ..
    src_root_dir="$(pwd -P)"
    coverage_search_path="$(pwd -P)/test/build"
    ex_option=""
    exclude_pattern_array=('test/gtest/' 'test/src/') # relative to $src_root_dir
    for ex_pat in ${exclude_pattern_array[@]};
    do
        ex_option="$ex_option -e $ex_pat"
    done
}

function exec_coverage_line() {
    gcovr    -r $src_root_dir $ex_option $coverage_search_path
}

function exec_coverage_branch() {
    gcovr -b -r $src_root_dir $ex_option $coverage_search_path
}

if [ $# -eq 0 ]; then
    link_header
    build_test
    exec_test
    set_coverage
    exec_coverage_line
    exec_coverage_branch
elif [ $1 = "build" ]; then
    link_header $2
    build_test
elif [ $1 = "test" ]; then
    exec_test
elif [ $1 = "c0" ]; then
    set_coverage
    exec_coverage_line
elif [ $1 = "c1" ]; then
    set_coverage
    exec_coverage_branch
else
    link_header $1
    build_test
    exec_test
    set_coverage
    exec_coverage_line
    exec_coverage_branch
fi

