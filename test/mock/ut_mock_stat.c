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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/*----------------------------------------------------------------------------*/
int __wrap_stat(const char *pathname, struct stat *buf)
{
    buf->st_mode = mock_type(int);
    return mock_type(int);
}
