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
#include <sys/wait.h>

/*----------------------------------------------------------------------------*/
int __wrap_waitpid(pid_t pid, int* status, int options)
{
    return mock_type(int);
}
