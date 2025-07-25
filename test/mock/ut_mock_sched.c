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

#if defined(__NuttX__)
#include "nuttx/compiler.h"
#include "ut_sched.h"
#endif
#if defined(__NuttX__)
/*----------------------------------------------------------------------------*/
int __wrap_task_create(FAR const char *name, int priority, int stack_size, main_t entry,
                       FAR char *const argv[])
{
    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
int __wrap_task_delete(pid_t pid)
{
    return mock_type(int);
}
#endif
