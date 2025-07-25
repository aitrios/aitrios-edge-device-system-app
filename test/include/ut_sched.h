/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef _UT_SCHED_H_
#define _UT_SCHED_H_

typedef int pid_t;
typedef CODE int (*main_t)(int argc, FAR char *argv[]);
int task_create(FAR const char *name,
                int priority,
                int stack_size,
                main_t entry,
                FAR char * const argv[]);

int task_delete(pid_t pid);

#endif  // _UT_SCHED_H_
