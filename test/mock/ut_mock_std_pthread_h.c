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

#include <pthread.h>
#include "ut_mock_std_pthread_h.h"

/*----------------------------------------------------------------------------*/
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(start_routine)(void *), void *arg)
{
    int *outval = (int *)arg;
    *outval = mock_type(int);
    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
// !!!!! Caution !!!!!
// Do NOT use "__wrap_pthread_exit()".
// The prototype declaration of pthread_exit has a non-return function designator,
// so the code after pthread_exit becomes invalid code.
// This results in unexpected test target behavior.
// Therefore, pthread_exit is mocked in a different way.

// void __wrap_pthread_exit(void* retval) {
void mock_pthread_exit(void *retval)
{
    //int val = mock_type(int);
    return;
}

/*----------------------------------------------------------------------------*/
int __wrap_pthread_join(pthread_t thread, void **retval)
{
    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
int __wrap_pthread_attr_init(pthread_attr_t *attr)
{
    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
int __wrap_pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize)
{
    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
int __wrap_pthread_cond_destroy(pthread_cond_t *cond)
{
    int ret = mock_type(int); // return status : {0:success | -1:error}
    return ret;
}

/*----------------------------------------------------------------------------*/
int __wrap_pthread_cond_init(pthread_cond_t *cond, pthread_condattr_t *attr)
{
    int ret = mock_type(int); // return status : {0:success | -1:error}
    return ret;
}

/*----------------------------------------------------------------------------*/
int __wrap_pthread_cond_signal(pthread_cond_t *cond)
{
    int ret = mock_type(int); // return status : {0:success | -1:error}
    return ret;
}

/*----------------------------------------------------------------------------*/
int __wrap_pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                                  const struct timespec *abstime)
{
    int ret = mock_type(int); // return status : {0:success | -1:error}
    return ret;
}

/*----------------------------------------------------------------------------*/
int __wrap_pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    int ret = mock_type(int); // return status : {0:success | -1:error}
    return ret;
}

/*----------------------------------------------------------------------------*/
int __wrap_pthread_mutex_init(pthread_mutex_t *mutex, pthread_mutexattr_t *attr)
{
    int ret = mock_type(int); // return status : {0:success | -1:error}
    return ret;
}

/*----------------------------------------------------------------------------*/
int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex)
{
    int ret = mock_type(int); // return status : {0:success | -1:error}
    return ret;
}

/*----------------------------------------------------------------------------*/
int __wrap_pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    int ret = mock_type(int); // return status : {0:success | -1:error}
    return ret;
}

/*----------------------------------------------------------------------------*/
int __wrap_pthread_attr_destroy(pthread_attr_t *attr)
{
    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
