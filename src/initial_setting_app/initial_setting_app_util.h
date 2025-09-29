/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef _INITIAL_SETTING_APP_UTIL_H_
#define _INITIAL_SETTING_APP_UTIL_H_

// For UnitTest
#ifdef INITIAL_SETTING_APP_UT
#if defined(__NuttX__)
#include "nuttx/compiler.h"
#include "ut_sched.h"
#endif
#include "ut_mock_std_memory_allocate.h"
#include "ut_mock_std_pthread_h.h"

#undef malloc
#define malloc(__size) mock_malloc(__size)

#undef realloc
#define realloc(__ptr, __size) mock_realloc(__ptr, __size)

#undef calloc
#define calloc(__nmemb, __size) mock_calloc(__nmemb, __size)

#undef free
#define free(__ptr) mock_free(__ptr)

#undef strdup
#define strdup(__ptr) mock_strdup(__ptr)

#undef pthread_exit
#define pthread_exit(retval) mock_pthread_exit(retval)

#define STATIC

#else // INITIAL_SETTING_APP_UT
#define STATIC static

#endif // INITIAL_SETTING_APP_UT

#endif // _INITIAL_SETTING_APP_UTIL_H_
