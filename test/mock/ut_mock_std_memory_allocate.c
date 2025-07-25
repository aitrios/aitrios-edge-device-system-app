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

#include <stdlib.h>
#include <string.h>
#include "ut_mock_std_memory_allocate.h"

/*----------------------------------------------------------------------------*/
void *mock_malloc(size_t __size)
{
    void *ret = NULL;

    // Is check parameter
    if (mock_type(bool) == true) {
        check_expected(__size);
    }

    // Is exec malloc
    if (mock_type(bool) == true) {
        ret = malloc(__size);
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
void *mock_realloc(void *__ptr, size_t __size)
{
    void *ret = NULL;

    // Is check parameter
    if (mock_type(bool) == true) {
        check_expected_ptr(__ptr);
        check_expected(__size);
    }

    // Is exec realloc
    if (mock_type(bool) == true) {
        ret = realloc(__ptr, __size);
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
void *mock_calloc(size_t __nmemb, size_t __size)
{
    void *ret = NULL;

    // Is check parameter
    if (mock_type(bool) == true) {
        check_expected(__nmemb);
        check_expected(__size);
    }

    // Is exec calloc
    if (mock_type(bool) == true) {
        ret = calloc(__nmemb, __size);
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
void mock_free(void *__ptr)
{
    // Is check parameter
    if (mock_type(bool) == true) {
        check_expected_ptr(__ptr);
    }

    free(__ptr);

    return;
}

/*----------------------------------------------------------------------------*/
void *mock_strdup(const char *__ptr)
{
    void *ret = NULL;

    // Is check parameter
    if (mock_type(bool) == true) {
        check_expected(__ptr);
    }

    // Is exec strdup
    if (mock_type(bool) == true) {
        ret = strdup(__ptr);
    }

    return ret;
}

/*----------------------------------------------------------------------------*/
