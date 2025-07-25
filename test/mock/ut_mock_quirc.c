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

#include "quirc.h"

/*----------------------------------------------------------------------------*/
void __wrap_quirc_destroy(struct quirc *q)
{
    check_expected_ptr(q);

    return;
}

/*----------------------------------------------------------------------------*/
struct quirc *__wrap_quirc_new(void)
{
    return mock_type(struct quirc *);
}

/*----------------------------------------------------------------------------*/
int __wrap_quirc_resize(struct quirc *q, int w, int h)
{
    check_expected_ptr(q);
    check_expected(w);
    check_expected(h);

    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
uint8_t *__wrap_quirc_begin(struct quirc *q, int *w, int *h)
{
    check_expected_ptr(q);
    check_expected_ptr(w);
    check_expected_ptr(h);

    return mock_type(uint8_t *);
}

/*----------------------------------------------------------------------------*/
void __wrap_quirc_end(struct quirc *q)
{
    check_expected_ptr(q);

    return;
}

/*----------------------------------------------------------------------------*/
int __wrap_quirc_count(const struct quirc *q)
{
    check_expected_ptr(q);

    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
void __wrap_quirc_extract(const struct quirc *q, int index, struct quirc_code *code)
{
    check_expected_ptr(q);
    check_expected(index);

    *code = *(mock_type(struct quirc_code *));

    return;
}

/*----------------------------------------------------------------------------*/
quirc_decode_error_t __wrap_quirc_decode(const struct quirc_code *code, struct quirc_data *data)
{
    check_expected_ptr(code);

    *data = *(mock_type(struct quirc_data *));

    return mock_type(quirc_decode_error_t);
}

/*----------------------------------------------------------------------------*/
