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

#include <string.h>
#include "mbedtls/sha256.h"

/*----------------------------------------------------------------------------*/
void __wrap_mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
    memcpy(ctx, mock_type(mbedtls_sha256_context *), sizeof(mbedtls_sha256_context));
    return;
}

/*----------------------------------------------------------------------------*/
void __wrap_mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
    check_expected_ptr(ctx);
    return;
}

/*----------------------------------------------------------------------------*/
int __wrap_mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224)
{
    check_expected_ptr(ctx);
    check_expected(is224);

    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
int __wrap_mbedtls_sha256_update(mbedtls_sha256_context *ctx, const unsigned char *input,
                                 size_t ilen)
{
    check_expected_ptr(ctx);
    check_expected_ptr(input);
    check_expected(ilen);

    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
int __wrap_mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char *output)
{
    char *checksum_result = mock_type(char *);

    check_expected_ptr(ctx);

    memcpy(output, checksum_result, strlen(checksum_result) + 1);

    return mock_type(int);
}

/*----------------------------------------------------------------------------*/
