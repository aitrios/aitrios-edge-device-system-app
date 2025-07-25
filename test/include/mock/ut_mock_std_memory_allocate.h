/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef _UT_MOCK_STD_MEMORY_ALLOCATE_H_
#define _UT_MOCK_STD_MEMORY_ALLOCATE_H_

void *mock_malloc(size_t __size);
void *mock_realloc(void *__ptr, size_t __size);
void *mock_calloc(size_t __nmemb, size_t __size);
void mock_free(void *__ptr);
void *mock_strdup(const char *__ptr);

#endif  // _UT_MOCK_STD_MEMORY_ALLOCATE_H_
