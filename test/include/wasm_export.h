/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _WASM_EXPORT_H
#define _WASM_EXPORT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NativeSymbol {
  int dummy;
} NativeSymbol;

/* Dummy for Unittest */
struct WASMExecEnv;
typedef struct WASMExecEnv *wasm_exec_env_t;

#ifdef __cplusplus
}
#endif

#endif /* end of _WASM_EXPORT_H */
