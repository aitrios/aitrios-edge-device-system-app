/*
* SPDX-FileCopyrightText: 2024-2025 Sony Semiconductor Solutions Corporation
*
* SPDX-License-Identifier: Apache-2.0
*/
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "zxing-cpp/src/wrappers/c/zxing-c.h"

zxing_ImageView* __wrap_zxing_ImageView_new(const uint8_t* data, int width, int height,
                                            zxing_ImageFormat format, int rowStride, int pixStride)
{
    return mock_type(zxing_ImageView*);
}

void __wrap_zxing_ImageView_delete(zxing_ImageView* iv)
{
}

zxing_BarcodeFormats __wrap_zxing_BarcodeFormatsFromString(const char* str)
{
    return zxing_BarcodeFormat_None;
}

zxing_BarcodeFormat __wrap_zxing_BarcodeFormatFromString(const char* str)
{
    return zxing_BarcodeFormat_None;
}

char* __wrap_zxing_BarcodeFormatToString(zxing_BarcodeFormat format)
{
    return mock_type(char*);
}

zxing_DecodeHints* __wrap_zxing_DecodeHints_new()
{
    return mock_type(zxing_DecodeHints*);
}

void __wrap_zxing_DecodeHints_delete(zxing_DecodeHints* hints)
{
}

void __wrap_zxing_DecodeHints_setTryHarder(zxing_DecodeHints* hints, bool tryHarder)
{
}

void __wrap_zxing_DecodeHints_setTryRotate(zxing_DecodeHints* hints, bool tryRotate)
{
}

void __wrap_zxing_DecodeHints_setTryInvert(zxing_DecodeHints* hints, bool tryInvert)
{
}

void __wrap_zxing_DecodeHints_setTryDownscale(zxing_DecodeHints* hints, bool tryDownscale)
{
}

void __wrap_zxing_DecodeHints_setIsPure(zxing_DecodeHints* hints, bool isPure)
{
}

void __wrap_zxing_DecodeHints_setReturnErrors(zxing_DecodeHints* hints, bool returnErrors)
{
}

void __wrap_zxing_DecodeHints_setFormats(zxing_DecodeHints* hints, zxing_BarcodeFormats formats)
{
}

void __wrap_zxing_DecodeHints_setBinarizer(zxing_DecodeHints* hints, zxing_Binarizer binarizer)
{
}

void __wrap_zxing_DecodeHints_setEanAddOnSymbol(zxing_DecodeHints* hints,
                                                zxing_EanAddOnSymbol eanAddOnSymbol)
{
}

void __wrap_zxing_DecodeHints_setTextMode(zxing_DecodeHints* hints, zxing_TextMode textMode)
{
}

char* __wrap_zxing_ContentTypeToString(zxing_ContentType type)
{
    return mock_type(char*);
}

bool __wrap_zxing_Result_isValid(const zxing_Result* result)
{
    return mock_type(bool);
}

char* __wrap_zxing_Result_errorMsg(const zxing_Result* result)
{
    return mock_type(char*);
}

zxing_BarcodeFormat __wrap_zxing_Result_format(const zxing_Result* result)
{
    return mock_type(zxing_BarcodeFormat);
}

zxing_ContentType __wrap_zxing_Result_contentType(const zxing_Result* result)
{
    return zxing_ContentType_UnknownECI;
}

uint8_t* __wrap_zxing_Result_bytes(const zxing_Result* result, int* len)
{
    *len = mock_type(int);
    return mock_type(uint8_t*);
}

char* __wrap_zxing_Result_text(const zxing_Result* result)
{
    return mock_type(char*);
}

char* __wrap_zxing_Result_ecLevel(const zxing_Result* result)
{
    return NULL;
}

char* __wrap_zxing_Result_symbologyIdentifier(const zxing_Result* result)
{
    return NULL;
}

int __wrap_zxing_Result_orientation(const zxing_Result* result)
{
    return mock_type(int);
}

bool __wrap_zxing_Result_isInverted(const zxing_Result* result)
{
    return mock_type(bool);
}

bool __wrap_zxing_Result_isMirrored(const zxing_Result* result)
{
    return mock_type(bool);
}

zxing_Result* __wrap_zxing_ReadBarcode(const zxing_ImageView* iv, const zxing_DecodeHints* hints)
{
    return mock_type(zxing_Result*);
}

zxing_Results* __wrap_zxing_ReadBarcodes(const zxing_ImageView* iv, const zxing_DecodeHints* hints)
{
    return NULL;
}

void __wrap_zxing_Result_delete(zxing_Result* result)
{
}

void __wrap_zxing_Results_delete(zxing_Results* results)
{
}

int __wrap_zxing_Results_size(const zxing_Results* results)
{
    return 0;
}

const zxing_Result* __wrap_zxing_Results_at(const zxing_Results* results, int i)
{
    return NULL;
}
