#pragma once
#include <Windows.h>
#ifndef LOAD64BITDLL_SPEC
#define LOAD64BITDLL_SPEC dllimport
#endif
EXTERN_C __declspec(LOAD64BITDLL_SPEC) UINT64 LoadLibraryW64(LPCWSTR);
EXTERN_C __declspec(LOAD64BITDLL_SPEC) UINT64 LoadLibraryExW64(LPCWSTR, HANDLE, DWORD);
EXTERN_C __declspec(LOAD64BITDLL_SPEC) UINT64 GetProcAddress64(UINT64, LPCSTR);
EXTERN_C __declspec(LOAD64BITDLL_SPEC) BOOL FreeLibrary64(UINT64);
EXTERN_C __declspec(LOAD64BITDLL_SPEC) UINT64 __cdecl X64Call(UINT64 func, int argc, const UINT64 *args);

#ifdef __cplusplus
template <typename RT, typename... Args>
RT Call64(UINT64 func, Args... args)
{
    UINT64 ary[] = { (UINT64)args... };
    auto length = sizeof(ary) / sizeof(*ary);
    return static_cast<RT>(X64Call(func, length, ary));
}
template <typename RT>
RT Call64(UINT64 func)
{
    return static_cast<RT>(X64Call(func, 0, nullptr));
}
#endif
