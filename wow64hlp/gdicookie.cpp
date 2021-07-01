#include "wow64hlp.h"
EXTERN_C_START
/*
 GDI Cookie Hack
Windows build 21354
32.9: kd:x86> dt win32k!_W32PROCESS 0xffffd70f`41d6dac0
   +0x000 Process          : 0xffff808c`5dbd0080 _EPROCESS
   +0x008 RefCount         : 1
   +0x00c W32PF_Flags      : 0x4080001
   +0x010 InputIdleEvent   : 0xffffffff`ffffffff _KEVENT
   +0x018 StartCursorHideTime : 0
   +0x020 NextStart        : (null)
   +0x028 pDCAttrList      : (null)
   +0x030 pBrushAttrList   : (null)
   +0x038 W32Pid           : 0
   +0x03c GDIHandleCount   : 0n0
   +0x040 GDIHandleCountPeak : 0
   +0x044 UserHandleCount  : 0n0
   +0x048 UserHandleCountPeak : 0
   +0x050 GDIPushLock      : _EX_PUSH_LOCK
   +0x058 GDIEngUserMemAllocTable : _RTL_AVL_TABLE
   +0x0c0 GDIDcAttrFreeList : _LIST_ENTRY [ 0x0 - 0x0 ]
   +0x0d0 GDIBrushAttrFreeList : _LIST_ENTRY [ 0x0 - 0x0 ]
   +0x0e0 GDIW32PIDLockedBitmaps : _LIST_ENTRY [ 0x41d6dba0 - 0xffffd70f ]
   +0x0f0 hSecureGdiSharedHandleTable : (null)
   +0x0f8 DxProcess        : (null)
   +0x100 DCompositionProcess : (null)
   +0x108 UMPDSandboxingEnabled : 0
   +0x110 pWakeReference   : (null)
   +0x118 defaultDpiContext : 0
   +0x11c Dpi              : 0
   +0x120 bChangedGdiGammaRamp : 0y0
  ~+0x124 GdiInitializeCalloutExecuted : 1~ <= removed?
--Windows 10 1803
   +0x120 bReadScreenBits  : 0y0
   +0x120 bWroteScreenBits : 0y0
--Windows 10 21H1
   +0x124 Cookie           : 0x1d1300c <= new!!!!!!
--Windows build 21354
*/

#include <pshpack1.h>
struct GDI_TABLE_ENTRY
{
    DWORD64 KernelAddress;
    USHORT Misc[4];
    DWORD64 UserAddress;
};
#include <poppack.h>
GDI_TABLE_ENTRY *pGdiSharedHandleTable;
DWORD gMaxGdiHandleCount;
DWORD gCookie;

DWORD64 DecodeCookie64(DWORD64 EncodedPointer, DWORD Cookie)
{
    auto Rot = 0x40 - (Cookie & 0x3f);
    return _rotr64(EncodedPointer, Rot) ^ (DWORD64)Cookie;
}

DWORD DecodeCookie32(DWORD EncodedPointer, DWORD Cookie)
{
    auto Rot = 0x20 - (Cookie & 0x1f);
    return _rotr(EncodedPointer, Rot) ^ Cookie;
}

DWORD64 EncodeCookie64(DWORD64 Pointer, DWORD Cookie)
{
    auto Rot = 0x40 - (Cookie & 0x3f);
    return _rotl64(Pointer ^ (DWORD64)Cookie, Rot);
}

DWORD64 EncodeCookie32(DWORD Pointer, DWORD Cookie)
{
    auto Rot = 0x20 - (Cookie & 0x1f);
    return _rotl(Pointer ^ Cookie, Rot);
}

struct CACHED_HANDLE_ENTRY
{
    DWORD64 EncodedUserAddress;
    DWORD64 DecodedUserAddress;
    DWORD HandleIndex;
};
int GdiHandleCacheCount;
CACHED_HANDLE_ENTRY GdiHandleCahce[65536];

VOID PrepareGdiHandleCahce(VOID)
{
    GdiHandleCacheCount = 0;
    for (DWORD i = 0; i < 65536; i++)
    {
        if (!pGdiSharedHandleTable[i].UserAddress)
            continue;
        auto Decoded64 = DecodeCookie64(pGdiSharedHandleTable[i].UserAddress, gCookie); // invalid on WOW64
        GdiHandleCahce[GdiHandleCacheCount++] = { pGdiSharedHandleTable[i].UserAddress, Decoded64, i };
    }
}

// find handle table
BOOL GdiHackFixContextReg2(PVOID addr, PDWORD64 pReg, PCSTR name, SIZE_T AllowDisp)
{
    if (!*pReg)
        return FALSE;
    for (int i = 0; i < GdiHandleCacheCount; i++)
    {
        auto Decoded64 = GdiHandleCahce[i].DecodedUserAddress;
        //DPRINTF("GdiHackFixContextReg2(%s) entry:%i reg:%p handle addr:%p decoded:%p\n", name, i, *pReg, GdiHandleCacheCount[i].EncodedUserAddress, Decoded64);
        if (*pReg < Decoded64)
            continue;
        auto Decoded32 = DecodeCookie32((DWORD)GdiHandleCahce[i].EncodedUserAddress, gCookie); // valid on WOW64
        auto Disp = *pReg - Decoded64;
        if (Disp > AllowDisp)
            continue;
        DPRINTF("GdiHackFixContextReg2: Handle:%08x Reg %s %p->%p\n", GdiHandleCahce[i].HandleIndex, name, *pReg, Decoded32 + Disp);
        *pReg = Decoded32 + Disp;
        return TRUE;
    }
    return FALSE;
}

// heuristic
BOOL GdiHackFixContextReg1(PVOID Addr, PDWORD64 pReg, LPCSTR RegName, SIZE_T AllowDisp)
{
    // Addr is not valid...
#if 0
    auto diff = (DWORD64)Addr > *pReg ? (DWORD64)Addr - *pReg : *pReg - (DWORD64)Addr;
    if (diff > AllowDisp)
    {
        return FALSE;
    }
#endif
    auto Encoded64 = EncodeCookie64(*pReg, gCookie);
    if (!Encoded64)
    {
        return FALSE;
    }
    if (Encoded64 & 0xffffffff00000000)
    {
        return FALSE;
    }
    auto aa = DecodeCookie32((DWORD)Encoded64, gCookie);
    DPRINTF("GdiHackFixContextReg1: reg %s %p->%p\n", RegName, *pReg, aa);
    *pReg = aa;
    return TRUE;
}

PVOID hGdi32;
PVOID hGdi32Full;
VOID GetGdiCookie(VOID)
{
    UNICODE_STRING uni;
    RtlInitUnicodeString(&uni, L"gdi32.dll");
    if (!NT_SUCCESS(LdrGetDllHandle(nullptr, 0, &uni, &hGdi32)))
    {
        return;
    }
    ANSI_STRING proc_name;
    RtlInitAnsiString(&proc_name, "gCookie");
    LPDWORD gpCookie;
    if (!NT_SUCCESS(LdrGetProcedureAddress(hGdi32, &proc_name, 0, (void**)&gpCookie)))
    {
        return;
    }
    gCookie = *gpCookie;
    GDI_TABLE_ENTRY **ppGdiSharedHandleTable;
    RtlInitAnsiString(&proc_name, "pGdiSharedHandleTable");
    if (!NT_SUCCESS(LdrGetProcedureAddress(hGdi32, &proc_name, 0, (void**)&ppGdiSharedHandleTable)))
    {
        return;
    }
    pGdiSharedHandleTable = *ppGdiSharedHandleTable;
    LPDWORD gpMaxGdiHandleCount;
    RtlInitAnsiString(&proc_name, "gMaxGdiHandleCount");
    if (!NT_SUCCESS(LdrGetProcedureAddress(hGdi32, &proc_name, 0, (void**)&gpMaxGdiHandleCount)))
    {
        return;
    }
    gMaxGdiHandleCount = *gpMaxGdiHandleCount;
    RtlInitUnicodeString(&uni, L"gdi32full.dll");
    if (!NT_SUCCESS(LdrGetDllHandle(nullptr, 0, &uni, &hGdi32Full)))
    {
        return;
    }
}

RTL_CRITICAL_SECTION_DEBUG GdiHandleLockDebug;
RTL_CRITICAL_SECTION GdiHandleLock =
{
    &GdiHandleLockDebug,
    -1,
    0,
    0,
    0,
    0
};

LONG NTAPI GdiHackExceptHandler(EXCEPTION_POINTERS *ExceptionInfo)
{
    PVOID base;
    if (!RtlPcToFileHeader(ExceptionInfo->ExceptionRecord->ExceptionAddress, &base))
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (!pGdiSharedHandleTable)
    {
        GetGdiCookie();
        if (!pGdiSharedHandleTable)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }
    if (base != hGdi32 && base != hGdi32Full)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
    {
        auto addr = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
        BOOL fixed = FALSE;
        SIZE_T Disp = 0x200;
        RtlEnterCriticalSection(&GdiHandleLock);
        DPRINTF("gMaxGdiHandleCount=%d gCookie=%08x pGdiSharedHandleTable=%p\n", gMaxGdiHandleCount, gCookie, pGdiSharedHandleTable);
        PrepareGdiHandleCahce();
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->Rax, "RAX", Disp);
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->Rcx, "RCX", Disp);
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->Rdx, "RDX", Disp);
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->Rbx, "RBX", Disp);
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->Rbp, "RBP", Disp);
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->Rsi, "RSI", Disp);
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->Rdi, "RDI", Disp);
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->R8, "R8", Disp);
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->R9, "R9", Disp);
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->R10, "R10", Disp);
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->R11, "R11", Disp);
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->R12, "R12", Disp);
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->R13, "R13", Disp);
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->R14, "R14", Disp);
        fixed |= GdiHackFixContextReg2(addr, &ExceptionInfo->ContextRecord->R15, "R15", Disp);
        RtlLeaveCriticalSection(&GdiHandleLock);
        if (fixed)
            return EXCEPTION_CONTINUE_EXECUTION;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    else
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

VOID InstallGdiHack(VOID)
{
    RtlAddVectoredExceptionHandler(0, GdiHackExceptHandler);
}
EXTERN_C_END
