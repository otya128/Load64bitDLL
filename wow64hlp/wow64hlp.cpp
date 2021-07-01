#include "wow64hlp.h"
EXTERN_C_START

#include <pshpack1.h>
struct syscall_entry
{
    BYTE mov_r10_rcx[3];
    BYTE mov_eax_dword[1];
    DWORD dword;
    BYTE test_byte_ptr_byte[3];
    DWORD byte_ptr;
    BYTE byte;
    BYTE jne;
    BYTE jne_rel;
    WORD syscall;
    BYTE ret;
};
struct syscall_entry_hooked
{
    WORD movabs_rax;
    LPVOID addr;
    WORD jmp_rax;
};
#include <poppack.h>

#include <pshpack4.h>
typedef struct _IO_STATUS_BLOCK32 {
    union {
        NTSTATUS Status;
        DWORD Pointer;
    } DUMMYUNIONNAME;
    DWORD Information;
} IO_STATUS_BLOCK32, *PIO_STATUS_BLOCK32;
#include <poppack.h>

static decltype(NtDeviceIoControlFile) *old_NtDeviceIoControlFile;
__kernel_entry NTSTATUS NTAPI hook_NtDeviceIoControlFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength)
{
    if (!IoStatusBlock)
    {
        return old_NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, 0, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
    }
    IO_STATUS_BLOCK32 stat = { };
    IO_STATUS_BLOCK s = { };
    s.Pointer = &stat; /* we expect stack address is 32-bit */
    NTSTATUS as = old_NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, &s, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
    IoStatusBlock->Status = stat.Status;
    IoStatusBlock->Information = stat.Information;
    return as;
}
static NTSTATUS(WINAPI *pLdrRegisterDllNotification)(ULONG, PLDR_DLL_NOTIFICATION_FUNCTION, void *, void **);

static HANDLE ntdll;
static void *hook_syscall(PCSTR func_name, PVOID hook_func)
{
    PVOID result = nullptr;
    ANSI_STRING ansi;
    RtlInitAnsiString(&ansi, func_name);
    PVOID hf;
    if (!NT_SUCCESS(LdrGetProcedureAddress(ntdll, &ansi, 0, &hf)))
    {
        return nullptr;
    }

    syscall_entry *sys = (syscall_entry*)hf;
    if (sys->syscall != 0x050f)
    {
        return nullptr;
    }
    PVOID address = nullptr;
    SIZE_T size = 4096;
    if (!NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess(), &address, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
    {
        return nullptr;
    }
    *(syscall_entry*)((SIZE_T)address + ((SIZE_T)sys & 0xfff)) = *sys;
    result = (decltype(NtDeviceIoControlFile)*)((SIZE_T)address + ((SIZE_T)sys & 0xfff));
    PVOID hook_addr = sys;
    ULONG old = 0;
    if (!NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(), &hook_addr, &size, PAGE_EXECUTE_READWRITE, &old)))
    {
        return nullptr;
    }
    syscall_entry_hooked *hooked = (syscall_entry_hooked*)sys;
    hooked->movabs_rax = 0xb848;
    hooked->jmp_rax = 0xe0ff;
    hooked->addr = hook_NtDeviceIoControlFile;
    NtProtectVirtualMemory(reinterpret_cast<HANDLE>(-1), &hook_addr, &size, old, &old);
    return result;
}

EXCEPTION_DISPOSITION(__cdecl *ntdll___C_specific_handler)(
    _In_    struct _EXCEPTION_RECORD*   ExceptionRecord,
    _In_    void*                       EstablisherFrame,
    _Inout_ struct _CONTEXT*            ContextRecord,
    _Inout_ struct _DISPATCHER_CONTEXT* DispatcherContext);

EXCEPTION_DISPOSITION __cdecl __C_specific_handler(
    _In_    struct _EXCEPTION_RECORD*   ExceptionRecord,
    _In_    void*                       EstablisherFrame,
    _Inout_ struct _CONTEXT*            ContextRecord,
    _Inout_ struct _DISPATCHER_CONTEXT* DispatcherContext)
{
    if (!ntdll___C_specific_handler)
    {
        ANSI_STRING hndlr;
        RtlInitAnsiString(&hndlr, "__C_specific_handler");
        LdrGetProcedureAddress(ntdll, &hndlr, 0, (PVOID*)&ntdll___C_specific_handler);
    }
    return ntdll___C_specific_handler(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
}

void dprintf(const char *fmt, ...)
{
    va_list arg;
    va_start(arg, fmt);
    vDbgPrintEx(101/* DPFLTR_DEFAULT_ID */, 3/* DPFLTR_INFO_LEVEL */, fmt, arg);
    va_end(arg);
    return;
}

void init_threads(void)
{
    DPRINTF("wow64hlp: init_threads\n");
    SYSTEM_PROCESS_INFORMATION sys_info_stack;
    ULONG len = 0;
    ULONG sys_info_len = sizeof(sys_info_stack);
    PSYSTEM_PROCESS_INFORMATION sys_info = &sys_info_stack;
    NTSTATUS result = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x39/* SystemExtendedProcessInformation */, (PVOID)sys_info, sys_info_len, &len);
    sys_info_len = len;
    sys_info = (PSYSTEM_PROCESS_INFORMATION)RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sys_info_len);
    while (TRUE)
    {
        NTSTATUS result = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x39, (PVOID)sys_info, sys_info_len, &len);
        if (result == STATUS_INFO_LENGTH_MISMATCH)
        {
            sys_info_len = len + 1000;
            sys_info = (PSYSTEM_PROCESS_INFORMATION)RtlReAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, (PVOID)sys_info, sys_info_len);
        }
        else
            break;
    }
    PSYSTEM_PROCESS_INFORMATION cur = sys_info;
    HANDLE pid = ((CLIENT_ID*)((LPBYTE)NtCurrentTeb() + 0x40 /* ClientId */))->UniqueProcess;
    while (cur - sys_info < len)
    {
        PSYSTEM_EXTENDED_THREAD_INFORMATION threads = (PSYSTEM_EXTENDED_THREAD_INFORMATION)(cur + 1);
        if (cur->UniqueProcessId == pid)
        {
            for (ULONG i = 0; i < cur->NumberOfThreads; i++)
            {
                RtlpInitializeThreadActivationContextStack((PTEB)threads[i].TebBase);
                LdrpInitializeTls((PTEB)threads[i].TebBase);
            }
            break;
        }
        if (cur->NextEntryOffset == 0)
            break;
        cur = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)cur + cur->NextEntryOffset);
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, sys_info);
}

__declspec(dllexport) BOOL Wow64Helper(void)
{
    UNICODE_STRING uni;
    RtlInitUnicodeString(&uni, L"ntdll.dll");
    if (!NT_SUCCESS(LdrGetDllHandle(nullptr, 0, &uni, &ntdll)))
    {
        return false;
    }
    ANSI_STRING proc_name;
    RtlInitAnsiString(&proc_name, "LdrRegisterDllNotification");
    if (!NT_SUCCESS(LdrGetProcedureAddress(ntdll, &proc_name, 0, (void**)&pLdrRegisterDllNotification)))
    {
        return false;
    }
    void *cookie;
    if (!NT_SUCCESS(pLdrRegisterDllNotification(0, ldr_notify_callback, NULL, &cookie)))
    {
        return false;
    }
    init_threads();
    old_NtDeviceIoControlFile = (decltype(NtDeviceIoControlFile)*)hook_syscall("NtDeviceIoControlFile", (PVOID)hook_NtDeviceIoControlFile);
    InstallGdiHack();
    return true;
}

LPVOID ImageBase;
// DLL_PROCESS_ATTACH/DLL_PROCESS_DETACH => called
// DLL_THREAD_ATTACH/DLL_THREAD_DETACH => not called
__declspec(dllexport) BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ImageBase = (LPVOID)hModule;
        break;
    case DLL_THREAD_ATTACH:
        LdrpInitializeThread(nullptr);
        break;
    case DLL_THREAD_DETACH:
        LdrShutdownThread();
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

EXTERN_C_END
