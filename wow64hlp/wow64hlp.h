#pragma once
#define WIN32_NO_STATUS
#include <Windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

EXTERN_C_START

typedef struct _RTL_BITMAP
{
    ULONG  SizeOfBitMap;
    PULONG  Buffer;
} RTL_BITMAP, *PRTL_BITMAP;

typedef BOOLEAN
(NTAPI *PDLL_INIT_ROUTINE)(
    _In_ PVOID DllHandle,
    _In_ ULONG Reason,
    _In_opt_ PCONTEXT Context
    );

typedef struct
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG64 SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union {
        UCHAR FlagGroup[4];
        ULONG Flags;
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    PVOID Spare;
    PVOID Lock;
    /*LDR_DDAG_NODE **/void *DdagNode;
    LIST_ENTRY NodeModuleLink;

    /*LDRP_LOAD_CONTEXT **/void *LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    //...
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;
_STATIC_ASSERT(FIELD_OFFSET(LDR_DATA_TABLE_ENTRY64, EntryPointActivationContext) == 0x88);

typedef struct {
    ULONG Length;
    BOOLEAN Initialized;
    ULONGLONG SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    ULONGLONG EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA64;
_STATIC_ASSERT(FIELD_OFFSET(PEB_LDR_DATA64, InLoadOrderModuleList) == 0x10);

NTSYSAPI PVOID NTAPI RtlAllocateHeap(
    PVOID  HeapHandle,
    ULONG  Flags,
    SIZE_T Size
);

NTSYSAPI PVOID NTAPI RtlReAllocateHeap(
    PVOID  HeapHandle,
    ULONG  Flags,
    PVOID Ptr,
    SIZE_T Size
);

NTSYSAPI BOOLEAN NTAPI RtlFreeHeap(
    PVOID HeapHandle,
    ULONG Flags,
    PVOID HeapBase
);

#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)
#define RtlGetProcessHeap() (*(PVOID*)((LPBYTE)NtCurrentPeb() + 0x30))

#define InitializeListHead(ListHead) (\
     (ListHead)->Flink = (ListHead)->Blink = (ListHead))

#define InsertTailList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Blink = _EX_ListHead->Blink;\
    (Entry)->Flink = _EX_ListHead;\
    (Entry)->Blink = _EX_Blink;\
    _EX_Blink->Flink = (Entry);\
    _EX_ListHead->Blink = (Entry);\
    }

NTSYSAPI PVOID NTAPI RtlImageDirectoryEntryToData(
    PVOID   Base,
    BOOLEAN MappedAsImage,
    USHORT  DirectoryEntry,
    PULONG  Size
);

typedef struct _THREAD_TLS_INFORMATION
{
    ULONG Flags;
    PVOID NewTlsData;
    HANDLE ThreadId;
} THREAD_TLS_INFORMATION, *PTHREAD_TLS_INFORMATION;

typedef enum _PROCESS_TLS_INFORMATION_TYPE
{
    ProcessTlsReplaceIndex,
    ProcessTlsReplaceVector,
    MaxProcessTlsOperation
} PROCESS_TLS_INFORMATION_TYPE, *PPROCESS_TLS_INFORMATION_TYPE;

typedef struct _PROCESS_TLS_INFORMATION
{
    ULONG Flags;
    ULONG OperationType;
    ULONG ThreadDataCount;
    ULONG TlsIndex;
    THREAD_TLS_INFORMATION ThreadData[1];
} PROCESS_TLS_INFORMATION, *PPROCESS_TLS_INFORMATION;

NTSYSAPI NTSTATUS NTAPI RtlEnterCriticalSection(RTL_CRITICAL_SECTION* crit);
NTSYSAPI NTSTATUS NTAPI RtlLeaveCriticalSection(RTL_CRITICAL_SECTION* crit);

NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
);
#define NtCurrentProcess()                      ((HANDLE)(LONG_PTR)-1)
#undef RtlCopyMemory
void* NTAPI RtlCopyMemory(
    _Out_writes_bytes_all_(_Size) void* _Dst,
    _In_reads_bytes_(_Size)       void const* _Src,
    _In_                          size_t      _Size
);
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA
{
    ULONG Flags;
    PCUNICODE_STRING FullDllName;
    PCUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA
{
    ULONG Flags;
    PCUNICODE_STRING FullDllName;
    PCUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA
{
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

#define LDR_DLL_NOTIFICATION_REASON_LOADED 1
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED 2

typedef void (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(ULONG, LDR_DLL_NOTIFICATION_DATA*, void*);

NTSYSAPI BOOLEAN NTAPI RtlEqualUnicodeString(
    PCUNICODE_STRING String1,
    PCUNICODE_STRING String2,
    BOOLEAN          CaseInSensitive
);

NTSYSCALLAPI NTSTATUS NTAPI NtProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID *BaseAddress,
    _In_ SIZE_T *NumberOfBytesToProtect,
    _In_ ULONG NewAccessProtection,
    _Out_ PULONG OldAccessProtection
);

__kernel_entry NTSYSCALLAPI NTSTATUS NTAPI NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ _Outptr_result_buffer_(*RegionSize) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);


NTSYSAPI NTSTATUS NTAPI LdrGetDllHandle(
    _In_opt_ PWSTR DllPath,
    _In_ PULONG DllCharacteristics,
    _In_ PUNICODE_STRING DllName,
    _Out_ PVOID *DllHandle
);

NTSYSAPI NTSTATUS NTAPI LdrGetProcedureAddress(
    _In_ PVOID BaseAddress,
    _In_ PANSI_STRING Name,
    _In_ ULONG Ordinal,
    _Out_ PVOID *ProcedureAddress
);

DWORD NTAPI NtGetTickCount(VOID);

NTSYSAPI ULONG NTAPI vDbgPrintEx(
    ULONG   ComponentId,
    ULONG   Level,
    PCCH    Format,
    va_list arglist
);

#undef RtlZeroMemory
PVOID NTAPI RtlZeroMemory(PVOID, SIZE_T);
VOID NTAPI RtlActivateActivationContextUnsafeFast(PVOID, PVOID);
VOID NTAPI RtlDeactivateActivationContextUnsafeFast(PVOID);

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
    SYSTEM_THREAD_INFORMATION ThreadInfo;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID Win32StartAddress;
    PVOID TebBase;
    ULONG_PTR Reserved2;
    ULONG_PTR Reserved3;
    ULONG_PTR Reserved4;
} SYSTEM_EXTENDED_THREAD_INFORMATION, *PSYSTEM_EXTENDED_THREAD_INFORMATION;

void NTAPI RtlpInitializeThreadActivationContextStack(PTEB teb);
void CALLBACK ldr_notify_callback(ULONG reason, LDR_DLL_NOTIFICATION_DATA *data, void *context);
NTSTATUS NTAPI LdrpInitializeTls(PTEB Teb);
VOID NTAPI LdrpInitializeThread(PCONTEXT/* arg1, arg2, arg3, arg4 */);
VOID NTAPI LdrShutdownThread(VOID);
NTSTATUS NTAPI LdrpHandleTlsData(LDR_DATA_TABLE_ENTRY64 *entry);

extern PVOID ImageBase;

void dprintf(const char *fmt, ...);
#define DPRINTF(...)

#define _SEH2_TRY __try
#define _SEH2_EXCEPT __except
#define _SEH2_END
EXTERN_C_END
