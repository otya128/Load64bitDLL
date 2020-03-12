#include "wow64hlp.h"
EXTERN_C_START
#include "ntdllp.h"
NTSTATUS NTAPI LdrpAllocateTlsEntry(LDR_DATA_TABLE_ENTRY64 *LdrEntry, PLDRP_TLS_DATA *pTlsData);
#define DPRINT1(...)
RTL_BITMAP TlsBitMap;
RTL_BITMAP TlsExpansionBitMap;
RTL_BITMAP FlsBitMap;
BOOLEAN LdrpImageHasTls;
LIST_ENTRY LdrpTlsList;
ULONG LdrpNumberOfTlsEntries;
ULONG LdrpNumberOfProcessors;
PVOID NtDllBase;
extern LARGE_INTEGER RtlpTimeout;
BOOLEAN RtlpTimeoutDisable;
PVOID LdrpHeap;
LIST_ENTRY LdrpHashTable[LDR_HASH_TABLE_ENTRIES];
LIST_ENTRY LdrpDllNotificationList;
HANDLE LdrpKnownDllObjectDirectory;
UNICODE_STRING LdrpKnownDllPath;
WCHAR LdrpKnownDllPathBuffer[128];
UNICODE_STRING LdrpDefaultPath;

LONG LdrpActiveThreadCount;

PRTL_CRITICAL_SECTION pLdrpLoaderLock;
RTL_CRITICAL_SECTION FastPebLock;

BOOLEAN ShowSnaps;

ULONG LdrpFatalHardErrorCount;
ULONG LdrpActiveUnloadCount;

//Add TLS entry
NTSTATUS NTAPI LdrpHandleTlsData(LDR_DATA_TABLE_ENTRY64 *entry)
{
    PLDRP_TLS_DATA TlsData = NULL;
    NTSTATUS Status;
    PROCESS_TLS_INFORMATION *TlsInfo;
    LdrpAllocateTlsEntry(entry, &TlsData);
    if (!TlsData)
        return STATUS_SUCCESS;

    SIZE_T TlsDataSize = TlsData->TlsDirectory.EndAddressOfRawData - TlsData->TlsDirectory.StartAddressOfRawData;

    DPRINTF("LdrpHandleTlsData %p %S %d\n", TlsDataSize, entry->FullDllName.Buffer, TlsData->TlsDirectory.Characteristics);
    //FIXME: leak old TLS
    ULONG Size = sizeof(PROCESS_TLS_INFORMATION) + sizeof(THREAD_TLS_INFORMATION) * (LdrpActiveThreadCount - 1);
    TlsInfo = (PROCESS_TLS_INFORMATION*)RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    TlsInfo->OperationType = ProcessTlsReplaceVector;
    TlsInfo->ThreadDataCount = LdrpActiveThreadCount;
    TlsInfo->TlsIndex = TlsData->TlsDirectory.Characteristics;
    for (int i = 0; i < LdrpActiveThreadCount; i++)
    {
        PVOID NewTlsData = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, TlsDataSize);
        PVOID *NewTlsVector = (PVOID*)RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, (TlsInfo->TlsIndex + 1) * sizeof(PVOID));
        NewTlsVector[TlsInfo->TlsIndex] = NewTlsData;
        TlsInfo->ThreadData[i].NewTlsData = NewTlsVector;
        if (TlsInfo->ThreadData[i].NewTlsData)
        {
            /* Copy the data */
            RtlCopyMemory(NewTlsData, (PVOID)TlsData->TlsDirectory.StartAddressOfRawData, TlsDataSize);
        }
    }
    Status = NtSetInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS)35/* ProcessTlsInformation */, TlsInfo, Size);
    RtlFreeHeap(RtlGetProcessHeap(), 0, TlsInfo);
    return Status;
}

PDLL_INIT_ROUTINE old_KernelBaseDllMain;
BOOL APIENTRY hook_KernelBaseDllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    PRTL_USER_PROCESS_PARAMETERS pbp = NtCurrentPeb()->ProcessParameters;
    PIMAGE_DOS_HEADER ImageBaseAddress = *(PIMAGE_DOS_HEADER*)((PBYTE)NtCurrentPeb() + 0x10);//ImageBaseAddress
    ULONG old;
    SIZE_T size = sizeof(WORD);
    BOOL success = FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)ImageBaseAddress + ImageBaseAddress->e_lfanew);
    PWORD psubsystem = &nt->OptionalHeader.Subsystem;
    WORD subsystem = nt->OptionalHeader.Subsystem;
    if (subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI && NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(), (PVOID*)&psubsystem, &size, PAGE_EXECUTE_READWRITE, &old)))
    {
        success = TRUE;
        nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    }
    HANDLE stdin = pbp->Reserved2[2];
    HANDLE stdout = pbp->Reserved2[3];
    HANDLE stderr = pbp->Reserved2[4];
    pbp->Reserved2[2] = INVALID_HANDLE_VALUE;
    pbp->Reserved2[3] = INVALID_HANDLE_VALUE;
    pbp->Reserved2[4] = INVALID_HANDLE_VALUE;
    old_KernelBaseDllMain(hModule, ul_reason_for_call, (PCONTEXT)lpReserved);
    pbp->Reserved2[2] = stdin;
    pbp->Reserved2[3] = stdout;
    pbp->Reserved2[4] = stderr;

    if (success)
    {
        nt->OptionalHeader.Subsystem = subsystem;
        NtProtectVirtualMemory(reinterpret_cast<HANDLE>(-1), (PVOID*)&psubsystem, &size, old, &old);
    }
    return TRUE;
}

void CALLBACK ldr_notify_callback(ULONG reason, LDR_DLL_NOTIFICATION_DATA *data, void *context)
{
    UNICODE_STRING kernelbase;
    BOOL load_kernelbase;
    RtlInitUnicodeString(&kernelbase, L"KernelBase.dll");
    load_kernelbase = RtlEqualUnicodeString(data->Loaded.BaseDllName, &kernelbase, TRUE);
    if (reason == LDR_DLL_NOTIFICATION_REASON_LOADED)
    {
        PLIST_ENTRY NextEntry, ListHead;
        LDR_DATA_TABLE_ENTRY64 *LdrEntry;
        ListHead = &((PEB_LDR_DATA64*)(NtCurrentPeb()->Ldr))->InLoadOrderModuleList;
        NextEntry = ListHead->Flink;
        while (ListHead != NextEntry)
        {
            LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);
            if (load_kernelbase && RtlEqualUnicodeString(&LdrEntry->BaseDllName, &kernelbase, TRUE))
            {
                old_KernelBaseDllMain = (PDLL_INIT_ROUTINE)LdrEntry->EntryPoint;
                LdrEntry->EntryPoint = hook_KernelBaseDllMain;
            }
            if (LdrEntry->DllBase == data->Loaded.DllBase)
            {
                LdrpHandleTlsData(LdrEntry);
                break;
            }
            NextEntry = NextEntry->Flink;
        }

    }
    return;
}

NTSTATUS NTAPI LdrpAllocateTlsEntry(LDR_DATA_TABLE_ENTRY64 *LdrEntry, PLDRP_TLS_DATA *pTlsData)
{
    PIMAGE_TLS_DIRECTORY TlsDirectory;
    ULONG Size;
    PLDRP_TLS_DATA TlsData;
    if (pTlsData)
        *pTlsData = NULL;
    /* Get the TLS directory */
    TlsDirectory = (PIMAGE_TLS_DIRECTORY)RtlImageDirectoryEntryToData(LdrEntry->DllBase,
        TRUE,
        IMAGE_DIRECTORY_ENTRY_TLS,
        &Size);

    /* Check if we have a directory */
    if (!TlsDirectory) return STATUS_SUCCESS;

    /* Check if the image has TLS */
    if (!LdrpImageHasTls) LdrpImageHasTls = TRUE;

    /* Show debug message */
    if (ShowSnaps)
    {
        DPRINT1("LDR: Tls Found in %wZ at %p\n",
            &LdrEntry->BaseDllName,
            TlsDirectory);
    }

    /* Allocate an entry */
    TlsData = (PLDRP_TLS_DATA)RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(LDRP_TLS_DATA));
    if (!TlsData) return STATUS_NO_MEMORY;

    /* Mark it for TLS Usage */
    LdrEntry->TlsIndex = -1;

    /* Save the cached TLS data */
    TlsData->TlsDirectory = *TlsDirectory;
    InsertTailList(&LdrpTlsList, &TlsData->TlsLinks);

    /* Update the index */
    *(PLONG)TlsData->TlsDirectory.AddressOfIndex = LdrpNumberOfTlsEntries;
    TlsData->TlsDirectory.Characteristics = LdrpNumberOfTlsEntries++;
    if (pTlsData)
        *pTlsData = TlsData;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI LdrpInitializeTls(PTEB Teb)
{
    PLIST_ENTRY NextEntry, ListHead;
    LDR_DATA_TABLE_ENTRY64 *LdrEntry;
    NTSTATUS Status;
    DPRINTF("init TLS %p %d\n", Teb, LdrpNumberOfTlsEntries);

    /* Initialize the TLS List */
    InitializeListHead(&LdrpTlsList);

    /* Loop all the modules */
    ListHead = &((PEB_LDR_DATA64*)(NtCurrentPeb()->Ldr))->InLoadOrderModuleList;
    NextEntry = ListHead->Flink;
    while (ListHead != NextEntry)
    {
        /* Get the entry */
        LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);
        NextEntry = NextEntry->Flink;
        Status = LdrpAllocateTlsEntry(LdrEntry, NULL);
        if (NT_ERROR(Status))
            return Status;
    }

    /* Done setting up TLS, allocate entries */
    return LdrpAllocateTls(Teb);
}

NTSTATUS NTAPI LdrpAllocateTls(PTEB Teb)
{
    PLIST_ENTRY NextEntry, ListHead;
    PLDRP_TLS_DATA TlsData;
    SIZE_T TlsDataSize;
    PVOID *TlsVector;

    _InterlockedIncrement(&LdrpActiveThreadCount);
    /* Check if we have any entries */
    if (!LdrpNumberOfTlsEntries)
    {
        /*Teb->ThreadLocalStoragePointer*/*(LPVOID*)((LPBYTE)Teb + 0x58) = (LPVOID)((LPBYTE)Teb + 0x58);
        return STATUS_SUCCESS;
    }
    /* Allocate the vector array */
    TlsVector = (PVOID*)RtlAllocateHeap(RtlGetProcessHeap(),
        0,
        LdrpNumberOfTlsEntries * sizeof(PVOID));
    if (!TlsVector) return STATUS_NO_MEMORY;
    /*Teb->ThreadLocalStoragePointer*/*(LPVOID*)((LPBYTE)Teb + 0x58) = TlsVector;

    /* Loop the TLS Array */
    ListHead = &LdrpTlsList;
    NextEntry = ListHead->Flink;
    while (NextEntry != ListHead)
    {
        /* Get the entry */
        TlsData = CONTAINING_RECORD(NextEntry, LDRP_TLS_DATA, TlsLinks);
        NextEntry = NextEntry->Flink;

        /* Allocate this vector */
        TlsDataSize = TlsData->TlsDirectory.EndAddressOfRawData -
            TlsData->TlsDirectory.StartAddressOfRawData;
        TlsVector[TlsData->TlsDirectory.Characteristics] = RtlAllocateHeap(RtlGetProcessHeap(),
            0,
            TlsDataSize);
        if (!TlsVector[TlsData->TlsDirectory.Characteristics])
        {
            /* Out of memory */
            return STATUS_NO_MEMORY;
        }

        /* Show debug message */
        if (ShowSnaps)
        {
            DPRINT1("LDR: TlsVector %p Index %lu = %p copied from %x to %p\n",
                TlsVector,
                TlsData->TlsDirectory.Characteristics,
                &TlsVector[TlsData->TlsDirectory.Characteristics],
                TlsData->TlsDirectory.StartAddressOfRawData,
                TlsVector[TlsData->TlsDirectory.Characteristics]);
        }

        /* Copy the data */
        RtlCopyMemory(TlsVector[TlsData->TlsDirectory.Characteristics],
            (PVOID)TlsData->TlsDirectory.StartAddressOfRawData,
            TlsDataSize);
    }

    /* Done */
    return STATUS_SUCCESS;
}


/*
    [+0x000] ActiveFrame      : 0x0 [Type: _RTL_ACTIVATION_CONTEXT_STACK_FRAME *]
    [+0x008] FrameListCache   [Type: _LIST_ENTRY]
    [+0x018] Flags            : 0x2 [Type: unsigned long]
    [+0x01c] NextCookieSequenceNumber : 0x1 [Type: unsigned long]
    [+0x020] StackId          : tickcount [Type: unsigned long]
*/
#include <pshpack4.h>
typedef PVOID PACTIVATION_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK
{
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

typedef struct _RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED
{
    SIZE_T Size;
    ULONG Format;
    RTL_ACTIVATION_CONTEXT_STACK_FRAME Frame;
    PVOID Extra1;
    PVOID Extra2;
    PVOID Extra3;
    PVOID Extra4;
    PVOID Extra5;
    PVOID Extra6;
    PVOID Extra7;
} RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED, *PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED;
#include <poppack.h>

_STATIC_ASSERT(sizeof(ACTIVATION_CONTEXT_STACK) == 0x24);
_STATIC_ASSERT(sizeof(RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED) == 0x58);
void NTAPI RtlpInitializeThreadActivationContextStack(PTEB teb)
{
    PACTIVATION_CONTEXT_STACK TebActivationStack = (PACTIVATION_CONTEXT_STACK)((LPBYTE)teb + 0x290); //ActivationStack
    PACTIVATION_CONTEXT_STACK *TebActivationContextStackPointer = (PACTIVATION_CONTEXT_STACK*)((LPBYTE)teb + 0x2c8); //ActivationContextStackPointer
    TebActivationStack->StackId = NtGetTickCount();
    TebActivationStack->NextCookieSequenceNumber = 1;
    TebActivationStack->Flags = 2;
    TebActivationStack->ActiveFrame = nullptr;
    *TebActivationContextStackPointer = TebActivationStack;
}

//ldrtypes.h
//
// Loader Data Table Entry Flags
//
#define LDRP_STATIC_LINK                        0x00000002
#define LDRP_IMAGE_DLL                          0x00000004
#define LDRP_SHIMENG_SUPPRESSED_ENTRY           0x00000008
#define LDRP_IMAGE_INTEGRITY_FORCED             0x00000020
#define LDRP_LOAD_IN_PROGRESS                   0x00001000
#define LDRP_UNLOAD_IN_PROGRESS                 0x00002000
#define LDRP_ENTRY_PROCESSED                    0x00004000
#define LDRP_ENTRY_INSERTED                     0x00008000
#define LDRP_CURRENT_LOAD                       0x00010000
#define LDRP_FAILED_BUILTIN_LOAD                0x00020000
#define LDRP_DONT_CALL_FOR_THREADS              0x00040000
#define LDRP_PROCESS_ATTACH_CALLED              0x00080000
#define LDRP_DEBUG_SYMBOLS_LOADED               0x00100000
#define LDRP_IMAGE_NOT_AT_BASE                  0x00200000
#define LDRP_COR_IMAGE                          0x00400000
#define LDR_COR_OWNS_UNMAP                      0x00800000
#define LDRP_SYSTEM_MAPPED                      0x01000000
#define LDRP_IMAGE_VERIFYING                    0x02000000
#define LDRP_DRIVER_DEPENDENT_DLL               0x04000000
#define LDRP_ENTRY_NATIVE                       0x08000000
#define LDRP_REDIRECTED                         0x10000000
#define LDRP_NON_PAGED_DEBUG_INFO               0x20000000
#define LDRP_MM_LOADED                          0x40000000
#define LDRP_COMPAT_DATABASE_PROCESSED          0x80000000

BOOLEAN LdrpShutdownInProgress;

#define DPRINT(...)
//part.based on ReactOS
VOID
NTAPI
LdrpCallTlsInitializers(IN PLDR_DATA_TABLE_ENTRY64 LdrEntry,
                        IN ULONG Reason)
{
    PIMAGE_TLS_DIRECTORY TlsDirectory;
    PIMAGE_TLS_CALLBACK *Array, Callback;
    ULONG Size;

    /* Get the TLS Directory */
    TlsDirectory = (PIMAGE_TLS_DIRECTORY)RtlImageDirectoryEntryToData(LdrEntry->DllBase,
                                                TRUE,
                                                IMAGE_DIRECTORY_ENTRY_TLS,
                                                &Size);

    /* Protect against invalid pointers */
    _SEH2_TRY
    {
        /* Make sure it's valid */
        if (TlsDirectory)
        {
            /* Get the array */
            Array = (PIMAGE_TLS_CALLBACK *)TlsDirectory->AddressOfCallBacks;
            if (Array)
            {
                /* Display debug */
                if (ShowSnaps)
                {
                    DPRINT1("LDR: Tls Callbacks Found. Imagebase %p Tls %p CallBacks %p\n",
                            LdrEntry->DllBase, TlsDirectory, Array);
                }

                /* Loop the array */
                while (*Array)
                {
                    /* Get the TLS Entrypoint */
                    Callback = *Array++;

                    /* Display debug */
                    if (ShowSnaps)
                    {
                        DPRINT1("LDR: Calling Tls Callback Imagebase %p Function %p\n",
                                LdrEntry->DllBase, Callback);
                    }

                    /* Call it */
                    LdrpCallInitRoutine((PDLL_INIT_ROUTINE)Callback,
                                        LdrEntry->DllBase,
                                        Reason,
                                        NULL);
                }
            }
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT1("LDR: Exception 0x%x during Tls Callback(%u) for %wZ\n",
                _SEH2_GetExceptionCode(), Reason, &LdrEntry->BaseDllName);
    }
    _SEH2_END;
}

BOOLEAN NTAPI LdrpCallInitRoutine(IN PDLL_INIT_ROUTINE EntryPoint, IN PVOID BaseAddress, IN ULONG Reason, IN PVOID Context)
{
    return EntryPoint(BaseAddress, Reason, (PCONTEXT)Context);
}
void NTAPI LdrpInitializeThread(IN PCONTEXT)
{
    PPEB Peb = NtCurrentPeb();
    PLDR_DATA_TABLE_ENTRY64 LdrEntry;
    PLIST_ENTRY NextEntry, ListHead;
    RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED ActCtx;
    PVOID EntryPoint;
    RtlpInitializeThreadActivationContextStack(NtCurrentTeb());

    LdrpAllocateTls(NtCurrentTeb());

    /* Start at the beginning */
    ListHead = &Peb->Ldr->InMemoryOrderModuleList;
    NextEntry = ListHead->Flink;
    while (NextEntry != ListHead)
    {
        /* Get the current entry */
        LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks);
        /* Make sure it's not ourselves */
        if (*(LPVOID*)((LPBYTE)Peb + 0x10)/*->ImageBaseAddress*/ != LdrEntry->DllBase && LdrEntry->DllBase != ImageBase)
        {
            /* Check if we should call */
            if (!(LdrEntry->Flags & LDRP_DONT_CALL_FOR_THREADS))
            {
                /* Get the entrypoint */
                EntryPoint = LdrEntry->EntryPoint;

                /* Check if we are ready to call it */
                if ((EntryPoint) &&
                    (LdrEntry->Flags & LDRP_PROCESS_ATTACH_CALLED) &&
                    (LdrEntry->Flags & LDRP_IMAGE_DLL))
                {
                    RtlZeroMemory(&ActCtx, sizeof(ActCtx));
                    /* Set up the Act Ctx */
                    ActCtx.Size = sizeof(ActCtx);
                    ActCtx.Format = 1;

                    /* Activate the ActCtx */
                    RtlActivateActivationContextUnsafeFast(&ActCtx,
                        LdrEntry->EntryPointActivationContext);

                    _SEH2_TRY
                    {
                        /* Check if it has TLS */
                        if (LdrEntry->TlsIndex)
                        {
                            /* Make sure we're not shutting down */
                            if (!LdrpShutdownInProgress)
                            {
                                /* Call TLS */
                                LdrpCallTlsInitializers(LdrEntry, DLL_THREAD_ATTACH);
                            }
                        }

                        /* Make sure we're not shutting down */
                        if (!LdrpShutdownInProgress)
                        {
                            /* Call the Entrypoint */
                            DPRINT("%wZ - Calling entry point at %p for thread attaching, %p/%p\n",
                                &LdrEntry->BaseDllName, LdrEntry->EntryPoint,
                                NtCurrentTeb()->RealClientId.UniqueProcess,
                                NtCurrentTeb()->RealClientId.UniqueThread);
                            LdrpCallInitRoutine((PDLL_INIT_ROUTINE)LdrEntry->EntryPoint,
                                LdrEntry->DllBase,
                                DLL_THREAD_ATTACH,
                                NULL);
                        }
                    }
                    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                    {
                        DPRINT1("WARNING: Exception 0x%x during LdrpCallInitRoutine(DLL_THREAD_ATTACH) for %wZ\n",
                            _SEH2_GetExceptionCode(), &LdrEntry->BaseDllName);
                    }
                    _SEH2_END;

                    /* Deactivate the ActCtx */
                    RtlDeactivateActivationContextUnsafeFast(&ActCtx);
                }
            }
        }

        /* Next entry */
        NextEntry = NextEntry->Flink;
    }
}
void NTAPI LdrShutdownThread(VOID)
{
    //TODO: call DllMain, tls callbacks
    _InterlockedDecrement(&LdrpActiveThreadCount);
}
EXTERN_C_END
