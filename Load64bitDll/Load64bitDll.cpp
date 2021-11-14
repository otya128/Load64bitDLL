#include <windows.h>
#include <winternl.h>
#include <vector>
#include "Load64bitDll.h"

NTSTATUS(NTAPI *NtWow64QueryInformationProcess64)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef struct {
    DWORD64 Reserved1;
    DWORD64 PebBaseAddress;
    DWORD64 Reserved2[2];
    DWORD64 UniqueProcessId;
    DWORD64 Reserved3;
} PROCESS_BASIC_INFORMATION64;

NTSTATUS(NTAPI *NtWow64ReadVirtualMemory64)(
    HANDLE ProcessHandle,
    UINT64 BaseAddress,
    PVOID Buffer,
    ULONG64 Size,
    PULONG64 NumberOfBytesRead
    );

typedef struct {
    ULONG Length;
    BOOLEAN Initialized;
    UINT64 SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
    UINT64 EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA64;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    UINT64 Buffer;
} UNICODE_STRING64;

_STATIC_ASSERT(sizeof(UNICODE_STRING64) == 0x10);

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    UINT64 Buffer;
} ANSI_STRING64;

_STATIC_ASSERT(sizeof(ANSI_STRING64) == 0x10);

typedef struct
{
    LIST_ENTRY64 InLoadOrderLinks;
    LIST_ENTRY64 InMemoryOrderLinks;
    union {
        LIST_ENTRY64 InInitializationOrderLinks;
        LIST_ENTRY64 InProgressLinks;
    };
    PVOID64 DllBase;
    PVOID64 EntryPoint;
    ULONG64 SizeOfImage;
    UNICODE_STRING64 FullDllName;
    UNICODE_STRING64 BaseDllName;
    union {
        UCHAR FlagGroup[4];
        ULONG Flags;
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY64 HashLinks;
} LDR_DATA_TABLE_ENTRY64;
static HANDLE handle;

_STATIC_ASSERT(FIELD_OFFSET(LDR_DATA_TABLE_ENTRY64, HashLinks) == 0x70);

static UINT64 get_peb64()
{
    PROCESS_BASIC_INFORMATION64 pbi64 = { 0 };
    NTSTATUS ret = NtWow64QueryInformationProcess64(GetCurrentProcess(), ProcessBasicInformation, &pbi64, sizeof(pbi64), NULL);
    return pbi64.PebBaseAddress;
}

static UINT64 get_module_base(LPCWSTR name)
{
    UINT64 peb64 = get_peb64();
    PVOID64 pLoaderData;
    NTSTATUS ret = NtWow64ReadVirtualMemory64(handle, peb64 + 24, &pLoaderData, sizeof(pLoaderData), NULL);
    PEB_LDR_DATA64 LoaderData;
    ret = NtWow64ReadVirtualMemory64(handle, (UINT64)pLoaderData, &LoaderData, sizeof(LoaderData), NULL);
    LDR_DATA_TABLE_ENTRY64 entry;
    UINT64 link = LoaderData.InLoadOrderModuleList.Flink;
    while (1)
    {
        ret = NtWow64ReadVirtualMemory64(handle, link, &entry, sizeof(entry), NULL);
        wchar_t buf1[65536];
        wchar_t buf2[65536];
        ret = NtWow64ReadVirtualMemory64(handle, (UINT64)entry.FullDllName.Buffer, buf1, entry.FullDllName.Length * sizeof(buf1[0]), NULL);
        ret = NtWow64ReadVirtualMemory64(handle, (UINT64)entry.BaseDllName.Buffer, buf2, entry.BaseDllName.Length * sizeof(buf2[0]), NULL);
        if (!lstrcmpW(buf2, name))
        {
            break;
        }
        link = entry.InLoadOrderLinks.Flink;
        if (link == LoaderData.InLoadOrderModuleList.Flink)
        {
            return 0;
        }
    }
    return (UINT64)entry.DllBase;
}

static UINT64 get_proc_address(UINT64 base, LPCSTR search_func)
{
    if (!base)
        return 0;
    IMAGE_DOS_HEADER dos_header;
    NtWow64ReadVirtualMemory64(handle, (UINT64)base, &dos_header, sizeof(dos_header), NULL);
    IMAGE_NT_HEADERS64 nt_headers;
    NtWow64ReadVirtualMemory64(handle, (UINT64)base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers), NULL);
    IMAGE_EXPORT_DIRECTORY export_dir;
    NtWow64ReadVirtualMemory64(handle, (UINT64)base + nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, &export_dir, sizeof(export_dir), NULL);
    std::vector<DWORD> func_table(export_dir.NumberOfFunctions);
    std::vector<WORD> ord_table(export_dir.NumberOfNames);
    std::vector<DWORD> name_table(export_dir.NumberOfNames);
    NtWow64ReadVirtualMemory64(handle, (UINT64)base + export_dir.AddressOfFunctions, func_table.data(), sizeof(DWORD) * export_dir.NumberOfFunctions, NULL);
    NtWow64ReadVirtualMemory64(handle, (UINT64)base + export_dir.AddressOfNameOrdinals, ord_table.data(), sizeof(WORD) * export_dir.NumberOfNames, NULL);
    NtWow64ReadVirtualMemory64(handle, (UINT64)base + export_dir.AddressOfNames, name_table.data(), sizeof(DWORD) * export_dir.NumberOfNames, NULL);
    size_t len = strlen(search_func) + 1;
    std::vector<char> name_buf(len);
    UINT64 func = 0;
    for (DWORD i = 0; i < export_dir.NumberOfNames; i++)
    {
        NtWow64ReadVirtualMemory64(handle, (UINT64)base + name_table[i], name_buf.data(), len, NULL);
        if (!memcmp(name_buf.data(), search_func, len))
        {
            func = func_table[ord_table[i]] + (UINT64)base;
        }
    }
    return func;
}

#pragma comment(lib, "ntdll")
static UINT64 pLdrLoadDll;
static UINT64 pLdrUnloadDll;
static UINT64 pLdrGetProcedureAddress;

extern "C" __declspec(dllexport) UINT64 __cdecl LoadLibraryW64(LPCWSTR libname)
{
    UINT64 handle;
    UNICODE_STRING uni32;
    UNICODE_STRING64 uni;
    RtlInitUnicodeString(&uni32, libname);
    uni.Buffer = reinterpret_cast<UINT64>(uni32.Buffer);
    uni.MaximumLength = uni32.MaximumLength;
    uni.Length = uni32.Length;
    auto status = Call64<NTSTATUS>(pLdrLoadDll, 0ULL, 0ULL, reinterpret_cast<UINT64>(&uni), reinterpret_cast<UINT64>(&handle));
    if (NT_SUCCESS(status))
    {
        return handle;
    }
    SetLastError(RtlNtStatusToDosError(status));
    return 0ULL;
}

extern "C" __declspec(dllexport) UINT64 __cdecl LoadLibraryExW64(LPCWSTR libname, HANDLE hFile, DWORD dwFlags)
{
    UINT64 handle;
    UNICODE_STRING uni32;
    UNICODE_STRING64 uni;
    if (dwFlags & (LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE))
    {
        return 0ULL;
    }
    RtlInitUnicodeString(&uni32, libname);
    uni.Buffer = reinterpret_cast<UINT64>(uni32.Buffer);
    uni.MaximumLength = uni32.MaximumLength;
    uni.Length = uni32.Length;
    auto status = Call64<NTSTATUS>(pLdrLoadDll, dwFlags | 1, //flags?
        reinterpret_cast<UINT64>(&dwFlags), reinterpret_cast<UINT64>(&uni), reinterpret_cast<UINT64>(&handle));
    if (NT_SUCCESS(status))
    {
        return handle;
    }
    SetLastError(RtlNtStatusToDosError(status));
    return 0ULL;
}

extern "C" __declspec(dllexport) BOOL __cdecl FreeLibrary64(UINT64 hmod)
{
    if (!hmod)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    auto status = Call64<NTSTATUS>(pLdrUnloadDll, hmod);
    if (NT_SUCCESS(status))
    {
        return TRUE;
    }
    SetLastError(RtlNtStatusToDosError(status));
    return FALSE;
}

extern "C" __declspec(dllexport) UINT64 __cdecl GetProcAddress64(UINT64 hmod, LPCSTR funcname)
{
    UINT64 addr;
    ANSI_STRING name32;
    ANSI_STRING64 name;
    RtlInitAnsiString(&name32, funcname);
    name.Buffer = (UINT64)name32.Buffer;
    name.MaximumLength = name32.MaximumLength;
    name.Length = name32.Length;
    auto status = Call64<NTSTATUS>(pLdrGetProcedureAddress, hmod, reinterpret_cast<UINT64>(&name), 0ULL, reinterpret_cast<UINT64>(&addr));
    if (NT_SUCCESS(status))
    {
        return addr;
    }
    SetLastError(RtlNtStatusToDosError(status));
    return 0;
}

static UINT64 pDllMain;
static UINT64 helper;

bool load()
{
    handle = OpenProcess(PROCESS_VM_READ, FALSE, GetCurrentProcessId());
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    NtWow64QueryInformationProcess64 = reinterpret_cast<decltype(NtWow64QueryInformationProcess64)>(GetProcAddress(ntdll, "NtWow64QueryInformationProcess64"));
    NtWow64ReadVirtualMemory64 = reinterpret_cast<decltype(NtWow64ReadVirtualMemory64)>(GetProcAddress(ntdll, "NtWow64ReadVirtualMemory64"));
    auto ntdll64 = get_module_base(L"ntdll.dll");
    pLdrGetProcedureAddress = get_proc_address(ntdll64, "LdrGetProcedureAddress");
    pLdrLoadDll = get_proc_address(ntdll64, "LdrLoadDll");
    pLdrUnloadDll = get_proc_address(ntdll64, "LdrUnloadDll");
    WCHAR search_buf[MAX_PATH];
    WCHAR dll[MAX_PATH];
    search_buf[0] = 0;
    if (GetDllDirectoryW(ARRAYSIZE(search_buf), search_buf) && search_buf[0])
    {
        dll[0] = 0;
        if (SearchPathW(search_buf, L"wow64hlp.dll", nullptr, ARRAYSIZE(dll), dll, nullptr) && dll[0])
        {
            helper = LoadLibraryW64(dll);
        }
    }
    if (!helper)
        helper = LoadLibraryW64(L"wow64hlp.dll");
    auto help_func = GetProcAddress64(helper, "Wow64Helper");
    if (!help_func)
    {
        return false;
    }
    auto result = Call64<UINT64>(help_func);
    pDllMain = GetProcAddress64(helper, "DllMain");
    return true;
}

void unload()
{
    CloseHandle(handle);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        return load();
    case DLL_THREAD_ATTACH:
        if (pDllMain)
        {
            Call64<BOOL>(pDllMain, helper, ul_reason_for_call, lpReserved);
        }
        break;
    case DLL_THREAD_DETACH:
        if (pDllMain)
        {
            Call64<BOOL>(pDllMain, helper, ul_reason_for_call, lpReserved);
        }
        break;
    case DLL_PROCESS_DETACH:
        unload();
        break;
    }
    return TRUE;
}

