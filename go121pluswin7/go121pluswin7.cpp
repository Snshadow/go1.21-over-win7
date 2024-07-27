#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <string.h>
#include <tchar.h>
#include "detours.h"

// image base of dll itself
EXTERN_C IMAGE_DOS_HEADER __ImageBase;

HMODULE hKernel32 = GetModuleHandleW(_T("kernel32.dll"));
FARPROC createProcessInternalAddr = GetProcAddress(hKernel32, "CreateProcessInternalW");

static HMODULE(WINAPI *TrueLoadLibraryEx)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) = LoadLibraryExW;
static FARPROC(WINAPI *TrueGetProcAddress)(HMODULE hModule, LPCSTR lpProcName) = GetProcAddress;
static BOOL(WINAPI *TrueCreateProcessInternalW)(
    _In_opt_ HANDLE hUserToken,
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation,
    _Out_ PHANDLE hNewToken) =
    (BOOL(WINAPI *)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE))createProcessInternalAddr;

LPVOID write_into_process(HANDLE hProcess, LPBYTE buffer, SIZE_T buffer_size, DWORD protect)
{
    LPVOID remoteAddress = VirtualAllocEx(hProcess, NULL, buffer_size, MEM_COMMIT | MEM_RESERVE, protect);
    if (remoteAddress == NULL)
    {
        return NULL;
    }
    if (!WriteProcessMemory(hProcess, remoteAddress, buffer, buffer_size, NULL))
    {
        VirtualFreeEx(hProcess, remoteAddress, buffer_size, MEM_FREE);
        return NULL;
    }
    return remoteAddress;
}

BOOL WINAPI HookedCreateProcessInternal(
    _In_opt_ HANDLE hUserToken,
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation,
    _Out_ PHANDLE hNewToken)
{
    // suspend process for injection
    dwCreationFlags |= CREATE_SUSPENDED;

    BOOL res;
    res = TrueCreateProcessInternalW(
        hUserToken,
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        hNewToken);

    if (res)
    {
        TCHAR dllpath[MAX_PATH];
        if (!GetModuleFileNameW((HMODULE)&__ImageBase, (LPWSTR)dllpath, MAX_PATH))
        {
            return FALSE;
        }

        LPVOID remote_text = write_into_process(lpProcessInformation->hProcess, (LPBYTE)dllpath, (wcslen((LPCWSTR)dllpath) + 1) * 2, PAGE_READWRITE);
        if (remote_text == NULL)
            return FALSE;

        // do the injection then wait
        HANDLE hInject;
        hInject = CreateRemoteThread(lpProcessInformation->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, remote_text, 0, NULL);
        WaitForSingleObject(hInject, INFINITE);

        // resume the main thread
        ResumeThread(lpProcessInformation->hThread);
    }
    return res;
}

BOOL WINAPI DetourProcessPrng(PBYTE pbData, SIZE_T cbData)
{
    (void)BCryptGenRandom(NULL, (PUCHAR)pbData, (ULONG)cbData, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    return TRUE;
}

HMODULE WINAPI HookedLoadLibraryEx(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    dwFlags &= ~(LOAD_LIBRARY_SEARCH_SYSTEM32);

    HMODULE hModule = TrueLoadLibraryEx(lpLibFileName, hFile, dwFlags);

    return hModule;
}

// circumvent non existent ProcessPrng function to BCryptGenRandom
FARPROC WINAPI HookedGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    FARPROC procAddr;

    // check if this is an ordinal value
    if ((lpProcName >= (LPCSTR)0x10000) && strcmp("ProcessPrng", lpProcName) == 0)
    {
        HMODULE hRefModule = GetModuleHandleW(_T("bcryptprimitives.dll"));

        if (hRefModule != hModule)
            return NULL;

        procAddr = (FARPROC)DetourProcessPrng;
    }
    else
    {
        procAddr = TrueGetProcAddress(hModule, lpProcName);
    }

    return procAddr;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    (void)hinst;
    (void)reserved;

    if (DetourIsHelperProcess())
    {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DetourRestoreAfterWith();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID &)TrueCreateProcessInternalW, (PVOID)HookedCreateProcessInternal);
        DetourAttach(&(PVOID &)TrueLoadLibraryEx, (PVOID)HookedLoadLibraryEx);
        DetourAttach(&(PVOID &)TrueGetProcAddress, (PVOID)HookedGetProcAddress);
        DetourTransactionCommit();
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID &)TrueCreateProcessInternalW, (PVOID)HookedCreateProcessInternal);
        DetourDetach(&(PVOID &)TrueLoadLibraryEx, (PVOID)HookedLoadLibraryEx);
        DetourDetach(&(PVOID &)TrueGetProcAddress, (PVOID)HookedGetProcAddress);
        DetourTransactionCommit();
    }

    return TRUE;
}
