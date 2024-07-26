# go1.21-over-win7

## Make golang 1.21 or later run in Windows 7!
![Windows 7 run sample](https://i.imgur.com/3Q7S5Q7.png)

- This repository seeks to run golang 1.21 or later on Windows 7(which was dropped its support in golang 1.21), in a need of using golang compiled programs in Windows 7(in production environments).

__Tested using go1.22.5__ with test cases in src/cmd/internal/testdir in official golang repository.

### How does it work?

![panic_image](https://i.imgur.com/o9MbdXf.png)

The following two commits result in the panic in the image above.

- https://github.com/golang/go/commit/a17d959debdb04cd550016a3501dd09d50cd62e7
  
  This breaks in Windows 7 as an specific update(KB2533623) is required for LOAD_LIBRARY_SEARCH_SYSTEM32(0x800) flag to work.
- https://github.com/golang/go/commit/693def151adff1af707d82d28f55dba81ceb08e1

  This breaks as ProcessPrng function does not exist in BCryptPrimitives.dll(the dll itself exists in Windows 7).

To handle these, [Microsoft Detours](https://github.com/microsoft/Detours) project(imported as submodule) is used to create DLL for hooking procedures that causes the panic.

1. Just remove the LOAD_LIBRARY_SEARCH_SYSTEM32 flag from LoadLibraryEx call.
2. Use BCryptGenRandom like this in a following format to replace ProcessPrng(this may not ideal as BCryptGenRandom can return error unlike ProcessPrng).

```cpp
(void)BCryptGenRandom(NULL, (PUCHAR)pbData, (ULONG)cbData, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
```

### Requirements to build

- Visual Studio 2017 or later
- [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk)

### How to build DLL

- After installing Visual Studio, open __native tools command prompt for vs [your version]__ or __x64 native tools command prompt for vs [your version]__  from start menu according to the architecture that you want to build dll.
- If haven't built Detours library before, run __nmake__ in the opened command prompt after navigating into __Detours/src__ directory. This should be done separately for x86 and x64 version in each command prompt to get the dll for each architecutre.
- Navigate info go121+win7 directory and then run

```cmd
cl /LD /nologo /Zi /MT /Gm- /W4 /WX /we4777 /we4800 /Od /DDETOUR_DEBUG=0  /I ..\Detours\include\ /Fego121pluswin7.dll go121pluswin7.cpp  /link /release /incremental:no  /nodefaultlib:oldnames.lib /export:DetourFinishHelperProcess,@1,NONAME /export:HookedCreateProcessInternal  /export:HookedLoadLibraryEx  /export:HookedGetProcAddress ..\Detours\lib.X86\detours.lib kernel32.lib bcrypt.lib
```

for x86 architecture and

```cmd
cl /LD /nologo /Zi /MT /Gm- /W4 /WX /we4777 /we4800 /Od /DDETOUR_DEBUG=0  /I ..\Detours\include\ /Fego121pluswin7_64.dll go121pluswin7.cpp  /link /release /incremental:no  /nodefaultlib:oldnames.lib /export:DetourFinishHelperProcess,@1,NONAME  /export:HookedCreateProcessInternal /export:HookedLoadLibraryEx  /export:HookedGetProcAddress ..\Detours\lib.X64\detours.lib kernel32.lib bcrypt.lib
```

for x64 architecture in a command prompt opened eariler.

- Copy the compiled dll into a path that the program can look for dll(%PATH% or the directory that the program exists).

(_Referenced from Makefile in [Simple sample](https://github.com/microsoft/Detours/wiki/SampleSimple) from Detours Project_)

To inject this dll into a binary you can use setdll.exe from Detours Project after building sample binaries by running nmake in a Detours/samples directory in as mentioned above.

### Inject into subprocesses for testing

- To make debugging convenient, this code can be used to build a simple cmd wrapper to inject the produced dll into every subprocesses.

```cpp
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int wmain()
{
	LoadLibraryW(L"go121pluswin7.dll"); // the path that dll exists

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	WCHAR cmdline[MAX_PATH] = L"cmd.exe";

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));

	si.cb = sizeof(si);

	if (!CreateProcessW(NULL, cmdline, NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi)) {
		fprintf(stderr, "FAILED: %d\n", GetLastError());
		return 1;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}
```
and build it from Visual studio.

## Special thanks

Special thanks to [@mrexodia](https://github.com/mrexodia) for creating [x64dbg](https://github.com/x64dbg/x64dbg) project which helped me a lot with investigating the issue and other Windows program debugging!
