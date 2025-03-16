# go1.21-over-win7

## Make golang 1.21 or later run in Windows 7!
![Windows 7 run sample](https://github.com/user-attachments/assets/978e0300-dbdc-49af-99f9-d9a1d420d437)

- This repository seeks to run golang 1.21 or later on Windows 7(which was dropped its support in golang 1.21), in a need of using golang compiled programs in Windows 7(in production environments).

Tested using __go1.24.1__ with test cases in src/cmd/internal/testdir in official golang repository.

### How does it work?

![panic_image](https://i.imgur.com/o9MbdXf.png)

The following two commits result in the panic in the image above.

- https://github.com/golang/go/commit/a17d959debdb04cd550016a3501dd09d50cd62e7
  
  This breaks in Windows 7 as a specific update(KB2533623) is required for LOAD_LIBRARY_SEARCH_SYSTEM32(0x800) flag to work.
- https://github.com/golang/go/commit/693def151adff1af707d82d28f55dba81ceb08e1

  This breaks as ProcessPrng function does not exist in BCryptPrimitives.dll(the dll itself exists in Windows 7).

To handle these, [Microsoft Detours](https://github.com/microsoft/Detours) project(imported as submodule) is used to create DLL for hooking procedures that cause the panic.

1. Just remove the LOAD_LIBRARY_SEARCH_SYSTEM32 flag from LoadLibraryEx call.
2. Use BCryptGenRandom like this in a following format to replace ProcessPrng(this may not ideal as BCryptGenRandom can return error unlike ProcessPrng).

```cpp
(void)BCryptGenRandom(NULL, (PUCHAR)pbData, (ULONG)cbData, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
```

### Requirements to build

- [Visual Studio](https://visualstudio.microsoft.com) 2017 or later
- [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk)

 or

- [mingw-w64](https://www.mingw-w64.org) toolchain

### How to build DLL

#### Visual Studio

- After installing Visual Studio, open __x86 native tools command prompt for vs [your version]__ or __x64 native tools command prompt for vs [your version]__  from start menu according to the architecture that you want to build dll.
- Navigate into `go121pluswin7/msvc` directory and then run

```cmd
nmake
```

, the go121pluswin7_(corresponding architecture).dll is to be created in the same directory.

- Copy the compiled dll into a path that the program can look for dll(%PATH% or the directory that the program exists).

(_Referenced from Makefile in [Simple sample](https://github.com/microsoft/Detours/wiki/SampleSimple) from Detours Project_)

To inject this dll into a binary you can use setdll.exe from Detours Project after building sample binaries by running `nmake` in a Detours/samples directory in as mentioned above.

#### mingw

[Mingw-w64](https://www.mingw-w64.org) can also be used to build dll.

- TBD

- Install mingw-w64 toolchain for Windows (see [here](https://www.mingw-w64.org/downloads)).

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
