#pragma once

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>


#define DBG_PRINT(...) {char cad[512]; sprintf_s(cad, 512, __VA_ARGS__);  OutputDebugStringA(cad);}

#define KERNEL_32 TEXT("kernel32")
#define LOAD_LIBRARY "LoadLibraryW"

BOOL makeStandardInjection(HANDLE hTargetProcess, PWSTR pwszDllName);
