// injection.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "injection.h"
#include <Tlhelp32.h>
#include <stdio.h>
#include <psapi.h>
#include <string.h>
#include <stdlib.h>

#define DBG_PRINT(...) {char cad[512]; sprintf_s(cad, 512, __VA_ARGS__);  OutputDebugStringA(cad);}

#define KERNEL_32 TEXT("kernel32")
#define LOAD_LIBRARY "LoadLibraryW"

VOID wcharToLower(PWCHAR pwchInput) {
	WCHAR tch;
	PWCHAR curr = pwchInput;
	while (*curr != wchar_t('\0')) {
		*curr = WCHAR(towlower(*curr));
		++curr;
	}
}

BOOL findProcessHandle(PHANDLE pHandle, PWSTR pwszInputProcessName) {
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;
	WCHAR pwchProcessName[MAX_PATH];
	WCHAR pwchInputProcessNameCopy[MAX_PATH];
	BOOL fCmpRes;

	if (NULL == pwszInputProcessName || wcslen(pwszInputProcessName) >= MAX_PATH) {
		DBG_PRINT("Wrong pwchInputProcessName param.");
		return FALSE;
	}

	wcscpy_s(pwchInputProcessNameCopy, MAX_PATH, pwszInputProcessName);
	wcharToLower(pwchInputProcessNameCopy);

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		DBG_PRINT("CreateToolhelp32Snapshot failed. Error code %d\n", GetLastError());
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do
	{
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (hProcess == NULL) {
			DBG_PRINT("OpenProcess for id %d failed. Error code %d\n", pe32.th32ProcessID, GetLastError());
			continue;
		}
		if (!GetModuleFileNameEx(hProcess, 0, pwchProcessName, MAX_PATH)) {
			DBG_PRINT("GetModuleFileNameEx for id %d failed. Error code %d\n", pe32.th32ProcessID, GetLastError());
			CloseHandle(hProcess);
			CloseHandle(hProcessSnap);
			return FALSE;
		}
		if (NULL == pwchProcessName || wcslen(pwchProcessName) == 0) {
			DBG_PRINT("Problem with process name");
			CloseHandle(hProcess);
			CloseHandle(hProcessSnap);
			return 1;
		}
				
		wcharToLower(pwchProcessName);
		if (wcscmp(pwchInputProcessNameCopy, pwchProcessName) == 0) {
			CloseHandle(hProcessSnap);
			*pHandle = hProcess;

			return TRUE;
		}

		CloseHandle(hProcess);

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return FALSE;
}

BOOL makeStandardInjection(HANDLE hTargetProcess, PWSTR pwszDllName) {
	SIZE_T cbAllocationSize, cbBytesWritten;
	PWSTR pwszRemoteDllNameAddr;
	HMODULE hKernel32;
	LPVOID pLoadLibraryW;

	hKernel32 = LoadLibrary(KERNEL_32);
	if (NULL == hKernel32) {
		DBG_PRINT("LoadLibrary for kernel32 failed. Error code %d\n", GetLastError());
		return FALSE;
	}

	pLoadLibraryW = GetProcAddress(hKernel32, LOAD_LIBRARY);
	if (NULL == pLoadLibraryW) {
		DBG_PRINT("GetProcAddress for LoadLibrary failed. Error code %d\n", GetLastError());
		return FALSE;
	}

	cbAllocationSize = (wcslen(pwszDllName) + 1) * sizeof(WCHAR);
	pwszRemoteDllNameAddr = (PWCHAR)VirtualAllocEx(
		hTargetProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
	if (NULL == pwszRemoteDllNameAddr) {
		DBG_PRINT("VirtualAllocEx failed. Error code %d\n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(
		hTargetProcess, pwszRemoteDllNameAddr, pwszDllName, cbAllocationSize, &cbBytesWritten)) {
		DBG_PRINT("WriteProcessMemory failed. Error code %d\n", GetLastError());
		return FALSE;
	}

	if (!CreateRemoteThread(
		hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE) pLoadLibraryW, pwszRemoteDllNameAddr, 0, NULL)) {
		DBG_PRINT("CreateRemoteThread failed. Error code %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

INJECTION_API BOOL exportedInject(PWCHAR pwchProcessName, PWCHAR pwchDllName) {
	HANDLE hProcess;

	if (!findProcessHandle(&hProcess, pwchProcessName)) {
		return FALSE;
	}
	DBG_PRINT("found process %S - handle %d\n", pwchProcessName, hProcess);

	if (!makeStandardInjection(hProcess, pwchDllName)) {
		CloseHandle(hProcess);
		return FALSE;
	}

	return TRUE;
}