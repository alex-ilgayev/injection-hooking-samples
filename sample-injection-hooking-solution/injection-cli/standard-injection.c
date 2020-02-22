#include "standard-injection.h"

/*
	Standard DLL Injection method.

	1
*/
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