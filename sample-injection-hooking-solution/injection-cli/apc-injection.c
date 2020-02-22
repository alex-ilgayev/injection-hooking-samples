#include "apc-injection.h"

BOOL makeAPCInjection(PWSTR pwszExePath, PWSTR pwszDllName) {
	SIZE_T cbAllocationSize, cbBytesWritten;
	PWSTR pwszRemoteDllNameAddr;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
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

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcess(pwszExePath, pwszExePath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		DBG_PRINT("CreateProcess failed. Error code %d\n", GetLastError());
		return FALSE;
	}

	hProcess = pi.hProcess;
	hThread = pi.hThread;

	cbAllocationSize = (wcslen(pwszDllName) + 1) * sizeof(WCHAR);
	pwszRemoteDllNameAddr = (PWCHAR)VirtualAllocEx(
		hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
	if (NULL == pwszRemoteDllNameAddr) {
		DBG_PRINT("VirtualAllocEx failed. Error code %d\n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(
		hProcess, pwszRemoteDllNameAddr, pwszDllName, cbAllocationSize, &cbBytesWritten)) {
		DBG_PRINT("WriteProcessMemory failed. Error code %d\n", GetLastError());
		return FALSE;
	}

	if (!QueueUserAPC((PAPCFUNC)pLoadLibraryW, hThread, pwszRemoteDllNameAddr)) {
		DBG_PRINT("QueueUserAPC failed. Error code %d\n", GetLastError());
		return FALSE;
	}

	if (!ResumeThread(hThread)) {
		DBG_PRINT("QueueUserAPC failed. Error code %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}