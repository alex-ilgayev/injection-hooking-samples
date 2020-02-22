#include "global.h"

/*
	- Standard Injection
	  - Searching for `LoadLibraryW` address. We assuming `kernel32` libraries are loaded in same addresses for all processes.
	  - Invoking `VirtualAllocEx` to allocate injected DLL name string.
	  - Invoking `WriteProcessMemory` to write that string.
	  - Invoking `CreateRemoteProcess` which will run `LoadLibraryW` with the dll name as a parameter.
*/
BOOL makeStandardInjection(HANDLE hTargetProcess, PWSTR pwszDllName) {
	SIZE_T cbAllocationSize, cbBytesWritten;
	PWSTR pwszRemoteDllNameAddr;
	LPVOID pLoadLibraryW;

	if (!getLoadLibraryAddress(&pLoadLibraryW)) {
		return FALSE;
	}

	cbAllocationSize = (wcslen(pwszDllName) + 1) * sizeof(WCHAR);
	if (!allocateAndWriteRemoteProcess
	(hTargetProcess, pwszDllName, cbAllocationSize, &pwszRemoteDllNameAddr)) {
		return FALSE;
	}

	if (!CreateRemoteThread(
		hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE) pLoadLibraryW, pwszRemoteDllNameAddr, 0, NULL)) {
		DBG_PRINT("CreateRemoteThread failed. Error code %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}