#include "global.h"


BOOL getLoadLibraryAddress(LPVOID* pLoadLibraryW_) {
	HMODULE hKernel32;
	LPVOID pLoadLibraryW;

	hKernel32 = LoadLibrary(KERNEL_32);
	if (NULL == hKernel32) {
		printf("LoadLibrary for kernel32 failed. Error code %d\n", GetLastError());
		return FALSE;
	}

	pLoadLibraryW = GetProcAddress(hKernel32, LOAD_LIBRARY);
	if (NULL == pLoadLibraryW) {
		printf("GetProcAddress for LoadLibrary failed. Error code %d\n", GetLastError());
		return FALSE;
	}
	*pLoadLibraryW_ = pLoadLibraryW;

	return TRUE;
}

BOOL allocateAndWriteRemoteProcess(HANDLE hProcess, LPVOID data, SIZE_T size, LPVOID* address) {
	LPVOID pRemoteAddr;
	SIZE_T cbBytesWritten;
	pRemoteAddr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
	if (NULL == pRemoteAddr) {
		printf("VirtualAllocEx failed. Error code %d\n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(
		hProcess, pRemoteAddr, data, size, &cbBytesWritten)) {
		printf("WriteProcessMemory failed. Error code %d\n", GetLastError());
		return FALSE;
	}
	*address = pRemoteAddr;
	return TRUE;
}
