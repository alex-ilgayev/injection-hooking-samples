#include "standard-injection.h"

/*
	converts unicode string into lowercase.
*/
VOID wcharToLower(PWCHAR pwchInput) {
	WCHAR tch;
	PWCHAR curr = pwchInput;
	while (*curr != L'\0') {
		*curr = towlower(*curr);
		++curr;
	}
}

/*
	Search for the process to inject.
	return TRUE if found, or FALSE otherwise.

	Errors are output into debug view.
*/
_Success_(return)
BOOL findProcessHandle(_Out_ PHANDLE pHandle, _In_ PWSTR pwszInputProcessName) {
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;
	WCHAR pwchProcessName[MAX_PATH];
	WCHAR pwchInputProcessNameCopy[MAX_PATH];
	BOOL fCmpRes;

	*pHandle = INVALID_HANDLE_VALUE;

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
		if (hProcess == NULL) { // permissions
			continue;
		}
		if (!GetModuleFileNameExW(hProcess, 0, pwchProcessName, MAX_PATH)) {
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

/*
	Searches for the desired processes, and injects the dll into using standard method.
	return TRUE if succeeded, or FALSE otherwise.
*/
BOOL standardInject(PWCHAR pwchProcessName, PWCHAR pwchDllName) {
	HANDLE hProcess;

	if (!findProcessHandle(&hProcess, pwchProcessName)) {
		return FALSE;
	}
	DBG_PRINT("found process %S - handle %d\n", pwchProcessName, (DWORD)hProcess);

	if (!makeStandardInjection(hProcess, pwchDllName)) {
		CloseHandle(hProcess);
		return FALSE;
	}

	return TRUE;
}

int wmain(int argc, wchar_t **argv) {

	//LPWSTR pszTargetProcess = L"C:\\Windows\\System32\\notepad.exe";
	LPWSTR pszTargetProcess = L"C:\\Windows\\System32\\cmd.exe";
	LPWSTR pszInjectedDll = L"C:\\Users\\alexi\\source\\repos\\sample-injection-hooking-proj\\sample-injection-hooking-solution\\x64\\Debug\\inline-hooking.dll";

	if (!standardInject(pszTargetProcess, pszInjectedDll)) {
		printf("The processes couldn't be found or insufficient permissions to make the injection.\n");
	}
	printf("Injection was successful.\n");
	return 0;
}