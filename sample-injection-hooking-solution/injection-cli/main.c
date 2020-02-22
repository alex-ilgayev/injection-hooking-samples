#include "standard-injection.h"

/*
	converts unicode string into lowercase.
*/
VOID wcharToLower(PWSTR pwszInput) {
	WCHAR tch;
	PWSTR curr = pwszInput;
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
	WCHAR pwszProcessName[MAX_PATH];
	WCHAR pwszInputProcessNameCopy[MAX_PATH];

	*pHandle = INVALID_HANDLE_VALUE;

	if (NULL == pwszInputProcessName || wcslen(pwszInputProcessName) >= MAX_PATH) {
		DBG_PRINT("Wrong pwszInputProcessName param.");
		return FALSE;
	}

	wcscpy_s(pwszInputProcessNameCopy, MAX_PATH, pwszInputProcessName);
	wcharToLower(pwszInputProcessNameCopy);

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap) {
		DBG_PRINT("CreateToolhelp32Snapshot failed. Error code %d\n", GetLastError());
		return FALSE;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		DBG_PRINT("Process32First failed. Error code %d\n", GetLastError());
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do
	{
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (hProcess == NULL) { // permissions
			continue;
		}
		if (!GetModuleFileNameExW(hProcess, 0, pwszProcessName, MAX_PATH)) {
			DBG_PRINT("GetModuleFileNameEx for id %d failed. Error code %d\n", pe32.th32ProcessID, GetLastError());
			CloseHandle(hProcess);
			CloseHandle(hProcessSnap);
			return FALSE;
		}
		if (NULL == pwszProcessName || wcslen(pwszProcessName) == 0) {
			DBG_PRINT("Problem with process name");
			CloseHandle(hProcess);
			CloseHandle(hProcessSnap);
			return 1;
		}

		wcharToLower(pwszProcessName);
		if (wcscmp(pwszInputProcessNameCopy, pwszProcessName) == 0) {
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
BOOL standardInject(PWSTR pwszProcessName, PWSTR pwszDllName) {
	HANDLE hProcess;

	if (!findProcessHandle(&hProcess, pwszProcessName)) {
		return FALSE;
	}
	DBG_PRINT("found process %S - handle %d\n", pwszProcessName, (DWORD)hProcess);

	if (!makeStandardInjection(hProcess, pwszDllName)) {
		CloseHandle(hProcess);
		return FALSE;
	}

	return TRUE;
}

BOOL apcInjection(PWSTR pwszExePath, PWSTR pwszDllName) {
	if (!makeAPCInjection(pwszExePath, pwszDllName)) {
		return FALSE;
	}
	return TRUE;
}

int wmain(int argc, wchar_t **argv) {

	//LPWSTR pszTargetProcess = L"C:\\Windows\\System32\\notepad.exe";
	//LPWSTR pszTargetProcess = L"C:\\Windows\\System32\\cmd.exe";
	//LPWSTR pszTargetProcess = L"C:\\Windows\\explorer.exe";
	LPWSTR pszTargetProcess = L"C:\\Windows\\system32\\svchost.exe";
	//LPWSTR pszInjectedDll = L"C:\\Users\\alexi\\source\\repos\\sample-injection-hooking-proj\\sample-injection-hooking-solution\\x64\\Debug\\inline-hooking.dll";
	LPWSTR pszInjectedDll = L"C:\\Users\\alexi\\source\\repos\\sample-injection-hooking-proj\\sample-injection-hooking-solution\\x64\\Debug\\sample-dll.dll";

	/*if (!standardInject(pszTargetProcess, pszInjectedDll)) {
		printf("The processes couldn't be found or insufficient permissions to make the injection.\n");
	}*/
	if (!apcInjection(pszTargetProcess, pszInjectedDll)) {
		printf("The processes couldn't be found or insufficient permissions to make the injection.\n");
	}
	printf("Injection was successful.\n");
	return 0;
}