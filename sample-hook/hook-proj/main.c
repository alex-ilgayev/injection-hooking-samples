#include <Windows.h>
#include <stdio.h>

#define DLL_NAME L"injection.dll"
#define PROC_NAME "exportedInject"

typedef BOOL (*__cdecl inject_proc_t)(PWCHAR pwchProcessName);

int wmain(int argc, wchar_t **argv) {
	HANDLE hLibrary;
	inject_proc_t inject_proc;

	if ((hLibrary = LoadLibrary(DLL_NAME)) == 0) {
		printf("LoadLibrary failed. Error code %d\n", GetLastError());
		return 1;
	}
	if ((inject_proc = (inject_proc_t) GetProcAddress(hLibrary, PROC_NAME)) == 0) {
		printf("GetProcAddress failed. Error code %d\n", GetLastError());
		return 1;
	}

	LPWSTR pszTargetProcess = TEXT("C:\\Windows\\System32\\cmd.exe");
	LPWSTR pszInjectedDll = TEXT("C:\\Users\\alexi\\source\\repos\\sample-hook-directory-listing\\sample-hook\\x64\\Debug\\sample-dll.dll");

	return inject_proc(pszTargetProcess, pszInjectedDll);
}