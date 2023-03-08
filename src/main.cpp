// https://github.com/x86ptr/apiresolver

#include <iostream>
#include <Windows.h>

extern "C" HMODULE WINAPI _GetModuleHandle(const char* ModuleName);
extern "C" FARPROC WINAPI _GetProcAddress(HMODULE hModule, const char *ProcName);

typedef LPVOID (WINAPI *pVirtualAlloc)(
	LPVOID,
	SIZE_T, 
	DWORD,
	DWORD
);

typedef HANDLE (WINAPI *pCreateThread)(
	LPSECURITY_ATTRIBUTES, 
	SIZE_T, 
	LPTHREAD_START_ROUTINE,
	LPVOID, 
	DWORD, 
	LPDWORD
);

int main() {
	unsigned char shellcode[] = {
		"\x90" // NOP
		"\x90" // NOP
		"\xCC" // INT3
		"\xC3" // RET
	};
	LPVOID exec_mem;
	HMODULE hModule;
	HANDLE hThread;
	pVirtualAlloc _VirtualAlloc;
	pCreateThread _CreateThread;

	hModule = _GetModuleHandle("kernel32.dll");
	if(hModule == INVALID_HANDLE_VALUE)
	{
		// std::cout << "_GetModuleHandle() failed!\n";
		exit(EXIT_FAILURE);
	}
	// std::cout << "kernel32.dll BaseAddress: 0x" << (void*)hModule << std::endl;

	_VirtualAlloc = (pVirtualAlloc)_GetProcAddress(hModule, "VirtualAlloc");
	if(_VirtualAlloc == INVALID_HANDLE_VALUE)
	{
		// std::cout << "_GetProcAddress() failed!\n";
		exit(EXIT_FAILURE);
	}
	// std::cout << "VirtualAlloc VA: 0x" << (void*)_VirtualAlloc << std::endl;

	exec_mem = _VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	RtlCopyMemory(exec_mem, shellcode, sizeof(shellcode));
	
	_CreateThread = (pCreateThread)_GetProcAddress(hModule, "CreateThread");
	if(_CreateThread == INVALID_HANDLE_VALUE)
	{
		// std::cout << "_GetProcAddress() failed!\n";
		exit(EXIT_FAILURE);
	}
	// std::cout << "CreateThread VA: 0x" << (void*)_CreateThread << std::endl;

	hThread = _CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
	if(hThread != INVALID_HANDLE_VALUE)
		WaitForSingleObject(hThread, INFINITE);

	return 0;
}
