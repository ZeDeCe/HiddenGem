#pragma once
#include "windows.h"
#include "ApiResolve.h"


// Copied from SecureZeroMemory
FORCEINLINE PVOID ForcedSecureMemory(_Out_writes_bytes_all_(cnt) PVOID ptr,_In_ SIZE_T cnt)
{
    volatile char* vptr = (volatile char*)ptr;
#if defined(_M_AMD64) && !defined(_M_ARM64EC)
    __stosb((PBYTE)((DWORD64)vptr), 0, cnt);
#else
    while (cnt) {
#if !defined(_M_CEE) && (defined(_M_ARM) || defined(_M_ARM64) || defined(_M_ARM64EC))
        __iso_volatile_store8(vptr, 0);
#else
        * vptr = 0;
#endif
        vptr++;
        cnt--;
    }
#endif // _M_AMD64 && !defined(_M_ARM64EC)
    return ptr;
}

struct CleanupParams {
    LPVOID myPage;
    SIZE_T myPageLength;
    PVOID virtualFree;
    PVOID sleep;
    PVOID virtualProtect;
};
#ifdef __cplusplus
extern "C" {
#endif

    void WINAPI Cleanup(struct CleanupParams* params);

    void CleanupEnd();

#ifdef __cplusplus
}
#endif
 
