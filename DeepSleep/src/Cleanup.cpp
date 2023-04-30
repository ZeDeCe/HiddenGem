#include "Cleanup.h"
// Credit by request

#pragma GCC push_options
//#pragma runtime_checks( "", off )

//#pragma optimize("", off)
#pragma GCC optimize ("O0")

//#pragma code_seg(".text$AAAA")

void
//__declspec(safebuffers)
//__attribute__((noinline))
__attribute__((section(".text$AAAA")))
WINAPI Cleanup(struct CleanupParams* params)  {
    SLEEP2 _sleep = (SLEEP2)(params->sleep);
    _sleep(5000);

    DWORD oldprot;
    VIRTUALPROTECT _virtualProtect = (VIRTUALPROTECT)(params->virtualProtect);
    _virtualProtect(params->myPage, params->myPageLength, PAGE_EXECUTE_READWRITE, &oldprot);
    ForcedSecureMemory(params->myPage, params->myPageLength);

    VIRTUALFREE _virtualFree = (VIRTUALFREE)(params->virtualFree);
    _virtualFree(params->myPage, 0, MEM_RELEASE);
}

//#pragma code_seg(".text$AAAB")

void __attribute__((section(".text$AAAB"))) CleanupEnd()
{
	// Left blank
}

//#pragma runtime_checks( "", restore)
#pragma GCC pop_options