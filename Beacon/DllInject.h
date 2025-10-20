#pragma once
#include <windows.h>
#include <stdint.h>

typedef struct {
	HANDLE hProcess;
	HANDLE hThread;
	DWORD  injectPid;
	BYTE   targetArch;
	BYTE   myArch;
	BOOL   sameArch;
	BOOL   samePid;
	BOOL   isSuspended;
} INJECTCONTEXT;

#define INJECT_ARCH_X86 0
#define INJECT_ARCH_X64 1

VOID InjectProcessLogic(PROCESS_INFORMATION* pi, HANDLE hProcess, size_t injectPid, unsigned char* buffer, size_t length, uint32_t offset, void* parameter, int plen);
VOID InjectProcess(INJECTCONTEXT* context, unsigned char* buffer, size_t length, size_t offset, void* parameter);
VOID initializeInjectContext(INJECTCONTEXT* context, PROCESS_INFORMATION* pi, HANDLE hProcess, DWORD injectPid);
unsigned char* localAllocdata(unsigned char* buffer, size_t length);
unsigned char* remoteAllocdata(INJECTCONTEXT* context, unsigned char* buffer, size_t length);
VOID InjectProcessExecute(INJECTCONTEXT* context, unsigned char* ptr, size_t offset, void* parameter);
VOID InjectViaResumethread(HANDLE hThread, LPVOID lpStartAddress, LPVOID lpParameter);