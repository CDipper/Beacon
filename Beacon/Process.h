#pragma once
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

BOOL is_x64();
BOOL is_wow64(HANDLE process);
BOOL is_x64_process(HANDLE process);
BOOL IsProcessX64(DWORD pid);
BOOL GetProcessUserInfo(HANDLE hProcess, unsigned char* userSid);
BOOL GetUserSid(size_t length, HANDLE hToken, unsigned char* result);
VOID CmdPs(unsigned char* command, size_t command_length);