#pragma once
#include <windows.h>
#include <stdio.h>

BOOL PipeWaitForExec(HANDLE hNamedPipe, DWORD waitTime, int iterWaitTime);
BOOL PipeConnect(LPCSTR lpFileName, HANDLE* pipe, DWORD flags);
int PipeConnectWithTokenNoFlags(LPCSTR filename, HANDLE* pipe);
int PipeConnectWithToken(LPCSTR filename, HANDLE* pipe, DWORD flags);



