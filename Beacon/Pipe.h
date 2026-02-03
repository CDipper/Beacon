#pragma once
#include <windows.h>
#include <stdio.h>

BOOL PipeWaitForExec(HANDLE hPipe, DWORD waite_time, int iter_time);
BOOL PipeConnect(LPCSTR pipe_name, HANDLE* hPipe, DWORD flags);
int PipeConnectWithTokenNoFlags(LPCSTR pipe_name, HANDLE* hPipe);
int PipeConnectWithToken(LPCSTR pipe_name, HANDLE* hPipe, DWORD flags);



