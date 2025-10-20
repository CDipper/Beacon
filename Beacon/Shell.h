#pragma once
#include <windows.h>

typedef struct {
    unsigned char* shellPath;
    unsigned char* shellBuf;
} ParseCommandShellStruct;

struct ShellThreadArgs {
    unsigned char* cmdBuffer;
    size_t cmdBufferLength;
};

ParseCommandShellStruct ParseCommandShell(unsigned char* cmdBuffer, int cmdBufferLength);
DWORD WINAPI myThreadCmdRun(LPVOID lpParam);
DWORD WINAPI myThreadCmdshell(LPVOID lpParam);