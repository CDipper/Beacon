#pragma once
#include <windows.h>

typedef struct {
    unsigned char* shellPath;
    unsigned char* shellBuf;
} CommandShell;

struct ShellThreadArgs {
    unsigned char* cmd_buffer;
    size_t cmd_length;
};

CommandShell parse_command(unsigned char* cmdBuffer, int cmdBufferLength);
DWORD WINAPI ThreadCmdRun(LPVOID lpParam);
DWORD WINAPI ThreadCmdshell(LPVOID lpParam);