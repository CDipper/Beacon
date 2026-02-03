#include "Identity.h"
#include "Command.h"

unsigned char* CmdGetUid(size_t* post_length)
{
    char* computer_name = malloc(MAX_COMPUTERNAME_LENGTH + 1);
    char* user_name = malloc(UNLEN + 1);

    if (!computer_name || !user_name) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameA(computer_name, &size)) {
        fprintf(stderr, "GetComputerNameA failed: %lu\n", GetLastError());
        goto cleanup;
    }

    size = UNLEN + 1;
    if (!GetUserNameA(user_name, &size)) {
        fprintf(stderr, "GetUserNameA failed: %lu\n", GetLastError());
        goto cleanup;
    }

    // '\' + '\0'
    size_t len = strlen(computer_name) + strlen(user_name) + 2;

    unsigned char* post_buffer = malloc(len);
    if (!post_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    snprintf((char*)post_buffer, len, "%s\\%s", computer_name, user_name);

    // 不包含 '\0'
    *post_length = len - 1;

    free(computer_name);
    free(user_name);
    return post_buffer;

cleanup:
    free(computer_name);
    free(user_name);
    return NULL;
}

// 是对当前进程的环境变量
unsigned char* CmdSetEnv(unsigned char* command_buffer, size_t command_length, size_t* post_length) {
    // 返回 0 表示成功
    if (putenv(command_buffer)) {
        fprintf(stderr, "putenv failed\n");
        return NULL;
    }

    unsigned char* result = "[*] Success!";
    unsigned char* post_buffer = malloc(strlen(result));
    if (!post_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    memcpy(post_buffer, result, strlen(result));
    *post_length = strlen(result);

    return post_buffer;
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

unsigned char* CmdGetPrivs(size_t* post_length) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        fprintf(stderr, "OpenProcessToken failed with error:%lu\n", GetLastError());
        return NULL;
    }

    DWORD needed = 0;
    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &needed) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        fprintf(stderr, "GetTokenInformation failed with error:%lu\n", GetLastError());
        CloseHandle(hToken);
        return NULL;
    }

    PTOKEN_PRIVILEGES pTP = (PTOKEN_PRIVILEGES)malloc(needed);
    if (!pTP) {
        CloseHandle(hToken);
        return NULL;
    }

    if (!GetTokenInformation(hToken, TokenPrivileges, pTP, needed, &needed)) {
        fprintf(stderr, "GetTokenInformation failed with error:%lu\n", GetLastError());
        free(pTP);
        CloseHandle(hToken);
        return NULL;
    }

    // 初始标题行
    size_t total_length = strlen("Privilege\t\t\t\tDescription\t\t\t\tState\r\n") + 1;

    // 第一次遍历：计算总长度
    for (DWORD i = 0; i < pTP->PrivilegeCount; i++) {
        LUID luid = pTP->Privileges[i].Luid;

        char name[256]; 
        DWORD nameLen = _countof(name);
        if (!LookupPrivilegeNameA(NULL, &luid, name, &nameLen)) {
            strcpy_s(name, sizeof(name), "(<unknown>");
        }

        char desc[512]; 
        DWORD descLen = _countof(desc);
        DWORD dwLangId = 0;
        if (!LookupPrivilegeDisplayNameA(NULL, name, desc, &descLen, &dwLangId)) {
            strcpy_s(desc, sizeof(desc), name);
        }

        unsigned char* state = AttrToStateStringA(pTP->Privileges[i].Attributes);

        total_length += strlen(name) + strlen(desc) + strlen(state) + 2 * sizeof("\t\t\t\t");
    }

    // 分配缓冲区
    unsigned char* post_buffer = (unsigned char*)malloc(total_length);
    if (!post_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        free(pTP);
        CloseHandle(hToken);
        return NULL;
    }

    strcpy_s(post_buffer, total_length, "Privilege\t\t\t\tDescription\t\t\t\tState\r\n");

    // 第二次遍历：拼接字符串
    for (DWORD i = 0; i < pTP->PrivilegeCount; i++) {
        LUID luid = pTP->Privileges[i].Luid;

        char name[256]; 
        DWORD nameLen = _countof(name);
        if (!LookupPrivilegeNameA(NULL, &luid, name, &nameLen)) {
            strcpy_s(name, sizeof(name), "<unknown>");
        }

        char desc[512]; 
        DWORD descLen = _countof(desc);
        DWORD dwLangId = 0;
        if (!LookupPrivilegeDisplayNameA(NULL, name, desc, &descLen, &dwLangId)) {
            strcpy_s(desc, sizeof(desc), name);
        }

        const unsigned char* state = AttrToStateStringA(pTP->Privileges[i].Attributes);

        char line[1024];
        _snprintf_s(line, sizeof(line), _TRUNCATE, "%s\t\t\t\t%s\t\t\t\t%s\r\n", name, desc, state);

        strcat_s(post_buffer, total_length, line);
    }

    free(pTP);
    CloseHandle(hToken);

    *post_length = total_length - 1;

    return post_buffer;
}