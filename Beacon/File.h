#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iphlpapi.h>

#define PATH_MAX 4096
#define MAX_PATH_LENGTH 1048
#define MAX_TIME_STRING_LENGTH 50
#define MAX_EXISTING_FILENAME 0x2000
#define MAX_NEW_FILENAME      0x2000
#define MAX_FILENAME 0x4000
#define MAX_BUFFER  2048
#define MAX_POST_FILENAME 2048 
#define MAX_PACKET 1024 * 512
#define MAX_DOWNLOAD_BUFFER 1024 * 256

#define SOURCE_DIRECTORY "\\*"

struct FileThreadArgs {
    char* fileNameBuf;
    size_t fileNameBufLen;
};

// ¸¨Öúº¯Êý£º×·¼Óµ½ resultStr
#define APPEND_FMT(fmt, ...) do { \
        wchar_t temp[1024]; \
        int n = swprintf(temp, 1024, fmt, __VA_ARGS__); \
        if (n > 0) { \
            size_t needed = bufLen + n + 1; \
            if (needed > bufCap) { \
                bufCap = needed * 2; \
                resultStr = (wchar_t*)realloc(resultStr, bufCap * sizeof(wchar_t)); \
                if (!resultStr) { \
                    _findclose(handle); \
                    free(path); \
                    return NULL; \
                } \
            } \
            wcscpy(resultStr + bufLen, temp); \
            bufLen += n; \
        } \
    } while(0)

unsigned char* listDirectory(char* dirPathStr, size_t * dirPathStrLen);
DWORD WINAPI downloadThread(LPVOID lpParam);
