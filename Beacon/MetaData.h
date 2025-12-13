#pragma once
#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <winternl.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma warning(disable:4996) 

typedef struct {
    unsigned char* MakeMeta;
    size_t MakeMetaLen;
} MakeMetaInfoResult;

typedef struct {
    unsigned char* EncryptMetaData;
    DWORD EncryptMetaDataLen;
} EncryptMetadataResult;

#define MAX_INFO 256
#define MAX_COMPUTER_NAME 256
#define MAX_USER_NAME 256
#define MAX_FILE_NAME 256

#define MAX_GET 51200

#define METADATA_ID 0xBEEF

#define METADATA_FLAG_NOTHING 1
#define METADATA_FLAG_X64_AGENT 2
#define METADATA_FLAG_X64_SYSTEM 4
#define METADATA_FLAG_ADMIN 8

#define MAX_PACKET 0x80000

MakeMetaInfoResult MakeMetaInfo();
EncryptMetadataResult EncryMetadata();
ULONG GetIP();
