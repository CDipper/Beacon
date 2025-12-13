#pragma once
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

// HTTP configuration
extern const wchar_t* g_server;
extern const wchar_t* g_get_path;
extern const wchar_t* g_post_path;
extern INTERNET_PORT g_port;
extern const wchar_t* g_host_header;
extern const wchar_t* g_user_agent_header;
extern const wchar_t* g_server_header;
extern const wchar_t* g_content_type_header;

// Metadata configuration
extern const char* g_metadata_prepend;
extern const char* g_metadata_header;
extern const char* g_response_prepend;
extern const char* g_response_append;

// POST data configuration
extern const char* g_http_post_id_prepend;
extern const char* g_http_post_id_append;
extern const char* g_http_post_client_output_prepend;
extern const char* g_http_post_client_output_append;
extern const char* g_post_header_name;

// Encryption configuration
extern char* g_public_key_str;
extern const char g_netbios_key;
extern const char g_iv[16];

// Runtime configuration
extern int g_sleeptime;
extern int g_jitter;
extern unsigned char g_aeskey[16];
extern unsigned char g_hmackey[16];
extern int g_counter;
extern int g_client_id;
