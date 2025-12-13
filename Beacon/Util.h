#pragma once
#include "MetaData.h"
#include <Psapi.h>
#include <dbghelp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <ncrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")

#pragma warning(disable:4996) 

wchar_t* convertToWideChar(char* input);
unsigned char* convertWideCharToUTF8(wchar_t* wideStr);
void PutUint32BigEndian(uint8_t* bytes, uint32_t value);
void PutUint16BigEndian(uint8_t* bytes, uint16_t value);
BOOL RandomAESKey(unsigned char* aesKey, size_t keyLength);
int GenerateRandomInt(int min, int max);
unsigned char* base64Encode(unsigned char* data, size_t Length);
unsigned char* NetbiosDecode(unsigned char* data, size_t data_length, char key, size_t* NetbiosDecodelen);
unsigned char* NetbiosEncode(unsigned char* data, size_t data_length, char key, size_t* encoded_length);
unsigned char* MaskDecode(unsigned char* data, size_t data_length, unsigned char* key, int key_length);
unsigned char* MaskEncode(unsigned char* data, size_t data_length, size_t* mask_length);
unsigned char* AesCBCDecrypt(unsigned char* encryptData, unsigned char* key, size_t dataLen, size_t* decryptAES_CBCdatalen);
unsigned char* AesCBCEncrypt(unsigned char* data, unsigned char* key, size_t dataLen, size_t* encryptedDataLen);
unsigned char* HMkey( unsigned char* encryptedBytes, size_t encryptedBytesLen);
unsigned char* str_replace_all(unsigned char* str, unsigned char* find, unsigned char* replace);
BOOL SHA256_Hash(unsigned char* input, DWORD inputLength, unsigned char* output);


#define HMAC_KEY_LENGTH 16 
extern char g_hmackey[16];

