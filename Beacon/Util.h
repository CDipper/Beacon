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

void PutUint32BigEndian(uint8_t* bytes, uint32_t value);
void PutUint16BigEndian(uint8_t* bytes, uint16_t value);
unsigned char* RandomAESKey(unsigned char* aesKey, size_t keyLength);
int GenerateRandomInt(int min, int max);
uint8_t* CalcByte(uint8_t** arrays, size_t* sizes, size_t numArrays);
uint8_t* WriteInt(size_t nInt, uint8_t* bBytes);
unsigned char* base64Encode(unsigned char* data, size_t Length);
unsigned char* NetbiosDecode(unsigned char* data, int data_length, unsigned char key, size_t* NetbiosDecodelen);
unsigned char* NetbiosEncode(unsigned char* data, size_t data_length, unsigned char key, size_t* encoded_length);
unsigned char* MaskDecode(unsigned char* data, size_t data_length, unsigned char* key, int key_length);
unsigned char* MaskEncode(unsigned char* data, size_t data_length, size_t* mask_length);
unsigned char* AesCBCDecrypt(unsigned char* encryptData, unsigned char* key, size_t dataLen, size_t* decryptAES_CBCdatalen);
unsigned char* AesCBCEncrypt(unsigned char* data, unsigned char* key, size_t dataLen, size_t* encryptedDataLen);
uint32_t bigEndianUint32(uint8_t b[4]);
unsigned char* CodepageToUTF8(unsigned char* input, size_t inputLen, size_t* outputLen);
unsigned char* HMkey( unsigned char* encryptedBytes, size_t encryptedBytesLen);
unsigned char* str_replace_all(unsigned char* str, unsigned char* find, unsigned char* replace);
uint16_t Readshort(uint8_t* b);
BOOL SHA256_Hash(unsigned char* input, DWORD inputLength, unsigned char* output);

#define HMAC_KEY_LENGTH 16  // HMAC KeyµÄ³¤¶È
extern unsigned char Hmackey[16];

