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

#define HMAC_KEY_LENGTH 16 
extern char g_hmackey[16];

// function api
wchar_t* convert_2_wchar(char* data);
unsigned char* convert_2_utf8(wchar_t* wdata);
BOOL generate_random_aes_key(unsigned char* key, size_t key_length);
int generate_random_data(int min, int max);
void PutUint32BigEndian(uint8_t* b, uint32_t v);
unsigned char* str_replace_all(unsigned char* str, unsigned char* find, unsigned char* replace);

// coding api
unsigned char* base64Encode(unsigned char* data, size_t data_length);
unsigned char* NetbiosDecode(unsigned char* data, size_t data_length, char key, size_t* netbios_dec_data_length);
unsigned char* NetbiosEncode(unsigned char* data, size_t data_length, char key, size_t* encoded_length);
unsigned char* MaskDecode(unsigned char* data, size_t data_length, unsigned char* key, int key_length);
unsigned char* MaskEncode(unsigned char* data, size_t data_length, size_t* mask_length);

// aes api
unsigned char* Aes_CBC_Decrypt(unsigned char* encrypt_data, unsigned char* key, size_t dataLen, size_t* CBC_data_length);
unsigned char* Aes_CBC_Encrypt(unsigned char* raw_data, unsigned char* key, size_t dataLen, size_t* enc_data_length);

// hash api
unsigned char* HMkey( unsigned char* encrypted_bytes, size_t encrypted_bytes_length);
BOOL sha256_hash(unsigned char* key, DWORD key_length, unsigned char* hash);
