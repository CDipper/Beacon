#include "Pipe.h"

BOOL PipeWaitForExec(HANDLE hPipe, DWORD waite_time, int iter_time)
{
	DWORD timeout = GetTickCount64() + waite_time;
	DWORD available;

	while (GetTickCount64() < timeout)
	{
		if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &available, NULL))
		{
			fprintf(stderr, "PeekNamePipe failed with error:%lu\n", GetLastError());
			return FALSE;
		}

		if (available)
		{
			return TRUE;
		}

		Sleep(iter_time);
	}

	return FALSE;
}

int PipeConnectWithToken(LPCSTR pipe_name, HANDLE* hPipe, DWORD flags)
{
	if (flags)
		return PipeConnect(pipe_name, hPipe, flags);

	return PipeConnectWithTokenNoFlags(pipe_name, hPipe);
}

BOOL PipeConnect(LPCSTR pipe_name, HANDLE* hPipe, DWORD flags)
{
	while (TRUE)
	{
		*hPipe = CreateFileA(pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, flags, NULL);
		if (*hPipe != INVALID_HANDLE_VALUE)
		{
			DWORD mode = PIPE_READMODE_BYTE;
			if (!SetNamedPipeHandleState(*hPipe, &mode, NULL, NULL))
			{
				DisconnectNamedPipe(*hPipe);
				CloseHandle(*hPipe);
				return FALSE;
			}

			return TRUE;
		}

		if (GetLastError() != ERROR_PIPE_BUSY)
		{
			return FALSE;
		}

		if (!WaitNamedPipeA(pipe_name, 10000))
		{
			SetLastError(WAIT_TIMEOUT);
			return FALSE;
		}
	}
}

int PipeConnectWithTokenNoFlags(LPCSTR pipe_name, HANDLE* hPipe)
{
	if (PipeConnect(pipe_name, hPipe, 0))
		return TRUE;

	BOOL bRet = FALSE;
	/*
	* 暂时不处理权限相关的
	*/

	return bRet;
}