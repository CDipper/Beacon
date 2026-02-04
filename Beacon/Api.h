#pragma once
#include <windows.h>

typedef struct
{
	char* buffer;
	int size;
} sizedbuf;

/* data API - unpacks data */
typedef struct {
	char* original; /* the original buffer [so we can free it] */
	char* buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} datap;

datap*  BeaconDataAlloc(int size);
void    BeaconDataFree(datap* parser);
void    BeaconDataParse(datap* parser, char* buffer, int size);
char*   BeaconDataPtr(datap* parser, int size);
int     BeaconDataInt(datap* parser);
short   BeaconDataShort(datap* parser);
char    BeaconDataByte(datap* parser);
char*   BeaconDataStringPointer(datap* parser);
int     BeaconDataStringCopySafe(datap* parse, char* buffer, int max);
char*   BeaconDataStringPointerCopy(datap* parser, int max);
int     BeaconDataStringCopy(datap* parser, char* buffer, int size);
char*   BeaconDataOriginal(datap* parser);
char*   BeaconDataBuffer(datap* parser);
int     BeaconDataLength(datap* parser);
char*   BeaconDataLengthAndString(datap* parser, sizedbuf* sb);
char*   BeaconDataExtract(datap* parser, int* size);
void    BeaconDataZero(datap* parser);

/* format API - packs data */
typedef datap formatp;

void    BeaconFormatAlloc(formatp* format, int maxsz);
void    BeaconFormatUse(formatp* format, char* buffer, int size);
void    BeaconFormatReset(formatp* format);
void    BeaconFormatAppend(formatp* format, char* text, int len);
void    BeaconFormatPrintf(formatp* format, char* fmt, ...);
void    BeaconFormatFree(formatp* format);
void    BeaconFormatInt(formatp* format, int value);
void    BeaconFormatShort(formatp* format, short value);
void    BeaconFormatChar(formatp* format, char value);
char*   BeaconFormatOriginal(formatp* format);
char*   BeaconFormatBuffer(formatp* format);
int     BeaconFormatLength(formatp* format);

/* once you're done with the format... */
char*   BeaconFormatToString(formatp* format, int* size);
 
/* Output Functions */

void    BeaconOutput(int type, char* data, int len);
void    BeaconPrintf(int type, char* fmt, ...);

void    BeaconErrorD(int type, int d1);
void    BeaconErrorDD(int type, int d1, int d2);
void    BeaconErrorNA(int type);
// void    BeaconErrorS(int type, char* s1);
// void    BeaconErrorDS(int type, int d1, char* s1);
// void    BeaconErrorDDS(int type, int d1, int d2, char* s1);
// void    BeaconErrorPrintf(int type, char* fmt, ...);

/* Token Functions */
BOOL   BeaconUseToken(HANDLE token);
void   BeaconRevertToken(void);
BOOL   BeaconIsAdmin(void);

/* Spawn+Inject Functions */
void   BeaconGetSpawnTo(BOOL x86, char* buffer, int length);
void   BeaconInjectProcess(HANDLE hProcess, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len);
void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len);
BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO* si, PROCESS_INFORMATION* pInfo);
void   BeaconCleanupProcess(PROCESS_INFORMATION* pInfo);

/* Utility Functions */
BOOL   toWideChar(char* src, wchar_t* dst, int max);

#define MAX_DYNAMIC_FUNCTIONS 32

typedef struct _Beacon_Internal_Api
{
	HMODULE(*fnLoadLibraryA)(LPCSTR lpLibFileName);
	BOOL(*fnFreeLibrary)(HMODULE hLibModule);
	FARPROC(*fnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
	HMODULE(*fnGetModuleHandleA)(LPCSTR lpModuleName);
	/*
	* data API
	*/
	void (*fnBeaconDataParse)(datap* parser, char* buffer, int size);
	char* (*fnBeaconDataPtr)(datap* parser, int size);
	int (*fnBeaconDataInt)(datap* parser);
	short (*fnBeaconDataShort)(datap* parser);
	int (*fnBeaconDataLength)(datap* parser);
	char* (*fnBeaconDataExtract)(datap* parser, int* size);
	/*
	* format api
	*/
	void (*fnBeaconFormatAlloc)(formatp* format, int maxsz);
	void (*fnBeaconFormatReset)(formatp* format);
	void (*fnBeaconFormatPrintf)(formatp* format, char* fmt, ...);
	void (*fnBeaconFormatAppend)(formatp* format, char* text, int len);
	void (*fnBeaconFormatFree)(formatp* format);
	char* (*fnBeaconFormatToString)(formatp* format, int* size);
	void (*fnBeaconFormatInt)(formatp* format, int value);
	/*
	* hash api
	*/
	void (*fnBeaconOutput)(int type, char* data, int len);
	void (*fnBeaconPrintf)(int type, char* fmt, ...);
	void (*fnBeaconErrorD)(int type, int d1);
	void (*fnBeaconErrorDD)(int type, int d1, int d2);
	void (*fnBeaconErrorNA)(int type);
	/*
	* token api
	*/
	BOOL(*fnBeaconUseToken)(HANDLE token);
	BOOL(*fnBeaconIsAdmin)();
	void (*fnBeaconRevertToken)();
	/*
	* spawn and inject api
	*/
	void (*fnBeaconGetSpawnTo)(BOOL x86, char* buffer, int length);
	void (*fnBeaconCleanupProcess)(PROCESS_INFORMATION* pInfo);
	void (*fnBeaconInjectProcess)(HANDLE hProcess, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len);
	BOOL(*fnBeaconSpawnTemporaryProcess)(BOOL x86, BOOL ignoreToken, STARTUPINFO* si, PROCESS_INFORMATION* pInfo);
	void (*fnBeaconInjectTemporaryProcess)(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len);
	/*
	* util api
	*/
	BOOL(*fnToWideChar)(char* src, wchar_t* dst, int max);
	/*
	* other api
	*/
	void* dynamicFns[MAX_DYNAMIC_FUNCTIONS];
} Beacon_Internal_Api;

void BeaconInternalAPI(Beacon_Internal_Api* beaconInternalApi);