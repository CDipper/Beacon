#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define RDATA_RELOC_TYPE 1024
#define DATA_RELOC_TYPE 1025
#define EXE_RELOC_TYPE 1026
#define DYNAMIC_FUNC_RELOC_TYPE 1027
#define END_RELOC_TYPE 1028

typedef struct _BEACON_RELOCATION {
	unsigned short relocType;
	union {
		short secType;
		short funcType;
	} beaconRelocType;
	long rvaddre;
	unsigned long value;
} BEACON_RELOCATION, * PBEACON_RELOCATION;


