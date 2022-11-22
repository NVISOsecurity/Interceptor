#pragma once
#include "pch.h"
#include "Common.h"
#include "SpinLock.h"
#include "FastMutex.h"
#include <aux_klib.h>
#include <stdlib.h>
#include <string.h>

#define DRIVER_PREFIX "Interceptor: "
const ULONG DRIVER_TAG = 'RCRI';

typedef enum _WINDOWS_INDEX {
	WindowsIndexUNSUPPORTED = 0,
	WindowsIndexWIN7 = 0,
	WindowsIndexWIN10_18 = 0,
	WindowsIndexWIN10_19 = 1,
	WindowsIndexWIN11 = 1,
} WINDOWS_INDEX, * PWINDOWS_INDEX;

typedef struct _CALLBACK_DATA {
	CHAR module[64];
	BOOLEAN patched;
	UCHAR instruction[8];
} CALLBACK_DATA, * PCALLBACK_DATA;

typedef struct _REGISTERED_CALLBACKS {
	CALLBACK_DATA ProcessCallbacks[64];
	CALLBACK_DATA ThreadCallbacks[64];
	CALLBACK_DATA ImageCallbacks[64];
	CALLBACK_DATA RegistryCallbacks[64];
	CALLBACK_DATA ObjectProcessCallbacks[64][2];
	CALLBACK_DATA ObjectThreadCallbacks[64][2];
} REGISTERED_CALLBACKS, * PREGISTERED_CALLBACKS;

#define EDR_DRIVER_COUNT 116
typedef struct EDR_DRIVER_DATA {
	struct EDR {
		const char* name;
		PCWCHAR vendor;
	} EDR[EDR_DRIVER_COUNT];
} EDR_DRIVER_DATA, * PEDR_DRIVER_DATA;

extern WINDOWS_INDEX g_WindowsIndex;
extern EDR_DRIVER_DATA g_EDRDriverData;