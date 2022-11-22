#pragma once
#include "Globals.h"

typedef struct _CALLBACK_ENTRY {
	INT16 Version; //0x0
	unsigned char unknown[6]; //0x2
	POB_OPERATION_REGISTRATION RegistrationContext; //0x8
	UNICODE_STRING Altitude; //0x10
} CALLBACK_ENTRY, * PCALLBACK_ENTRY; //header only: size 0x20

typedef struct _CALLBACK_ENTRY_ITEM {
	LIST_ENTRY EntryItemList; //0x0
	OB_OPERATION Operations; //0x10
	DWORD Active; //0x14
	PCALLBACK_ENTRY CallbackEntry; //0x18
	POBJECT_TYPE ObjectType; //0x20
	POB_PRE_OPERATION_CALLBACK PreOperation; //0x28
	POB_POST_OPERATION_CALLBACK PostOperation; //0x30
	__int64 unk; //0x38
} CALLBACK_ENTRY_ITEM, * PCALLBACK_ENTRY_ITEM; //size 0x40

typedef struct _OBJECT_TYPE {
	LIST_ENTRY TypeList; //0x0
	UNICODE_STRING Name; //0x10
	PVOID DefaultObject; //0x20
	ULONG Index; //0x28
	ULONG TotalNumberOfObjects; //0x2C
	ULONG TotalNumberOfHandles; //0x30
	ULONG HighWaterNumberOfObjects; //0x34
	ULONG HighWaterNumberOfHandles; //0x38
	unsigned char TypeInfo[0x78]; //0x40 _OBJECT_TYPE_INITIALIZER
	EX_PUSH_LOCK TypeLock; //0xB8
	ULONG Key; //0xC0
	LIST_ENTRY CallbackList; //0xC8
} OBJECT_TYPE, * POBJECT_TYPE;

#pragma warning(disable:4201)
typedef union {
	struct {
		UINT64 protection_enable : 1;
		UINT64 monitor_coprocessor : 1;
		UINT64 emulate_fpu : 1;
		UINT64 task_switched : 1;
		UINT64 extension_type : 1;
		UINT64 numeric_error : 1;
		UINT64 reserved_1 : 10;
		UINT64 write_protect : 1;
		UINT64 reserved_2 : 1;
		UINT64 alignment_mask : 1;
		UINT64 reserved_3 : 10;
		UINT64 not_write_through : 1;
		UINT64 cache_disable : 1;
		UINT64 paging_enable : 1;
	};

	UINT64 flags;
} cr0;

const UCHAR OPCODE_PSP[] = { 0x00, 0xe8 };
const UCHAR OPCODE_LEA_R13_1[] = { 0x00, 0x4c };
const UCHAR OPCODE_LEA_R13_2[] = { 0x00, 0x8d };
const UCHAR OPCODE_LEA_R13_3[] = { 0x00, 0x2d };

const UCHAR OPCODE_LEA_RCX_1[] = { 0x00, 0x48 };
const UCHAR OPCODE_LEA_RCX_2[] = { 0x00, 0x8d };
const UCHAR OPCODE_LEA_RCX_3[] = { 0x00, 0x0d };

const UCHAR OPCODE_LEA_RCX_4[] = { 0x00, 0x48 };
const UCHAR OPCODE_LEA_RCX_5[] = { 0x00, 0x8d };
const UCHAR OPCODE_LEA_RCX_6[] = { 0x00, 0x0d };

const UCHAR OPCODE_LEA_RCX_7[] = { 0x00, 0x48 };
const UCHAR OPCODE_LEA_RCX_8[] = { 0x00, 0x8d };
const UCHAR OPCODE_LEA_RCX_9[] = { 0x00, 0x0d };

extern REGISTERED_CALLBACKS g_CallbackGlobals;

void CR0_WP_OFF_x64();
void CR0_WP_ON_x64();
ULONG64 FindPspCreateProcessNotifyRoutine();
ULONG64 FindPsSetCreateThreadNotifyRoutine();
ULONG64 FindPsLoadImageNotifyRoutineEx();
ULONG64 FindCmUnregisterCallbackCallbackListHead();
PVOID* FindObRegisterCallbacksListHead(POBJECT_TYPE);
NTSTATUS PatchModule(PCHAR moduleName);
NTSTATUS PatchCallback(ULONG64, CALLBACK_TYPE);
NTSTATUS PatchCallbackList(ULONG64 index, PVOID* callbackListHead, CALLBACK_TYPE callback);
NTSTATUS PatchObCallbackList(ULONG64 index, PVOID* callbackListHead, CALLBACK_TYPE callback);
NTSTATUS RestoreCallback(ULONG64, CALLBACK_TYPE);
NTSTATUS RestoreCallbackList(ULONG64 index, PVOID* callbackListHead, CALLBACK_TYPE callback);
NTSTATUS RestoreObCallbackList(ULONG64 index, PVOID* callbackListHead, CALLBACK_TYPE callback);
NTSTATUS RestoreModule(PCHAR moduleName);
NTSTATUS RestoreAllCallbacks();
NTSTATUS ReadCallbackArray(PINTERCEPTOR_BUFFER, ULONG64, PCALLBACK_DATA);
NTSTATUS ReadCallbackList(PINTERCEPTOR_BUFFER, PVOID*, PCALLBACK_DATA);
NTSTATUS ReadObCallbackList(PINTERCEPTOR_BUFFER, PVOID*, CALLBACK_TYPE);
NTSTATUS ReadCallbacks(PINTERCEPTOR_BUFFER);
NTSTATUS GetModuleNameFromCallbackAddr(ULONG64, PCHAR&);
NTSTATUS GetModuleNameFromCallbackAddr(PINTERCEPTOR_BUFFER, ULONG64, PCHAR&);
ULONG64 GetKernelBaseAddress();
ULONG64 VerifyOffsets(LONG OffsetAddr, ULONG64 InstructionAddr);

extern NTSTATUS CheckEDR(PINTERCEPTOR_BUFFER, PCHAR);