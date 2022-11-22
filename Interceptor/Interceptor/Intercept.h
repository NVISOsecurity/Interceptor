#pragma once
#include "Globals.h"

extern "C"
NTSYSAPI
NTSTATUS NTAPI ObReferenceObjectByName(
	_In_ PUNICODE_STRING ObjectPath,
	_In_ ULONG Attributes,
	_In_opt_ PACCESS_STATE PassedAccessState,
	_In_opt_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE AccessMode,
	_Inout_opt_ PVOID ParseContext,
	_Out_ PVOID * Object);

extern "C" POBJECT_TYPE * IoDriverObjectType;

struct INTERCEPTED_DRIVER {
	WCHAR DriverName[64];
	PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
	PDRIVER_OBJECT DriverObject;
	PDRIVER_UNLOAD DriverUnload;
	PDEVICE_OBJECT DeviceObjects[4];
};

const int MaxIntercept = 64;

struct INTERCEPT_GLOBALS {
	INTERCEPTED_DRIVER Drivers[MaxIntercept];
	short Count;
};

extern INTERCEPT_GLOBALS g_InterceptGlobals;

NTSTATUS ListDrivers(PINTERCEPTOR_BUFFER);
NTSTATUS GetDriverName(ULONG, PCHAR&);
NTSTATUS HookDriver(PCWSTR);
NTSTATUS UnhookDriver(int);
NTSTATUS UnhookDriver(PVOID);
NTSTATUS UnhookAllDrivers();
BOOLEAN isTargetIrp(PIRP);
BOOLEAN isDiscardIrp(PIRP);
NTSTATUS ModifyIrp(PIRP);
extern NTSTATUS CheckEDR(PINTERCEPTOR_BUFFER, PCHAR);

extern NTSTATUS CompleteRequest(PIRP, NTSTATUS, ULONG_PTR);
extern NTSTATUS InterceptGenericDispatch(PDEVICE_OBJECT, PIRP);
extern void GenericDriverUnload(PDRIVER_OBJECT);