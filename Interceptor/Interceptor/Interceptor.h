#pragma once
#include "Globals.h"
#include "Intercept.h"
#include "Callbacks.h"

WINDOWS_INDEX GetWindowsIndex();

void InterceptUnload(PDRIVER_OBJECT);
NTSTATUS InterceptCreateClose(PDEVICE_OBJECT, PIRP);
NTSTATUS InterceptDeviceControl(PDEVICE_OBJECT, PIRP);
NTSTATUS CompleteRequest(PIRP, NTSTATUS, ULONG_PTR);
NTSTATUS InterceptGenericDispatch(PDEVICE_OBJECT, PIRP);
void GenericDriverUnload(PDRIVER_OBJECT);