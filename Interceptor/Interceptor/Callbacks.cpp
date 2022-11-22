#include "pch.h"
#include "Callbacks.h"

#pragma intrinsic(__readmsr)

REGISTERED_CALLBACKS g_CallbackGlobals;

void CR0_WP_OFF_x64() {
	ULONG CPUCount = KeQueryActiveProcessorCount(0);
	for (ULONG64 CPUIndex = 0; CPUIndex < CPUCount; CPUIndex++) {
		KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << CPUIndex));

		cr0 mycr0;
		mycr0.flags = __readcr0();
		mycr0.write_protect = 0;
		__writecr0(mycr0.flags);

		KeRevertToUserAffinityThreadEx(oldAffinity);
	}
}

void CR0_WP_ON_x64() {
	ULONG CPUCount = KeQueryActiveProcessorCount(0);
	for (ULONG64 CPUIndex = 0; CPUIndex < CPUCount; CPUIndex++) {
		KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << CPUIndex));

		cr0 mycr0;
		mycr0.flags = __readcr0();
		mycr0.write_protect = 1;
		__writecr0(mycr0.flags);

		KeRevertToUserAffinityThreadEx(oldAffinity);
	}
}

ULONG64 FindPspCreateProcessNotifyRoutine() {
	UNICODE_STRING func;
	RtlInitUnicodeString(&func, L"PsSetCreateProcessNotifyRoutine");

	ULONG64 funcAddr = (ULONG64)MmGetSystemRoutineAddress(&func);

	LONG OffsetAddr = 0;
	for (ULONG64 instructionAddr = funcAddr; instructionAddr < funcAddr + 20; instructionAddr++) {
		if ((*(PUCHAR)instructionAddr == OPCODE_PSP[g_WindowsIndex])) {
			OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(instructionAddr + 1), 4);

			funcAddr = funcAddr + (instructionAddr - funcAddr) + OffsetAddr + 5;
			break;
		}
	}

	for (ULONG64 instructionAddr = funcAddr; instructionAddr < funcAddr + 0xff; instructionAddr++) {
		if (*(PUCHAR)instructionAddr == OPCODE_LEA_R13_1[g_WindowsIndex] && 
			*(PUCHAR)(instructionAddr + 1) == OPCODE_LEA_R13_2[g_WindowsIndex] &&
			*(PUCHAR)(instructionAddr + 2) == OPCODE_LEA_R13_3[g_WindowsIndex]) {

			OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(instructionAddr + 3), 4);
			
			return VerifyOffsets(OffsetAddr, instructionAddr);
		}
	}
	KdPrint((DRIVER_PREFIX "Could not locate Process Callback Array\n"));
	return 0;
}

ULONG64 FindPsSetCreateThreadNotifyRoutine() {
	UNICODE_STRING func;
	RtlInitUnicodeString(&func, L"PsSetCreateThreadNotifyRoutine");

	ULONG64 funcAddr = (ULONG64)MmGetSystemRoutineAddress(&func);

	LONG OffsetAddr = 0;
	for (ULONG64 instructionAddr = funcAddr; instructionAddr < funcAddr + 20; instructionAddr++) {
		if ((*(PUCHAR)instructionAddr == OPCODE_PSP[g_WindowsIndex])) {
			OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(instructionAddr + 1), 4);
			funcAddr = funcAddr + (instructionAddr - funcAddr) + OffsetAddr + 5;
			break;
		}
	}

	for (ULONG64 instructionAddr = funcAddr; instructionAddr < funcAddr + 0xff; instructionAddr++) {
		if (*(PUCHAR)instructionAddr == OPCODE_LEA_RCX_1[g_WindowsIndex] &&
			*(PUCHAR)(instructionAddr + 1) == OPCODE_LEA_RCX_2[g_WindowsIndex] &&
			*(PUCHAR)(instructionAddr + 2) == OPCODE_LEA_RCX_3[g_WindowsIndex]) {

			OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(instructionAddr + 3), 4);

			return VerifyOffsets(OffsetAddr, instructionAddr);
		}
	}
	KdPrint((DRIVER_PREFIX "Could not locate Thread Callback Array\n"));
	return 0;
}

ULONG64 FindPsLoadImageNotifyRoutineEx() {
	UNICODE_STRING func;
	RtlInitUnicodeString(&func, L"PsSetLoadImageNotifyRoutineEx");

	ULONG64 funcAddr = (ULONG64)MmGetSystemRoutineAddress(&func);

	LONG OffsetAddr = 0;
	for (ULONG64 instructionAddr = funcAddr; instructionAddr < funcAddr + 0xff; instructionAddr++) {
		if (*(PUCHAR)instructionAddr == OPCODE_LEA_RCX_4[g_WindowsIndex] &&
			*(PUCHAR)(instructionAddr + 1) == OPCODE_LEA_RCX_5[g_WindowsIndex] &&
			*(PUCHAR)(instructionAddr + 2) == OPCODE_LEA_RCX_6[g_WindowsIndex]) {

			OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(instructionAddr + 3), 4);
			
			return VerifyOffsets(OffsetAddr, instructionAddr);
		}
	}
	KdPrint((DRIVER_PREFIX "Could not locate Image Callback Array\n"));
	return 0;
}

ULONG64 FindCmUnregisterCallbackCallbackListHead() {
	UNICODE_STRING func;
	RtlInitUnicodeString(&func, L"CmUnRegisterCallback");

	ULONG64 funcAddr = (ULONG64)MmGetSystemRoutineAddress(&func);

	LONG OffsetAddr = 0;
	for (ULONG64 instructionAddr = funcAddr; instructionAddr < funcAddr + 0xff; instructionAddr++) {
		if (*(PUCHAR)instructionAddr == OPCODE_LEA_RCX_7[g_WindowsIndex] &&
			*(PUCHAR)(instructionAddr + 1) == OPCODE_LEA_RCX_8[g_WindowsIndex] &&
			*(PUCHAR)(instructionAddr + 2) == OPCODE_LEA_RCX_9[g_WindowsIndex]) {

			OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(instructionAddr + 3), 4);
			
			return VerifyOffsets(OffsetAddr, instructionAddr);
		}
	}
	KdPrint((DRIVER_PREFIX "Could not locate Registry CallbackListHead\n"));
	return 0;
}

PVOID* FindObRegisterCallbacksListHead(POBJECT_TYPE pObType) {
	return (PVOID*)((__int64)pObType + 0xc8);
}

NTSTATUS PatchModule(PCHAR moduleName) {
	NTSTATUS status = STATUS_SUCCESS;

	for (int i = 0; i < 64; i++) {
		if (strcmp(g_CallbackGlobals.ProcessCallbacks[i].module, moduleName) == 0) {
			status = PatchCallback((ULONG)i, process);
			if (!NT_SUCCESS(status))
				return status;
		}

		if (strcmp(g_CallbackGlobals.ThreadCallbacks[i].module, moduleName) == 0) {
			status = PatchCallback((ULONG)i, thread);
			if (!NT_SUCCESS(status))
				return status;
		}

		if (strcmp(g_CallbackGlobals.ImageCallbacks[i].module, moduleName) == 0) {
			status = PatchCallback((ULONG)i, image);
			if (!NT_SUCCESS(status))
				return status;
		}

		/* temporary disable register callback patching due to crash
		if (strcmp(g_CallbackGlobals.RegistryCallbacks[i].module, moduleName) == 0) {
			status = PatchCallback((ULONG)i, registry);
			if (!NT_SUCCESS(status))
				return status;
		}
		*/

		if (strcmp(g_CallbackGlobals.ObjectProcessCallbacks[i][0].module, moduleName) == 0 || 
			strcmp(g_CallbackGlobals.ObjectProcessCallbacks[i][1].module, moduleName) == 0) {
			status = PatchCallback((ULONG)i, object_process);
			if (!NT_SUCCESS(status))
				return status;
		}

		if (strcmp(g_CallbackGlobals.ObjectThreadCallbacks[i][0].module, moduleName) == 0 ||
			strcmp(g_CallbackGlobals.ObjectThreadCallbacks[i][1].module, moduleName) == 0) {
			status = PatchCallback((ULONG)i, object_thread);
			if (!NT_SUCCESS(status))
				return status;
		}
	}
	return status;
}

NTSTATUS PatchCallback(ULONG64 index, CALLBACK_TYPE callback) {
	ULONG64 callbackArray = 0;

	switch (callback) {
		case process:
			callbackArray = FindPspCreateProcessNotifyRoutine();
			break;
		case thread:
			callbackArray = FindPsSetCreateThreadNotifyRoutine();
			break;
		case image:
			callbackArray = FindPsLoadImageNotifyRoutineEx();
			break;
		case registry:
			return PatchCallbackList(index, (PVOID*)FindCmUnregisterCallbackCallbackListHead(), callback);
			break;
		case object_process:
			return PatchObCallbackList(index, FindObRegisterCallbacksListHead(*PsProcessType), callback);
			break;
		case object_thread:
			return PatchObCallbackList(index, FindObRegisterCallbacksListHead(*PsThreadType), callback);
			break;
		default:
			return STATUS_NOT_SUPPORTED;
			break;
	}
	
	if (!callbackArray)
		return STATUS_UNSUCCESSFUL;

	ULONG64 magicPtr = callbackArray + index * 8;
	ULONG64 callbackFuncAddr = *(PULONG64)(magicPtr);

	if (MmIsAddressValid((PVOID)callbackFuncAddr) && callbackFuncAddr != 0) {
		callbackFuncAddr = *(PULONG64)(callbackFuncAddr & 0xFFFFFFFFFFFFFFF8);

		CR0_WP_OFF_x64();

		PULONG64 pPointer = (PULONG64)callbackFuncAddr;
		
		switch (callback) {
			case process:
				g_CallbackGlobals.ProcessCallbacks[index].patched = true;
				memcpy(g_CallbackGlobals.ProcessCallbacks[index].instruction, pPointer, 8);
				break;
			case thread:
				g_CallbackGlobals.ThreadCallbacks[index].patched = true;
				memcpy(g_CallbackGlobals.ThreadCallbacks[index].instruction, pPointer, 8);
				break;
			case image:
				g_CallbackGlobals.ImageCallbacks[index].patched = true;
				memcpy(g_CallbackGlobals.ImageCallbacks[index].instruction, pPointer, 8);
				break;
			default:
				return STATUS_NOT_SUPPORTED;
				break;
		}

		*pPointer = (ULONG64)0xC3;

		CR0_WP_ON_x64();

		return STATUS_SUCCESS;
	}
	else {
		return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS PatchCallbackList(ULONG64 index, PVOID* callbackListHead, CALLBACK_TYPE callback) {
	NTSTATUS status = STATUS_SUCCESS;
	PLIST_ENTRY pEntry;
	ULONG64 i;

	if (callbackListHead) {
		for (pEntry = (PLIST_ENTRY)*callbackListHead, i = 0; pEntry != (PLIST_ENTRY)callbackListHead; pEntry = (PLIST_ENTRY)(pEntry->Flink), i++) {
			if (i == index) {
				auto callbackFuncAddr = *(ULONG64*)((ULONG_PTR)pEntry + 0x028);

				CR0_WP_OFF_x64();

				PULONG64 pPointer = (PULONG64)callbackFuncAddr;

				switch (callback) {
					case registry:
						g_CallbackGlobals.RegistryCallbacks[index].patched = true;
						memcpy(g_CallbackGlobals.RegistryCallbacks[index].instruction, pPointer, 8);
						break;
					default:
						return STATUS_NOT_SUPPORTED;
						break;
				}

				*pPointer = (ULONG64)0xC3;

				CR0_WP_ON_x64();

				return STATUS_SUCCESS;
			}
		}
	}
	else {
		status = STATUS_INVALID_ADDRESS;
	}
	return status;
}

NTSTATUS PatchObCallbackList(ULONG64 index, PVOID* callbackListHead, CALLBACK_TYPE callback) {
	NTSTATUS status = STATUS_SUCCESS;
	PLIST_ENTRY pEntry;
	ULONG64 i;

	if (callbackListHead) {
		for (pEntry = (PLIST_ENTRY)*callbackListHead, i = 0; (pEntry != (PLIST_ENTRY)callbackListHead); pEntry = (PLIST_ENTRY)(pEntry->Flink), i++) {
			if (i == index) {
				auto preOpCallbackFuncAddr = *(ULONG64*)((ULONG_PTR)pEntry + 0x28);
				if (MmIsAddressValid((PVOID*)preOpCallbackFuncAddr)) {
					CR0_WP_OFF_x64();

					PULONG64 pPointer = (PULONG64)preOpCallbackFuncAddr;

					switch (callback) {
						case object_process:
							g_CallbackGlobals.ObjectProcessCallbacks[index][0].patched = true;
							memcpy(g_CallbackGlobals.ObjectProcessCallbacks[index][0].instruction, pPointer, 8);
							break;
						case object_thread:
							g_CallbackGlobals.ObjectThreadCallbacks[index][0].patched = true;
							memcpy(g_CallbackGlobals.ObjectThreadCallbacks[index][0].instruction, pPointer, 8);
							break;
						default:
							return STATUS_NOT_SUPPORTED;
							break;
					}

					*pPointer = (ULONG64)0xC3;

					CR0_WP_ON_x64();
				}

				auto postOpCallbackFuncAddr = *(ULONG64*)((ULONG_PTR)pEntry + 0x30);
				if (MmIsAddressValid((PVOID*)postOpCallbackFuncAddr)) {
					CR0_WP_OFF_x64();

					PULONG64 pPointer = (PULONG64)postOpCallbackFuncAddr;

					switch (callback) {
						case object_process:
							g_CallbackGlobals.ObjectProcessCallbacks[index][1].patched = true;
							memcpy(g_CallbackGlobals.ObjectProcessCallbacks[index][1].instruction, pPointer, 8);
							break;
						case object_thread:
							g_CallbackGlobals.ObjectThreadCallbacks[index][1].patched = true;
							memcpy(g_CallbackGlobals.ObjectThreadCallbacks[index][1].instruction, pPointer, 8);
							break;
						default:
							return STATUS_NOT_SUPPORTED;
							break;
					}

					*pPointer = (ULONG64)0xC3;

					CR0_WP_ON_x64();
				}
				return STATUS_SUCCESS;
			}
		}
	}
	else {
		status = STATUS_INVALID_ADDRESS;
	}
	return status;
}

NTSTATUS RestoreCallback(ULONG64 index, CALLBACK_TYPE callback) {
	ULONG64 callbackArray = 0;

	switch (callback) {
		case process:
			callbackArray = FindPspCreateProcessNotifyRoutine();
			break;
		case thread:
			callbackArray = FindPsSetCreateThreadNotifyRoutine();
			break;
		case image:
			callbackArray = FindPsLoadImageNotifyRoutineEx();
			break;
		case registry:
			return RestoreCallbackList(index, (PVOID*)FindCmUnregisterCallbackCallbackListHead(), callback);
			break;
		case object_process:
			return RestoreObCallbackList(index, FindObRegisterCallbacksListHead(*PsProcessType), callback);
			break;
		case object_thread:
			return RestoreObCallbackList(index, FindObRegisterCallbacksListHead(*PsThreadType), callback);
			break;
		default:
			return STATUS_NOT_SUPPORTED;
			break;
	}
	
	if (!callbackArray)
		return STATUS_UNSUCCESSFUL;

	ULONG64 magicPtr = callbackArray + index * 8;
	ULONG64 callbackFuncAddr = *(PULONG64)(magicPtr);

	if (MmIsAddressValid((PVOID)callbackFuncAddr) && callbackFuncAddr != 0) {
		callbackFuncAddr = *(PULONG64)(callbackFuncAddr & 0xFFFFFFFFFFFFFFF8);

		CR0_WP_OFF_x64();

		PULONG64 pPointer = (PULONG64)callbackFuncAddr;

		switch (callback) {
			case process:
				g_CallbackGlobals.ProcessCallbacks[index].patched = false;
				memcpy(pPointer, g_CallbackGlobals.ProcessCallbacks[index].instruction, 8);
				break;
			case thread:
				g_CallbackGlobals.ThreadCallbacks[index].patched = false;
				memcpy(pPointer, g_CallbackGlobals.ThreadCallbacks[index].instruction, 8);
				break;
			case image:
				g_CallbackGlobals.ImageCallbacks[index].patched = false;
				memcpy(pPointer, g_CallbackGlobals.ImageCallbacks[index].instruction, 8);
				break;
			default:
				return STATUS_NOT_SUPPORTED;
				break;
		}

		CR0_WP_ON_x64();

		return STATUS_SUCCESS;
	}
	else {
		return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS RestoreCallbackList(ULONG64 index, PVOID* callbackListHead, CALLBACK_TYPE callback) {
	NTSTATUS status = STATUS_SUCCESS;
	PLIST_ENTRY pEntry;
	ULONG64 i;

	if (callbackListHead) {
		for (pEntry = (PLIST_ENTRY)*callbackListHead, i = 0; pEntry != (PLIST_ENTRY)callbackListHead; pEntry = (PLIST_ENTRY)(pEntry->Flink), i++) {
			if (i == index) {
				auto callbackFuncAddr = *(ULONG64*)((ULONG_PTR)pEntry + 0x028);

				CR0_WP_OFF_x64();

				PULONG64 pPointer = (PULONG64)callbackFuncAddr;

				switch (callback) {
					case registry:
						g_CallbackGlobals.RegistryCallbacks[index].patched = false;
						memcpy(pPointer, g_CallbackGlobals.RegistryCallbacks[index].instruction, 8);
						break;
					default:
						return STATUS_NOT_SUPPORTED;
						break;
				}

				CR0_WP_ON_x64();

				return STATUS_SUCCESS;
			}
		}
	}
	else {
		status = STATUS_INVALID_ADDRESS;
	}
	return status;
}

NTSTATUS RestoreObCallbackList(ULONG64 index, PVOID* callbackListHead, CALLBACK_TYPE callback) {
	NTSTATUS status = STATUS_SUCCESS;
	PLIST_ENTRY pEntry;
	ULONG64 i;

	if (callbackListHead) {
		for (pEntry = (PLIST_ENTRY)*callbackListHead, i = 0; (pEntry != (PLIST_ENTRY)callbackListHead); pEntry = (PLIST_ENTRY)(pEntry->Flink), i++) {
			if (i == index) {
				auto preOpCallbackFuncAddr = *(ULONG64*)((ULONG_PTR)pEntry + 0x28);
				if (MmIsAddressValid((PVOID*)preOpCallbackFuncAddr)) {
					CR0_WP_OFF_x64();

					PULONG64 pPointer = (PULONG64)preOpCallbackFuncAddr;

					switch (callback) {
						case object_process:
							g_CallbackGlobals.ObjectProcessCallbacks[index][0].patched = false;
							memcpy(pPointer, g_CallbackGlobals.ObjectProcessCallbacks[index][0].instruction, 8);
							break;
						case object_thread:
							g_CallbackGlobals.ObjectThreadCallbacks[index][0].patched = false;
							memcpy(pPointer, g_CallbackGlobals.ObjectThreadCallbacks[index][0].instruction, 8);
							break;
					}

					CR0_WP_ON_x64();
				}

				auto postOpCallbackFuncAddr = *(ULONG64*)((ULONG_PTR)pEntry + 0x30);
				if (MmIsAddressValid((PVOID*)postOpCallbackFuncAddr)) {
					CR0_WP_OFF_x64();

					PULONG64 pPointer = (PULONG64)postOpCallbackFuncAddr;

					switch (callback) {
						case object_process:
							g_CallbackGlobals.ObjectProcessCallbacks[index][1].patched = false;
							memcpy(pPointer, g_CallbackGlobals.ObjectProcessCallbacks[index][1].instruction, 8);
							break;
						case object_thread:
							g_CallbackGlobals.ObjectThreadCallbacks[index][1].patched = false;
							memcpy(pPointer, g_CallbackGlobals.ObjectThreadCallbacks[index][1].instruction, 8);
							break;
					}

					CR0_WP_ON_x64();
				}
				return STATUS_SUCCESS;
			}
		}
	}
	else {
		status = STATUS_INVALID_ADDRESS;
	}
	return status;
}

NTSTATUS RestoreModule(PCHAR moduleName) {
	NTSTATUS status = STATUS_SUCCESS;
	for (int i = 0; i < 64; i++) {
		if (strcmp(g_CallbackGlobals.ProcessCallbacks[i].module, moduleName) == 0 && g_CallbackGlobals.ProcessCallbacks[i].patched) {
			status = RestoreCallback((ULONG)i, process);
			if (!NT_SUCCESS(status))
				return status;
		}

		if (strcmp(g_CallbackGlobals.ThreadCallbacks[i].module, moduleName) == 0 && g_CallbackGlobals.ThreadCallbacks[i].patched) {
			status = RestoreCallback((ULONG)i, thread);
			if (!NT_SUCCESS(status))
				return status;
		}

		if (strcmp(g_CallbackGlobals.ImageCallbacks[i].module, moduleName) == 0 && g_CallbackGlobals.ImageCallbacks[i].patched) {
			status = RestoreCallback((ULONG)i, image);
			if (!NT_SUCCESS(status))
				return status;
		}

		/* temporary disable register callback patching due to crash
		if (strcmp(g_CallbackGlobals.RegistryCallbacks[i].module, moduleName) == 0 && g_CallbackGlobals.RegistryCallbacks[i].patched) {
			status = RestoreCallback((ULONG)i, registry);
			if (!NT_SUCCESS(status))
				return status;
		}
		*/

		if ((strcmp(g_CallbackGlobals.ObjectProcessCallbacks[i][0].module, moduleName) == 0 ||
			strcmp(g_CallbackGlobals.ObjectProcessCallbacks[i][1].module, moduleName) == 0) &&
			(g_CallbackGlobals.ObjectProcessCallbacks[i][0].patched || g_CallbackGlobals.ObjectProcessCallbacks[i][1].patched)) {
			status = RestoreCallback((ULONG)i, object_process);
			if (!NT_SUCCESS(status))
				return status;
		}

		if ((strcmp(g_CallbackGlobals.ObjectThreadCallbacks[i][0].module, moduleName) == 0 ||
			strcmp(g_CallbackGlobals.ObjectThreadCallbacks[i][1].module, moduleName) == 0) &&
			(g_CallbackGlobals.ObjectThreadCallbacks[i][0].patched || g_CallbackGlobals.ObjectThreadCallbacks[i][1].patched)) {
			status = RestoreCallback((ULONG)i, object_thread);
			if (!NT_SUCCESS(status))
				return status;
		}
	}
	return status;
}

NTSTATUS RestoreAllCallbacks() {
	NTSTATUS status = STATUS_SUCCESS;
	for (int i = 0; i < 64; i++) {
		if (g_CallbackGlobals.ProcessCallbacks[i].patched) {
			status = RestoreCallback((ULONG64)i, process);
			if (!NT_SUCCESS(status))
				return status;
		}

		if (g_CallbackGlobals.ThreadCallbacks[i].patched) {
			status = RestoreCallback((ULONG64)i, thread);
			if (!NT_SUCCESS(status))
				return status;
		}

		if (g_CallbackGlobals.ImageCallbacks[i].patched) {
			status = RestoreCallback((ULONG64)i, image);
			if (!NT_SUCCESS(status))
				return status;
		}

		if (g_CallbackGlobals.RegistryCallbacks[i].patched) {
			status = RestoreCallback((ULONG64)i, registry);
			if (!NT_SUCCESS(status))
				return status;
		}

		if (g_CallbackGlobals.ObjectProcessCallbacks[i][0].patched || g_CallbackGlobals.ObjectProcessCallbacks[i][1].patched) {
			status = RestoreCallback((ULONG64)i, object_process);
			if (!NT_SUCCESS(status))
				return status;
		}

		if (g_CallbackGlobals.ObjectThreadCallbacks[i][0].patched || g_CallbackGlobals.ObjectThreadCallbacks[i][1].patched) {
			status = RestoreCallback((ULONG64)i, object_thread);
			if (!NT_SUCCESS(status))
				return status;
		}
	}
	return status;
}

NTSTATUS ReadCallbackArray(PINTERCEPTOR_BUFFER outBuffer, ULONG64 callbackArrayAddr, PCALLBACK_DATA registeredCallbackArray) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG64 callbackFuncAddr = 0;
	ULONG64 magicPtr = 0;

	for (ULONG64 i = 0; i < 64; i++) {
		magicPtr = callbackArrayAddr + i * 8;
		callbackFuncAddr = *(PULONG64)(magicPtr);
		
		if (MmIsAddressValid((PVOID)callbackFuncAddr) && callbackFuncAddr != 0) {
			callbackFuncAddr = *(PULONG64)(callbackFuncAddr & 0xFFFFFFFFFFFFFFF8);
			CHAR name[64];
			PCHAR pName = name;

			status = GetModuleNameFromCallbackAddr(callbackFuncAddr, pName);
			if (!NT_SUCCESS(status))
				return status;

			strcpy_s(registeredCallbackArray[i].module, pName);

			status = kwriteout(outBuffer, L"[%02llu] PATCHED [%c] (0x%llx) %S", i, (registeredCallbackArray[i].patched) ? '+': '-', callbackFuncAddr, pName);
			if (!NT_SUCCESS(status))
				return status;

			status = CheckEDR(outBuffer, pName);
			if (!NT_SUCCESS(status))
				return status;

			status = kwriteout(outBuffer, L"\n");
			if (!NT_SUCCESS(status))
				return status;
		}
	}
	return status;
}

NTSTATUS ReadCallbackList(PINTERCEPTOR_BUFFER outBuffer, PVOID* callbackListHead, PCALLBACK_DATA registeredCallbackArray) {
	NTSTATUS status = STATUS_SUCCESS;
	PLIST_ENTRY pEntry;
	ULONG64 i;

	if (callbackListHead) {
		for (pEntry = (PLIST_ENTRY)*callbackListHead, i = 0; NT_SUCCESS(status) && (pEntry != (PLIST_ENTRY)callbackListHead); pEntry = (PLIST_ENTRY)(pEntry->Flink), i++) {
			status = kwriteout(outBuffer, L"[%02llu] PATCHED [%c] (0x%llx) ", i, (registeredCallbackArray[i].patched) ? '+' : '-', *(ULONG64*)((ULONG_PTR)pEntry + 0x028));
			if (!NT_SUCCESS(status))
				return status;

			CHAR name[64];
			PCHAR pName = name;
			status = GetModuleNameFromCallbackAddr(outBuffer, *(ULONG64*)((ULONG_PTR)pEntry + 0x028), pName);
			if (!NT_SUCCESS(status))
				return status;

			strcpy_s(registeredCallbackArray[i].module, pName);

			status = CheckEDR(outBuffer, pName);
			if (!NT_SUCCESS(status))
				return status;

			status = kwriteout(outBuffer, L"\n");
			if (!NT_SUCCESS(status))
				return status;
		}
	}
	else {
		status = STATUS_INVALID_ADDRESS;
	}
	return status;
}

NTSTATUS ReadObCallbackList(PINTERCEPTOR_BUFFER outBuffer, PVOID* callbackListHead, CALLBACK_TYPE callback) {
	NTSTATUS status = STATUS_SUCCESS;
	PLIST_ENTRY pEntry;
	ULONG64 i;

	if (callbackListHead) {
		for (pEntry = (PLIST_ENTRY)*callbackListHead, i = 0; NT_SUCCESS(status) && (pEntry != (PLIST_ENTRY)callbackListHead); pEntry = (PLIST_ENTRY)(pEntry->Flink), i++) {
			auto preOpCallback = *(ULONG64*)((ULONG_PTR)pEntry + 0x28);
			if (MmIsAddressValid((PVOID*)preOpCallback)) {
				status = kwriteout(outBuffer, L"[%02llu][pre] PATCHED [%c] (0x%llx) ", i,
					(callback == object_process) ? ((g_CallbackGlobals.ObjectProcessCallbacks[i][0].patched) ? '+' : '-') : ((g_CallbackGlobals.ObjectThreadCallbacks[i][0].patched) ? '+' : '-'),
					preOpCallback);
				if (!NT_SUCCESS(status))
					return status;

				CHAR name[64];
				PCHAR pName = name;

				status = GetModuleNameFromCallbackAddr(outBuffer, preOpCallback, pName);
				if (!NT_SUCCESS(status))
					return status;

				if (callback == object_process)
					strcpy_s(g_CallbackGlobals.ObjectProcessCallbacks[i][0].module, pName);
				else
					strcpy_s(g_CallbackGlobals.ObjectThreadCallbacks[i][0].module, pName);

				status = CheckEDR(outBuffer, pName);
				if (!NT_SUCCESS(status))
					return status;

				status = kwriteout(outBuffer, L"\n");
				if (!NT_SUCCESS(status))
					return status;
			}

			auto postOpCallback = *(ULONG64*)((ULONG_PTR)pEntry + 0x30);
			if (MmIsAddressValid((PVOID*)postOpCallback)) {
				status = kwriteout(outBuffer, L"[%02llu][post] PATCHED [%c] (0x%llx) ", i,
					(callback == object_process) ? ((g_CallbackGlobals.ObjectProcessCallbacks[i][1].patched) ? '+' : '-') : ((g_CallbackGlobals.ObjectThreadCallbacks[i][1].patched) ? '+' : '-'),
					postOpCallback);
				if (!NT_SUCCESS(status))
					return status;

				CHAR name[64];
				PCHAR pName = name;

				status = GetModuleNameFromCallbackAddr(outBuffer, postOpCallback, pName);
				if (!NT_SUCCESS(status))
					return status;

				if (callback == object_process)
					strcpy_s(g_CallbackGlobals.ObjectProcessCallbacks[i][1].module, pName);
				else
					strcpy_s(g_CallbackGlobals.ObjectThreadCallbacks[i][1].module, pName);

				status = CheckEDR(outBuffer, pName);
				if (!NT_SUCCESS(status))
					return status;

				status = kwriteout(outBuffer, L"\n");
				if (!NT_SUCCESS(status))
					return status;
			}
		}
	}
	else {
		status = STATUS_INVALID_ADDRESS;
	}
	return status;
}

NTSTATUS ReadCallbacks(PINTERCEPTOR_BUFFER outBuffer) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG64 processCallbackArray = FindPspCreateProcessNotifyRoutine();
	ULONG64 threadCallbackArray = FindPsSetCreateThreadNotifyRoutine();
	ULONG64 imageCallbackArray = FindPsLoadImageNotifyRoutineEx();
	PVOID* regCallbackListHead = (PVOID*)FindCmUnregisterCallbackCallbackListHead();
	PVOID* obProcessCallbackListHead = FindObRegisterCallbacksListHead(*PsProcessType);
	PVOID* obThreadCallbackListHead = FindObRegisterCallbacksListHead(*PsThreadType);

	if (!processCallbackArray || !threadCallbackArray || !imageCallbackArray || !regCallbackListHead || !obProcessCallbackListHead || !obThreadCallbackListHead)
		return STATUS_INVALID_ADDRESS;

	kwriteout(outBuffer, L"[*] Process callbacks:\n");
	if (!NT_SUCCESS(status = ReadCallbackArray(outBuffer, processCallbackArray, g_CallbackGlobals.ProcessCallbacks)))
		return status;
	kwriteout(outBuffer, L"[*] Thread callbacks:\n");
	if (!NT_SUCCESS(status = ReadCallbackArray(outBuffer, threadCallbackArray, g_CallbackGlobals.ThreadCallbacks)))
		return status;
	kwriteout(outBuffer, L"[*] Image callbacks:\n");
	if (!NT_SUCCESS(status = ReadCallbackArray(outBuffer, imageCallbackArray, g_CallbackGlobals.ImageCallbacks)))
		return status;
	kwriteout(outBuffer, L"[*] Registry callbacks:\n");
	if (!NT_SUCCESS(status = ReadCallbackList(outBuffer, regCallbackListHead, g_CallbackGlobals.RegistryCallbacks)))
		return status;
	kwriteout(outBuffer, L"[*] Process Object callbacks:\n");
	if (!NT_SUCCESS(status = ReadObCallbackList(outBuffer, obProcessCallbackListHead, object_process)))
		return status;
	kwriteout(outBuffer, L"[*] Thread object callbacks:\n");
	if (!NT_SUCCESS(status = ReadObCallbackList(outBuffer, obThreadCallbackListHead, object_thread)))
		return status;

	return status;
}

NTSTATUS GetModuleNameFromCallbackAddr(ULONG64 moduleAddr, PCHAR& moduleName) {
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

	for (ULONG i = 0; i < numberOfModules; i++) {
		if (moduleAddr > (ULONG64)modules[i].BasicInfo.ImageBase && moduleAddr < ((ULONG64)modules[i].BasicInfo.ImageBase + modules[i].ImageSize)) {
			strcpy(moduleName, (CHAR*)(modules[i].FullPathName + modules[i].FileNameOffset));
			ExFreePoolWithTag(modules, DRIVER_TAG);
			return status;
		}
	}

	ExFreePoolWithTag(modules, DRIVER_TAG);
	return status;
}

NTSTATUS GetModuleNameFromCallbackAddr(PINTERCEPTOR_BUFFER outBuffer, ULONG64 moduleAddr, PCHAR& moduleName) {
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

	for (ULONG i = 0; i < numberOfModules; i++) {
		if (moduleAddr > (ULONG64)modules[i].BasicInfo.ImageBase && moduleAddr < ((ULONG64)modules[i].BasicInfo.ImageBase + modules[i].ImageSize)) {
			status = kwriteout(outBuffer, L"%S", modules[i].FullPathName + modules[i].FileNameOffset);
			strcpy(moduleName, (CHAR*)(modules[i].FullPathName + modules[i].FileNameOffset));
			ExFreePoolWithTag(modules, DRIVER_TAG);
			return status;
		}
	}

	ExFreePoolWithTag(modules, DRIVER_TAG);
	return status;
}

ULONG64 GetKernelBaseAddress() {
	NTSTATUS status;
	ULONG modulesSize = 0;
	PAUX_MODULE_EXTENDED_INFO modules;
	ULONG numberOfModules;

	status = AuxKlibInitialize();
	if (!NT_SUCCESS(status))
		return 0;

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), nullptr);
	if (!NT_SUCCESS(status) || modulesSize == 0)
		return 0;

	numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);

	modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePoolWithTag(PagedPool, modulesSize, DRIVER_TAG);
	if (modules == nullptr)
		return 0;

	RtlZeroMemory(modules, modulesSize);

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(modules, DRIVER_TAG);
		return 0;
	}

	ULONG64 baseAddr =  (ULONG64)modules[0].BasicInfo.ImageBase;
	ExFreePoolWithTag(modules, DRIVER_TAG);
	return baseAddr;
}

ULONG64 VerifyOffsets(LONG OffsetAddr, ULONG64 InstructionAddr) {
	ULONG64 ReturnAddr = OffsetAddr + 7 + InstructionAddr;
	ULONG64 KernelBaseAddr = GetKernelBaseAddress();
	if (KernelBaseAddr != 0) {
		if (ReturnAddr - KernelBaseAddr > 0x1000000) {
			KdPrint((DRIVER_PREFIX "Mismatch between kernel base address and expected return address: %llx\n", ReturnAddr - KernelBaseAddr));
			return 0;
		}
		return ReturnAddr;
	}
	else {
		KdPrint((DRIVER_PREFIX "Unable to get kernel base address\n"));
		return 0;
	}
}