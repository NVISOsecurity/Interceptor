#pragma once

#define IOCTL_INTERCEPTOR_LIST_DRIVERS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_INTERCEPTOR_LIST_HOOKED_DRIVERS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_INTERCEPTOR_HOOK_DRIVER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INTERCEPTOR_HOOK_DRIVER_BY_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INTERCEPTOR_UNHOOK_DRIVER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INTERCEPTOR_UNHOOK_ALL_DRIVERS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_ANY_ACCESS)

#define IOCTL_INTERCEPTOR_LIST_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_INTERCEPTOR_PATCH_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INTERCEPTOR_RESTORE_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INTERCEPTOR_RESTORE_ALL_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_INTERCEPTOR_PATCH_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INTERCEPTOR_RESTORE_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INTERCEPTOR_PATCH_VENDOR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INTERCEPTOR_RESTORE_VENDOR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INTERCEPTOR_PATCH_EDR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef enum _CALLBACK_TYPE {
	process = 0,
	thread = 1,
	image = 2,
	registry = 3,
	object_process = 4,
	object_thread = 5,
} CALLBACK_TYPE, * PCALLBACK_TYPE;

struct USER_DRIVER_DATA {
	ULONG index;
	WCHAR name[256];
};

struct USER_CALLBACK_DATA {
	WCHAR vendor[64];
	CHAR module[64];
	ULONG index;
	CALLBACK_TYPE callback;
};

typedef struct _INTERCEPTOR_BUFFER {
	size_t* szBuffer;
	PWSTR* Buffer;
} INTERCEPTOR_BUFFER, * PINTERCEPTOR_BUFFER;

#define kwriteout(InterceptorBuffer, Format, ...) (RtlStringCbPrintfExW(*(InterceptorBuffer)->Buffer, *(InterceptorBuffer)->szBuffer, (InterceptorBuffer)->Buffer, (InterceptorBuffer)->szBuffer, STRSAFE_NO_TRUNCATION, Format, __VA_ARGS__))
