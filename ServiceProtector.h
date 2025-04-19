/*++

Module Name:

    ServiceProtector.h

Abstract:

    Header file for the ServiceProtector driver

Environment:

    Kernel mode

--*/

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

// IOCTL codes for user-mode communication
#define IOCTL_SERVICE_PROTECTOR_SET_TARGET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Maximum length for service name
#define MAX_SERVICE_NAME_LENGTH 256

// Callback registration handle
typedef struct _CALLBACK_REGISTRATION {
    BOOLEAN Registered;
    PVOID RegistrationHandle;
} CALLBACK_REGISTRATION, *PCALLBACK_REGISTRATION;

// Service information structure
typedef struct _SERVICE_INFORMATION {
    BOOLEAN TargetProcessFound;
    HANDLE TargetProcessId;
    WCHAR ServiceName[MAX_SERVICE_NAME_LENGTH];
} SERVICE_INFORMATION, *PSERVICE_INFORMATION;

// Driver device context
typedef struct _DEVICE_CONTEXT {
    WDFDEVICE Device;
    SERVICE_INFORMATION ServiceInfo;
    CALLBACK_REGISTRATION ProcessCallback;
    CALLBACK_REGISTRATION ThreadCallback;
    FAST_MUTEX ServiceInfoMutex;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, GetDeviceContext)

// Function prototypes
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD ServiceProtectorEvtDriverUnload;
EVT_WDF_DEVICE_FILE_CREATE ServiceProtectorEvtDeviceFileCreate;
EVT_WDF_FILE_CLOSE ServiceProtectorEvtFileClose;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL ServiceProtectorEvtIoDeviceControl;

NTSTATUS RegisterCallbacks(_In_ PDEVICE_CONTEXT DeviceContext);
VOID UnregisterCallbacks(_In_ PDEVICE_CONTEXT DeviceContext);
OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
);
VOID ProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

// Debug logging macros
#if DBG
#define SERVICE_PROTECTOR_PRINT(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ServiceProtector: " fmt "\n", ##__VA_ARGS__)
#else
#define SERVICE_PROTECTOR_PRINT(fmt, ...)
#endif
