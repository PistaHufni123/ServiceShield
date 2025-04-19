
/*++
*
*Module Name:
*
*    ServiceProtector.h
*
*Abstract:
*
*    Header file for the ServiceProtector driver
*
*Environment:
*
*    Kernel mode
*
--*/

#pragma once

#include <ntdef.h>
#include <wdm.h>
#include <ntddk.h>
#include <wdf.h>

#define MAX_SERVICE_NAME_LENGTH 256
#define IOCTL_SERVICE_PROTECTOR_SET_TARGET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _SERVICE_INFORMATION {
    BOOLEAN TargetProcessFound;
    HANDLE TargetProcessId;
    WCHAR ServiceName[MAX_SERVICE_NAME_LENGTH];
} SERVICE_INFORMATION, *PSERVICE_INFORMATION;

typedef struct _DEVICE_CONTEXT {
    WDFDEVICE Device;
    SERVICE_INFORMATION ServiceInfo;
    PVOID RegistrationHandle;
    FAST_MUTEX ServiceInfoMutex;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

// Device context accessor
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, GetDeviceContext)

// Driver function declarations
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD ServiceProtectorEvtDriverUnload;
NTSTATUS ServiceProtectorCreateClose(_In_ WDFDEVICE Device, _In_ WDFREQUEST Request, _In_ WDFFILEOBJECT FileObject);
NTSTATUS ServiceProtectorDeviceControl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request, _In_ size_t OutputBufferLength, _In_ size_t InputBufferLength, _In_ ULONG IoControlCode);
