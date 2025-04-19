
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
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL ServiceProtectorDeviceControl;
EVT_WDF_DEVICE_FILE_CREATE ServiceProtectorCreateClose;
