/*++

Module Name:

    ServiceProtector.h

Abstract:

    Header file for the ServiceProtector driver

Environment:

    Kernel mode

--*/

#pragma once

// Define architecture for kernel compilation
#define _AMD64_

// For kernel-mode drivers, we should ONLY use kernel headers, not um (user-mode) headers
// Define target Windows version before including headers
#define NTDDI_VERSION NTDDI_WIN10_RS1
#define _WIN32_WINNT 0x0A00  // Windows 10

// Base Windows kernel types and definitions (order is important)
#include <ntdef.h>
#include <wdm.h>
#include <ntddk.h>
#include <wdf.h>

// WDF function declarations
#include <wdfdriver.h>  // For WDF driver functions

// WDF function declarations will be handled via our global device approach
// No need to include wdfldr.h which is causing inclusion errors

// Additional headers for specific API functions
#include <ntstrsafe.h>  // String safe functions
#include <ntimage.h>    // NT image functions

// Forward declare the callback type before using it
typedef VOID (*PCREATE_PROCESS_NOTIFY_ROUTINE_EX)(
    PEPROCESS Process,
    HANDLE ProcessId,
    struct _PS_CREATE_NOTIFY_INFO* CreateInfo
);

// Function declarations for functions we use that might not be in headers
NTKERNELAPI HANDLE PsGetProcessId(PEPROCESS Process);
NTKERNELAPI HANDLE PsGetCurrentProcessId(VOID);
NTKERNELAPI NTSTATUS PsSetCreateProcessNotifyRoutineEx(PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine, BOOLEAN Remove);
NTKERNELAPI WCHAR NTAPI RtlUpcaseUnicodeChar(WCHAR SourceCharacter);

// Buffer validation function - ProbeForRead is available in kernel mode but add declaration just in case
#if !defined(PROBE_FOR_READ_DEFINED)
#define PROBE_FOR_READ_DEFINED
NTKERNELAPI VOID ProbeForRead(
    _In_ volatile VOID *Address,
    _In_ SIZE_T Length,
    _In_ ULONG Alignment
);
#endif

// Fix for PPS_CREATE_NOTIFY_INFO definition (required for PsSetCreateProcessNotifyRoutineEx)
#if !defined(_PS_CREATE_NOTIFY_INFO_DEFINED)
#define _PS_CREATE_NOTIFY_INFO_DEFINED
typedef struct _PS_CREATE_NOTIFY_INFO {
    SIZE_T Size;
    union {
        ULONG Flags;
        struct {
            ULONG FileOpenNameAvailable : 1;
            ULONG IsSubsystemProcess : 1;
            ULONG Reserved : 30;
        };
    };
    HANDLE ParentProcessId;
    CLIENT_ID CreatingThreadId;
    struct _FILE_OBJECT *FileObject;
    PCUNICODE_STRING ImageFileName;
    PCUNICODE_STRING CommandLine;
    NTSTATUS CreationStatus;
} PS_CREATE_NOTIFY_INFO, *PPS_CREATE_NOTIFY_INFO;
#endif // !defined(_PS_CREATE_NOTIFY_INFO_DEFINED)

// PCREATE_PROCESS_NOTIFY_ROUTINE_EX is already defined above

// Define WPP_ENABLED based on the project settings
// This will be defined when WPP tracing is enabled in the project
#if !defined(WPP_ENABLED)
    #if defined(EVENT_TRACING)
        #define WPP_ENABLED 1
    #endif
#endif

// Define process access rights if not already defined
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                  (0x0001)
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE                   (0x0020)
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME             (0x0800)
#endif

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
    _In_ PVOID CreateInfoPtr
);

// Debug logging macros
#if DBG
#define SERVICE_PROTECTOR_PRINT(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ServiceProtector: " fmt "\n", ##__VA_ARGS__)
#else
#define SERVICE_PROTECTOR_PRINT(fmt, ...)
#endif
