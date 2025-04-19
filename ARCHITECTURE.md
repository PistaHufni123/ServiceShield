# ServiceProtector Driver Architecture

## Overview

The ServiceProtector is a Windows kernel-mode driver designed to protect critical Windows services from unauthorized termination or modification. It operates by intercepting process handle creation requests and filtering access rights to prevent harmful operations against the protected service.

## Core Components

### 1. Driver Structure

The ServiceProtector driver is implemented using the Windows Driver Frameworks (WDF) model, specifically the Kernel-Mode Driver Framework (KMDF), which simplifies driver development by handling many common tasks.

Key files:
- **ServiceProtector.h**: Contains data structures, constants, and function prototypes
- **ServiceProtector.c**: Main implementation of the driver functionality
- **ServiceProtector.inf**: Installation information file for the driver
- **ServiceProtector.rc**: Resource script for version information
- **trace.h**: Contains definitions for WPP tracing support

The driver uses a global device reference approach to simplify device access across callbacks:

```c
// Global device reference in ServiceProtector.c
WDFDEVICE g_Device = NULL;

// In DriverEntry, after device creation:
g_Device = device;

// In callback functions, access the device directly:
device = g_Device;
```

This approach eliminates the need for WdfDriverGetDevice calls and simplifies device access from asynchronous callbacks.

### 2. Data Structures

The driver uses several important data structures to manage its state:

#### Device Context

```c
typedef struct _DEVICE_CONTEXT {
    WDFDEVICE Device;
    SERVICE_INFORMATION ServiceInfo;
    CALLBACK_REGISTRATION ProcessCallback;
    CALLBACK_REGISTRATION ThreadCallback;
    FAST_MUTEX ServiceInfoMutex;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;
```

This structure maintains the global state of the driver and contains information about the protected service.

#### Service Information

```c
typedef struct _SERVICE_INFORMATION {
    BOOLEAN TargetProcessFound;
    HANDLE TargetProcessId;
    WCHAR ServiceName[MAX_SERVICE_NAME_LENGTH];
} SERVICE_INFORMATION, *PSERVICE_INFORMATION;
```

This structure stores information about the target service, including its name and process ID.

#### Callback Registration

```c
typedef struct _CALLBACK_REGISTRATION {
    BOOLEAN Registered;
    PVOID RegistrationHandle;
} CALLBACK_REGISTRATION, *PCALLBACK_REGISTRATION;
```

This structure manages the state of the object callbacks registered with the system.

### 3. Core Mechanisms

#### A. Object Callbacks

The driver uses the Windows Object Manager callback mechanism (`ObRegisterCallbacks`) to intercept handle creation requests for processes. The callback function `PreOperationCallback` is invoked before any handle to a process is created or duplicated.

```c
OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
);
```

This callback checks if the target handle belongs to the protected service process and, if so, filters out potentially harmful access rights like `PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, and `PROCESS_SUSPEND_RESUME`.

#### B. Process Creation Monitoring

The driver monitors process creation and termination using `PsSetCreateProcessNotifyRoutineEx`, which registers the `ProcessNotifyCallback` function to be called whenever a process is created or terminated.

```c
VOID ProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
);
```

This function identifies when the protected service's process starts or terminates and updates the driver's state accordingly.

#### C. User-Mode Communication

The driver communicates with user-mode applications through I/O control codes (IOCTLs). The primary IOCTL is:

```c
#define IOCTL_SERVICE_PROTECTOR_SET_TARGET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

This allows a privileged user-mode application to configure which service the driver should protect.

## Protection Mechanisms

### 1. Handle Access Filtering

The main protection mechanism is filtering access rights in handle creation requests:

```c
// Determine which access rights to deny
deniedAccess = 0;

// Prevent process termination
if (*desiredAccess & PROCESS_TERMINATE) {
    deniedAccess |= PROCESS_TERMINATE;
}

// Prevent memory writes (to prevent DLL injection)
if (*desiredAccess & PROCESS_VM_WRITE) {
    deniedAccess |= PROCESS_VM_WRITE;
}

// Prevent process suspension
if (*desiredAccess & PROCESS_SUSPEND_RESUME) {
    deniedAccess |= PROCESS_SUSPEND_RESUME;
}

// Remove the denied access rights
*desiredAccess &= ~deniedAccess;
```

This code checks if access requests include rights that could be used to harm the protected process and removes those rights.

### 2. Service Process Identification

The driver identifies the target service's process using a custom filename matching approach:

```c
// Check if the process name ends with the service executable name
// Using a custom implementation of string suffix comparison
BOOLEAN nameMatches = FALSE;
if (processName.Length >= targetServiceName.Length) {
    PCWSTR processSuffix = (PCWSTR)((PCHAR)processName.Buffer + 
        (processName.Length - targetServiceName.Length));
    
    // Compare the suffix - case insensitive comparison using RtlUpcaseUnicodeChar
    // (Convert both strings to uppercase for proper comparison)
    WCHAR processTemp[MAX_SERVICE_NAME_LENGTH];
    WCHAR targetTemp[MAX_SERVICE_NAME_LENGTH];
    
    // Copy and convert to uppercase, making sure not to overflow buffers
    for (ULONG i = 0; i < copyLength; i++) {
        processTemp[i] = RtlUpcaseUnicodeChar(processSuffix[i]);
        targetTemp[i] = RtlUpcaseUnicodeChar(targetServiceName.Buffer[i]);
    }
    
    // Compare the strings
    nameMatches = (wcscmp(processTemp, targetTemp) == 0);
}

if (nameMatches) {
    // Mark this process as our target for protection
    deviceContext->ServiceInfo.TargetProcessFound = TRUE;
    deviceContext->ServiceInfo.TargetProcessId = ProcessId;
}
```

This allows the driver to locate the service process when it starts and begin protecting it.

## Execution Flow

### 1. Driver Initialization

1. The `DriverEntry` function initializes the driver, sets up a device object, and registers callbacks
2. `PsSetCreateProcessNotifyRoutineEx` is called to register for process notifications
3. `RegisterCallbacks` is called to register object callbacks
4. The driver enters a passive state, waiting for callbacks to be triggered

### 2. Service Protection

1. When a process is created, `ProcessNotifyCallback` is called
2. If the process matches the target service, it's marked for protection
3. When a handle to the protected process is requested, `PreOperationCallback` is called
4. The callback filters out dangerous access rights
5. The filtered handle creation request continues

### 3. Driver Unloading

1. The `ServiceProtectorEvtDriverUnload` function is called when the driver is unloaded
2. `PsSetCreateProcessNotifyRoutineEx` is called to unregister process notifications
3. `UnregisterCallbacks` is called to unregister object callbacks
4. Resources are released and the driver unloads

## Security Considerations

### 1. Protection Scope

The current implementation protects against:
- Process termination
- Memory writes (which could be used for code injection)
- Process suspension

It does not protect against:
- Kernel-mode attacks
- Direct manipulation of system data structures
- Attacks with sufficient privileges

### 2. Access Control

The driver device object is created with security that restricts access to administrators:
```c
deviceInit = WdfControlDeviceInitAllocate(driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
```

This prevents non-privileged users from configuring the driver.

### 3. Edge Cases

The driver handles several important edge cases:
- Synchronizes access to shared data with mutexes
- Properly tracks the protected process's lifecycle
- Maintains separate callback mechanisms for processes and threads
- Includes proper cleanup in the unload routine

## Potential Enhancements

1. **Improved Service Identification**: The current service identification mechanism is simplistic. Integration with the Service Control Manager would provide more accurate identification.

2. **Additional Protection Mechanisms**: The driver could be extended to protect the service registry keys, related files, and other resources.

3. **Audit Logging**: Adding more comprehensive logging of protection events to the Windows Event Log would improve security monitoring.

4. **Digital Signature Verification**: Adding code to verify the digital signature of processes attempting to access the protected service would enhance security.

5. **Memory Protection**: Implementing Page Guard or similar techniques to protect critical memory regions of the service process.

## Conclusion

The ServiceProtector driver demonstrates a practical implementation of a Windows kernel security mechanism using object callbacks and process monitoring. While focused on a specific protection scenario, the techniques demonstrated are applicable to a variety of Windows kernel security applications.