/*++

Module Name:

    ServiceProtector.c

Abstract:

    Implementation of the ServiceProtector driver

Environment:

    Kernel mode

--*/

#include "ServiceProtector.h"

// Add trace headers
#include "trace.h"
#include "ServiceProtector.tmh"

// Driver entry point
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;
    PWDFDEVICE_INIT deviceInit;
    WDFDEVICE device;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_IO_QUEUE_CONFIG ioQueueConfig;
    PDEVICE_CONTEXT deviceContext;
    WDFQUEUE queue;
    DECLARE_CONST_UNICODE_STRING(deviceName, L"\\Device\\ServiceProtector");
    DECLARE_CONST_UNICODE_STRING(symbolicLinkName, L"\\DosDevices\\ServiceProtector");

    // Initialize WPP Tracing
    WPP_INIT_TRACING(DriverObject, RegistryPath);

    SERVICE_PROTECTOR_PRINT("Driver initializing");

    // Initialize the driver configuration
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.EvtDriverUnload = ServiceProtectorEvtDriverUnload;
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.DriverPoolTag = 'PSVC';

    // Create the WDF driver object
    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        &driver
    );

    if (!NT_SUCCESS(status)) {
        SERVICE_PROTECTOR_PRINT("WdfDriverCreate failed with status 0x%x", status);
        return status;
    }

    // Create a device
    deviceInit = WdfControlDeviceInitAllocate(driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (deviceInit == NULL) {
        SERVICE_PROTECTOR_PRINT("WdfControlDeviceInitAllocate failed");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set device name
    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        SERVICE_PROTECTOR_PRINT("WdfDeviceInitAssignName failed with status 0x%x", status);
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    // Set file object callbacks
    WdfDeviceInitSetFileObjectConfig(
        deviceInit,
        WDF_NO_OBJECT_ATTRIBUTES,
        WDF_NO_EVENT_CALLBACK,
        WdfFileObjectCanBeOptional
    );

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);

    // Create the device
    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        SERVICE_PROTECTOR_PRINT("WdfDeviceCreate failed with status 0x%x", status);
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    // Create symbolic link
    status = WdfDeviceCreateSymbolicLink(device, &symbolicLinkName);
    if (!NT_SUCCESS(status)) {
        SERVICE_PROTECTOR_PRINT("WdfDeviceCreateSymbolicLink failed with status 0x%x", status);
        return status;
    }

    // Initialize the device context
    deviceContext = GetDeviceContext(device);
    deviceContext->Device = device;
    deviceContext->ServiceInfo.TargetProcessFound = FALSE;
    deviceContext->ServiceInfo.TargetProcessId = NULL;
    RtlZeroMemory(deviceContext->ServiceInfo.ServiceName, sizeof(deviceContext->ServiceInfo.ServiceName));
    deviceContext->ProcessCallback.Registered = FALSE;
    deviceContext->ProcessCallback.RegistrationHandle = NULL;
    deviceContext->ThreadCallback.Registered = FALSE;
    deviceContext->ThreadCallback.RegistrationHandle = NULL;
    ExInitializeFastMutex(&deviceContext->ServiceInfoMutex);

    // Configure the default I/O queue
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchSequential);
    ioQueueConfig.EvtIoDeviceControl = ServiceProtectorEvtIoDeviceControl;
    ioQueueConfig.EvtIoStop = WdfIoQueueStopSynchronously;

    status = WdfIoQueueCreate(
        device,
        &ioQueueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &queue
    );

    if (!NT_SUCCESS(status)) {
        SERVICE_PROTECTOR_PRINT("WdfIoQueueCreate failed with status 0x%x", status);
        return status;
    }

    // Register for process notifications
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        SERVICE_PROTECTOR_PRINT("PsSetCreateProcessNotifyRoutineEx failed with status 0x%x", status);
        return status;
    }

    // Register the object callbacks
    status = RegisterCallbacks(deviceContext);
    if (!NT_SUCCESS(status)) {
        SERVICE_PROTECTOR_PRINT("RegisterCallbacks failed with status 0x%x", status);
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        return status;
    }

    WdfControlFinishInitializing(device);

    SERVICE_PROTECTOR_PRINT("Driver initialized successfully");
    return STATUS_SUCCESS;
}

// Driver unload handler
VOID
ServiceProtectorEvtDriverUnload(
    _In_ WDFDRIVER Driver
)
{
    WDFDEVICE device;
    PDEVICE_CONTEXT deviceContext;

    SERVICE_PROTECTOR_PRINT("Driver unloading");

    // Get the device context
    device = WdfGetDriver_Device(Driver);
    deviceContext = GetDeviceContext(device);

    // Unregister process notifications
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);

    // Unregister callbacks
    UnregisterCallbacks(deviceContext);

    SERVICE_PROTECTOR_PRINT("Driver unloaded successfully");
    
    // Cleanup WPP Tracing
    WPP_CLEANUP(WdfDriverWdmGetDriverObject(Driver));
}

// Register object callbacks
NTSTATUS
RegisterCallbacks(
    _In_ PDEVICE_CONTEXT DeviceContext
)
{
    NTSTATUS status;
    OB_CALLBACK_REGISTRATION callbackRegistration;
    OB_OPERATION_REGISTRATION operationRegistration[2];

    // Setup operation registration for process objects
    operationRegistration[0].ObjectType = PsProcessType;
    operationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[0].PreOperation = PreOperationCallback;
    operationRegistration[0].PostOperation = NULL;

    // Setup operation registration for thread objects
    operationRegistration[1].ObjectType = PsThreadType;
    operationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[1].PreOperation = PreOperationCallback;
    operationRegistration[1].PostOperation = NULL;

    // Setup callback registration
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 2;
    callbackRegistration.RegistrationContext = DeviceContext;
    callbackRegistration.OperationRegistration = operationRegistration;
    RtlInitUnicodeString(&callbackRegistration.Altitude, L"320000");

    // Register the callbacks
    status = ObRegisterCallbacks(&callbackRegistration, &DeviceContext->ProcessCallback.RegistrationHandle);
    if (NT_SUCCESS(status)) {
        DeviceContext->ProcessCallback.Registered = TRUE;
        SERVICE_PROTECTOR_PRINT("Object callbacks registered successfully");
    }
    else {
        SERVICE_PROTECTOR_PRINT("ObRegisterCallbacks failed with status 0x%x", status);
    }

    return status;
}

// Unregister callbacks
VOID
UnregisterCallbacks(
    _In_ PDEVICE_CONTEXT DeviceContext
)
{
    if (DeviceContext->ProcessCallback.Registered && DeviceContext->ProcessCallback.RegistrationHandle != NULL) {
        ObUnRegisterCallbacks(DeviceContext->ProcessCallback.RegistrationHandle);
        DeviceContext->ProcessCallback.RegistrationHandle = NULL;
        DeviceContext->ProcessCallback.Registered = FALSE;
        SERVICE_PROTECTOR_PRINT("Process callbacks unregistered");
    }

    if (DeviceContext->ThreadCallback.Registered && DeviceContext->ThreadCallback.RegistrationHandle != NULL) {
        ObUnRegisterCallbacks(DeviceContext->ThreadCallback.RegistrationHandle);
        DeviceContext->ThreadCallback.RegistrationHandle = NULL;
        DeviceContext->ThreadCallback.Registered = FALSE;
        SERVICE_PROTECTOR_PRINT("Thread callbacks unregistered");
    }
}

// Pre-operation callback for handle creation
OB_PREOP_CALLBACK_STATUS
PreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
)
{
    PDEVICE_CONTEXT deviceContext;
    ACCESS_MASK deniedAccess = 0;
    PACCESS_MASK desiredAccess;
    HANDLE targetProcessId;

    deviceContext = (PDEVICE_CONTEXT)RegistrationContext;

    // Process protection logic
    if (PreInfo->ObjectType == *PsProcessType) {
        // Get the process ID
        targetProcessId = PsGetProcessId((PEPROCESS)PreInfo->Object);

        // Check if this is our target process
        ExAcquireFastMutex(&deviceContext->ServiceInfoMutex);
        if (deviceContext->ServiceInfo.TargetProcessFound &&
            deviceContext->ServiceInfo.TargetProcessId == targetProcessId) {
            
            // This is our protected process
            // Determine if this access is coming from a trusted source
            // For simplicity, we'll just check if the access is from kernel mode or the process itself
            if (PreInfo->KernelHandle == FALSE && 
                PsGetCurrentProcessId() != targetProcessId) {
                
                // This is user-mode access from another process
                // Deny potentially harmful access rights
                if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
                    desiredAccess = &PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
                }
                else { // OB_OPERATION_HANDLE_DUPLICATE
                    desiredAccess = &PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
                }

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

                // Log the protection event if access was restricted
                if (deniedAccess != 0) {
                    SERVICE_PROTECTOR_PRINT(
                        "Protected process %wZ (PID: %lu) from access 0x%x by process %lu",
                        deviceContext->ServiceInfo.ServiceName,
                        HandleToULong(targetProcessId),
                        deniedAccess,
                        HandleToULong(PsGetCurrentProcessId())
                    );

                    // Remove the denied access rights
                    *desiredAccess &= ~deniedAccess;
                }
            }
        }
        ExReleaseFastMutex(&deviceContext->ServiceInfoMutex);
    }

    return OB_PREOP_SUCCESS;
}

// Process notification callback
VOID
ProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    PDEVICE_CONTEXT deviceContext;
    WDFDEVICE device;
    UNICODE_STRING processName;
    UNICODE_STRING targetServiceName;
    
    UNREFERENCED_PARAMETER(ProcessId);

    // Handle process creation
    if (CreateInfo != NULL) {
        // Get the device context
        device = WdfGetDriver_Device(WdfGetDriver());
        if (device == NULL) {
            SERVICE_PROTECTOR_PRINT("Failed to get device from driver");
            return;
        }

        deviceContext = GetDeviceContext(device);
        if (deviceContext == NULL) {
            SERVICE_PROTECTOR_PRINT("Failed to get device context");
            return;
        }

        // Get the process image name
        if (CreateInfo->ImageFileName != NULL) {
            // Check if this is the target service
            ExAcquireFastMutex(&deviceContext->ServiceInfoMutex);
            
            if (deviceContext->ServiceInfo.ServiceName[0] != L'\0') {
                RtlInitUnicodeString(&targetServiceName, deviceContext->ServiceInfo.ServiceName);
                
                if (CreateInfo->ImageFileName->Buffer != NULL) {
                    processName = *CreateInfo->ImageFileName;
                    
                    // Check if the process name ends with the service executable name
                    // This is a simplistic check; in a real-world scenario, you might want to
                    // cross-reference with the Service Control Manager
                    if (RtlUnicodeStringEndsWithString(&processName, &targetServiceName, TRUE)) {
                        SERVICE_PROTECTOR_PRINT("Target service process started: %wZ (PID: %lu)",
                            &processName, HandleToULong(ProcessId));
                        
                        // Mark this process as our target for protection
                        deviceContext->ServiceInfo.TargetProcessFound = TRUE;
                        deviceContext->ServiceInfo.TargetProcessId = ProcessId;
                    }
                }
            }
            
            ExReleaseFastMutex(&deviceContext->ServiceInfoMutex);
        }
    }
    // Handle process termination
    else {
        // Get the device context
        device = WdfGetDriver_Device(WdfGetDriver());
        if (device == NULL) {
            return;
        }

        deviceContext = GetDeviceContext(device);
        if (deviceContext == NULL) {
            return;
        }

        // Check if this is our target process
        ExAcquireFastMutex(&deviceContext->ServiceInfoMutex);
        
        if (deviceContext->ServiceInfo.TargetProcessFound &&
            deviceContext->ServiceInfo.TargetProcessId == ProcessId) {
            
            // Our target process has terminated
            SERVICE_PROTECTOR_PRINT("Target service process terminated: %wZ (PID: %lu)",
                deviceContext->ServiceInfo.ServiceName, HandleToULong(ProcessId));
            
            deviceContext->ServiceInfo.TargetProcessFound = FALSE;
            deviceContext->ServiceInfo.TargetProcessId = NULL;
        }
        
        ExReleaseFastMutex(&deviceContext->ServiceInfoMutex);
    }
}

// Device I/O control handler
VOID
ServiceProtectorEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    NTSTATUS status = STATUS_SUCCESS;
    WDFDEVICE device;
    PDEVICE_CONTEXT deviceContext;
    PVOID inputBuffer;
    size_t bufferSize;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    device = WdfIoQueueGetDevice(Queue);
    deviceContext = GetDeviceContext(device);

    switch (IoControlCode) {
    case IOCTL_SERVICE_PROTECTOR_SET_TARGET:
        // Retrieve the input buffer
        status = WdfRequestRetrieveInputBuffer(
            Request,
            InputBufferLength,
            &inputBuffer,
            &bufferSize
        );

        if (!NT_SUCCESS(status)) {
            SERVICE_PROTECTOR_PRINT("WdfRequestRetrieveInputBuffer failed with status 0x%x", status);
            break;
        }

        // Validate buffer size
        if (bufferSize < sizeof(WCHAR)) {
            SERVICE_PROTECTOR_PRINT("Input buffer too small");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (bufferSize > sizeof(deviceContext->ServiceInfo.ServiceName)) {
            SERVICE_PROTECTOR_PRINT("Input buffer too large");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        // Update the target service name
        ExAcquireFastMutex(&deviceContext->ServiceInfoMutex);
        
        // Reset current target
        deviceContext->ServiceInfo.TargetProcessFound = FALSE;
        deviceContext->ServiceInfo.TargetProcessId = NULL;
        
        // Copy the new service name
        RtlCopyMemory(
            deviceContext->ServiceInfo.ServiceName,
            inputBuffer,
            bufferSize
        );
        
        // Ensure null termination
        if (bufferSize < sizeof(deviceContext->ServiceInfo.ServiceName)) {
            ((PWCHAR)deviceContext->ServiceInfo.ServiceName)[bufferSize / sizeof(WCHAR)] = L'\0';
        }
        else {
            ((PWCHAR)deviceContext->ServiceInfo.ServiceName)[(sizeof(deviceContext->ServiceInfo.ServiceName) / sizeof(WCHAR)) - 1] = L'\0';
        }
        
        SERVICE_PROTECTOR_PRINT("Target service set to: %ws", deviceContext->ServiceInfo.ServiceName);
        
        ExReleaseFastMutex(&deviceContext->ServiceInfoMutex);
        break;

    default:
        SERVICE_PROTECTOR_PRINT("Unknown IOCTL code: 0x%x", IoControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestComplete(Request, status);
}
