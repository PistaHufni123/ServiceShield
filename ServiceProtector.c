/*++

Module Name:

    ServiceProtector.c

Abstract:

    Implementation of the ServiceProtector driver

Environment:

    Kernel mode

--*/

// Define Windows version and architecture targets for kernel-mode driver
#define NTDDI_VERSION NTDDI_WIN10_RS1
#define _WIN32_WINNT 0x0A00  // Windows 10
#define _AMD64_            // For 64-bit driver (use _X86_ for 32-bit)

// Include our driver header with proper include order
#include "ServiceProtector.h"

// Add trace headers
#include "trace.h"

// Global device reference to avoid WdfDriverGetDevice usage
WDFDEVICE g_Device = NULL;

// Global flag to disable all callbacks if BSOD is detected
volatile LONG g_DriverSafetyMode = 0;

// The following include is required for WPP tracing
// This will be auto-generated during compilation by the WPP preprocessor
#ifdef WPP_ENABLED
#include "ServiceProtector.tmh"
#endif

// Safe wrapper that acts as a fail-safe in case of repeated BSODs
VOID ActivateSafetyMode(VOID)
{
    // Set the global safety flag to disable all callbacks
    SERVICE_PROTECTOR_PRINT("!!! ACTIVATING DRIVER SAFETY MODE - PROTECTION DISABLED !!!");
    InterlockedExchange(&g_DriverSafetyMode, 1);
}

// Helper function for memory validation with fail-safe
BOOLEAN IsMemoryCorrupted(PVOID Memory, SIZE_T Size) 
{
    if (Memory == NULL || Size == 0) {
        return TRUE; // Consider null memory as corrupted
    }

    // Use exception handling to check if memory is accessible
    __try {
        // Read the first and last byte to check boundaries
        volatile BYTE firstByte = *((BYTE*)Memory);
        if (Size > 1) {
            volatile BYTE lastByte = *((BYTE*)Memory + (Size - 1));
            // Prevent compiler from optimizing out
            if ((firstByte == 0 && lastByte == 0) || 
                (firstByte != 0 && lastByte != 0)) {
                // Just a dummy check to make the compiler use the values
            }
        }
        return FALSE; // Memory seems valid
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Memory access caused an exception
        SERVICE_PROTECTOR_PRINT("Memory corruption detected!");
        ActivateSafetyMode(); // Immediately enable safety mode
        return TRUE;
    }
}

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
#ifdef WPP_ENABLED
    WPP_INIT_TRACING(DriverObject, RegistryPath);
#endif

    SERVICE_PROTECTOR_PRINT("Driver initializing");

    // Initialize the driver configuration
    // Initialize driver configuration
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.EvtDriverUnload = ServiceProtectorEvtDriverUnload;
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.DriverPoolTag = 'PSVC';

    // Set additional WDF attributes for the driver
    WDF_OBJECT_ATTRIBUTES driverAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT(&driverAttributes);
    driverAttributes.SynchronizationScope = WdfSynchronizationScopeNone;

    // Create the WDF driver object with enhanced error checking
    SERVICE_PROTECTOR_PRINT("Creating WDF driver object");

    // Validate WDF environment
    if (WdfFunctions == NULL) {
        SERVICE_PROTECTOR_PRINT("Critical Error: WDF function table is NULL");
        return STATUS_DRIVER_INTERNAL_ERROR;
    }

    // Validate driver parameters
    if (DriverObject == NULL || RegistryPath == NULL) {
        SERVICE_PROTECTOR_PRINT("Invalid driver parameters");
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        status = WdfDriverCreate(
            DriverObject,
            RegistryPath,
            WDF_NO_OBJECT_ATTRIBUTES,
            &config,
            &driver
        );
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        SERVICE_PROTECTOR_PRINT("Exception in WdfDriverCreate");
        return STATUS_DRIVER_INTERNAL_ERROR;
    }

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
    WDF_FILEOBJECT_CONFIG fileConfig;
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, 
                               WDF_NO_EVENT_CALLBACK,  // No create callback
                               WDF_NO_EVENT_CALLBACK,  // No close callback
                               WDF_NO_EVENT_CALLBACK); // No cleanup callback

    fileConfig.FileObjectClass = WdfFileObjectCanBeOptional;

    WdfDeviceInitSetFileObjectConfig(
        deviceInit,
        &fileConfig,
        WDF_NO_OBJECT_ATTRIBUTES
    );

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);

    // Create the device with enhanced error handling and verification
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.SynchronizationScope = WdfSynchronizationScopeDevice;

    // Additional device initialization with error checking
    if (deviceInit == NULL) {
        SERVICE_PROTECTOR_PRINT("deviceInit is NULL before WdfDeviceInitSetDeviceType");
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        status = WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_UNKNOWN);
        if (!NT_SUCCESS(status)) {
            SERVICE_PROTECTOR_PRINT("WdfDeviceInitSetDeviceType failed with status 0x%x", status);
            WdfDeviceInitFree(deviceInit);
            return status;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        SERVICE_PROTECTOR_PRINT("Exception in WdfDeviceInitSetDeviceType");
        if (deviceInit != NULL) {
            WdfDeviceInitFree(deviceInit);
        }
        return STATUS_DRIVER_INTERNAL_ERROR;
    }

    status = WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);
    if (!NT_SUCCESS(status)) {
        SERVICE_PROTECTOR_PRINT("WdfDeviceInitSetIoType failed with status 0x%x", status);
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    // Set exclusive access to prevent multiple opens
    WdfDeviceInitSetExclusive(deviceInit, TRUE);

    SERVICE_PROTECTOR_PRINT("Creating WDF device object");
    status = WdfDeviceCreate(&deviceInit, &attributes, &device);
    if (!NT_SUCCESS(status)) {
        SERVICE_PROTECTOR_PRINT("WdfDeviceCreate failed with status 0x%x", status);
        if (deviceInit != NULL) {
            WdfDeviceInitFree(deviceInit);
        }
        return status;
    }

    // Verify device creation and initialization
    if (device == NULL) {
        SERVICE_PROTECTOR_PRINT("Device creation succeeded but handle is NULL");
        WdfDeviceInitFree(deviceInit);
        return STATUS_UNSUCCESSFUL;
    }

    // Set device characteristics
    WdfDeviceSetCharacteristics(device, FILE_DEVICE_SECURE_OPEN);

    // Verify device initialization
    if (device == NULL) {
        SERVICE_PROTECTOR_PRINT("Device handle is NULL after creation");
        WdfDeviceInitFree(deviceInit);
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    // Initialize device context
    deviceContext = GetDeviceContext(device);
    if (deviceContext == NULL) {
        SERVICE_PROTECTOR_PRINT("Failed to get device context");
        return STATUS_DEVICE_NOT_CONNECTED;
    }
    RtlZeroMemory(deviceContext, sizeof(DEVICE_CONTEXT));

    // Store the device handle in our global variable with validation
    if (device != NULL) {
        g_Device = device;
        SERVICE_PROTECTOR_PRINT("Device created successfully");
    } else {
        SERVICE_PROTECTOR_PRINT("Device handle is NULL after creation");
        return STATUS_UNSUCCESSFUL;
    }

    // Verify device was created properly
    if (g_Device == NULL) {
        SERVICE_PROTECTOR_PRINT("Global device handle is NULL");
        return STATUS_DEVICE_NOT_CONNECTED;
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

    // Get the device context from the driver
    // For this driver, we've only created one device, so we'll use a global reference
    device = g_Device;
    if (device == NULL) {
        SERVICE_PROTECTOR_PRINT("No device found for driver");
        return;
    }

    deviceContext = GetDeviceContext(device);

    // Unregister process notifications
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);

    // Unregister callbacks
    UnregisterCallbacks(deviceContext);

    SERVICE_PROTECTOR_PRINT("Driver unloaded successfully");

    // Cleanup WPP Tracing
#ifdef WPP_ENABLED
    WPP_CLEANUP(WdfDriverWdmGetDriverObject(Driver));
#endif
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
    // SAFETY FIRST: Check global safety mode flag
    if (InterlockedCompareExchange(&g_DriverSafetyMode, 0, 0) == 1) {
        // Driver is in safety mode - return success without doing anything
        return OB_PREOP_SUCCESS;
    }

    // Variables declared at the top level for structured exception handling
    PDEVICE_CONTEXT deviceContext = NULL;
    ACCESS_MASK deniedAccess = 0;
    PACCESS_MASK desiredAccess = NULL;
    HANDLE targetProcessId = NULL;
    PEPROCESS targetProcess = NULL;
    HANDLE currentProcessId = NULL;
    BOOLEAN mutexAcquired = FALSE;
    NTSTATUS status = STATUS_SUCCESS; // Initialize status here

    // Counter for tracking problems, helps enable safety mode after 
    // encountering multiple exceptions
    static volatile LONG exceptionCounter = 0;

    // Use exception handling to guard ALL operations
    __try {
        // Track failures - if we get too many exceptions, go into safe mode
        if (InterlockedIncrement(&exceptionCounter) > 5) {
            ActivateSafetyMode();
            return OB_PREOP_SUCCESS;
        }
        // Basic null pointer checks - Do NOT proceed if anything is missing
        if (PreInfo == NULL || 
            PsProcessType == NULL || 
            RegistrationContext == NULL) {
            SERVICE_PROTECTOR_PRINT("NULL essential parameters in PreOperationCallback");
            return OB_PREOP_SUCCESS;
        }

        // Additional pointer validations
        if (PreInfo->ObjectType == NULL) {
            SERVICE_PROTECTOR_PRINT("NULL ObjectType");
            return OB_PREOP_SUCCESS;
        }

        if (PreInfo->Object == NULL) {
            SERVICE_PROTECTOR_PRINT("NULL Object pointer");
            return OB_PREOP_SUCCESS;
        }

        // Check for corrupted PreInfo memory structures
        if (IsMemoryCorrupted(PreInfo, sizeof(OB_PRE_OPERATION_INFORMATION))) {
            SERVICE_PROTECTOR_PRINT("PreInfo memory corruption detected");
            ActivateSafetyMode(); // Critical failure, immediately activate safety mode
            return OB_PREOP_SUCCESS;
        }

        __try {
            status = STATUS_SUCCESS;
            deviceContext = (PDEVICE_CONTEXT)RegistrationContext;

            // Verify context fields to ensure it's valid
            if (deviceContext == NULL ||
                deviceContext->Device == NULL) {
                SERVICE_PROTECTOR_PRINT("Invalid deviceContext");
                return OB_PREOP_SUCCESS;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            SERVICE_PROTECTOR_PRINT("Exception accessing device context");
            status = STATUS_ACCESS_VIOLATION;
            return OB_PREOP_SUCCESS;
        }

        // Process protection logic - only for process objects
        // Safe comparison for object types
        BOOLEAN isProcessObject = FALSE;

        __try {
            isProcessObject = (PreInfo->ObjectType == *PsProcessType);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            SERVICE_PROTECTOR_PRINT("Exception comparing object types");
            return OB_PREOP_SUCCESS;
        }

        if (!isProcessObject) {
            // Not a process object - nothing to do
            return OB_PREOP_SUCCESS;
        }

        // Get the process ID with safe exception handling
        __try {
            targetProcess = (PEPROCESS)PreInfo->Object;

            if (targetProcess == NULL) {
                SERVICE_PROTECTOR_PRINT("NULL target process");
                return OB_PREOP_SUCCESS;
            }

            targetProcessId = PsGetProcessId(targetProcess);

            if (targetProcessId == NULL) {
                SERVICE_PROTECTOR_PRINT("NULL process ID");
                return OB_PREOP_SUCCESS;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            SERVICE_PROTECTOR_PRINT("Exception getting process ID");
            return OB_PREOP_SUCCESS;
        }

        // Safely access the mutex with timeout to prevent deadlocks
        __try {
            ExAcquireFastMutex(&deviceContext->ServiceInfoMutex);
            mutexAcquired = TRUE;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            SERVICE_PROTECTOR_PRINT("Exception acquiring mutex");
            return OB_PREOP_SUCCESS;
        }

        // Main protection logic wrapped in try/finally
        __try {
            // Guard every field access with additional checks
            if (!deviceContext->ServiceInfo.TargetProcessFound) {
                __leave; // No target to protect
            }

            // Verify target process ID before comparison
            if (deviceContext->ServiceInfo.TargetProcessId == NULL) {
                __leave; // Invalid target process ID
            }

            // Safely compare process IDs
            BOOLEAN isTargetProcess = FALSE;

            __try {
                isTargetProcess = (deviceContext->ServiceInfo.TargetProcessId == targetProcessId);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                SERVICE_PROTECTOR_PRINT("Exception comparing process IDs");
                __leave;
            }

            if (!isTargetProcess) {
                __leave; // Not our target process
            }

            // This is our protected process
            // Safely check if this is kernel handle
            BOOLEAN isUserModeAccess = FALSE;

            __try {
                isUserModeAccess = (PreInfo->KernelHandle == FALSE);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                SERVICE_PROTECTOR_PRINT("Exception checking KernelHandle");
                __leave;
            }

            if (!isUserModeAccess) {
                __leave; // Kernel handle - allow access
            }

            // Safely get current process ID for comparison
            __try {
                currentProcessId = PsGetCurrentProcessId();

                if (currentProcessId == NULL) {
                    SERVICE_PROTECTOR_PRINT("NULL current process ID");
                    __leave;
                }

                // Allow access from the process itself
                if (currentProcessId == targetProcessId) {
                    __leave;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                SERVICE_PROTECTOR_PRINT("Exception getting current process ID");
                __leave;
            }

            // User-mode access from another process - check parameters
            BOOLEAN hasValidParameters = FALSE;

            __try {
                hasValidParameters = (PreInfo->Parameters != NULL);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                SERVICE_PROTECTOR_PRINT("Exception accessing Parameters");
                __leave;
            }

            if (!hasValidParameters) {
                SERVICE_PROTECTOR_PRINT("NULL Parameters");
                __leave;
            }

            // Safely get the desired access pointer within exception handling
            __try {
                ULONG operation = 0;

                // First safely read the operation value
                operation = PreInfo->Operation;

                // Check operation type
                if (operation == OB_OPERATION_HANDLE_CREATE) {
                    // Verify the field exists before accessing
                    if (PreInfo->Parameters != NULL) {
                        desiredAccess = &PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
                    }
                }
                else if (operation == OB_OPERATION_HANDLE_DUPLICATE) {
                    // Verify the field exists before accessing
                    if (PreInfo->Parameters != NULL) {
                        desiredAccess = &PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
                    }
                }
                else {
                    SERVICE_PROTECTOR_PRINT("Unknown operation: %d", operation);
                    desiredAccess = NULL;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                SERVICE_PROTECTOR_PRINT("Exception getting desired access");
                __leave;
            }

            // Only proceed if we have a valid access mask pointer
            if (desiredAccess == NULL) {
                __leave;
            }

            // Determine which access rights to deny
            __try {
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
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                SERVICE_PROTECTOR_PRINT("Exception checking access rights");
                __leave;
            }

            // Apply restrictions only if we're denying something
            if (deniedAccess != 0) {
                __try {
                    // Log with safe access to service name
                    WCHAR safeServiceName[MAX_SERVICE_NAME_LENGTH] = L"<unknown>";

                    // Safely copy service name with bounds checking
                    if (deviceContext->ServiceInfo.ServiceName[0] != L'\0') {
                        wcsncpy(safeServiceName, 
                                deviceContext->ServiceInfo.ServiceName, 
                                MAX_SERVICE_NAME_LENGTH - 1);
                        safeServiceName[MAX_SERVICE_NAME_LENGTH - 1] = L'\0';
                    }

                    SERVICE_PROTECTOR_PRINT(
                        "Protected process %ws (PID: %lu) from access 0x%x by process %lu",
                        safeServiceName,
                        HandleToULong(targetProcessId),
                        deniedAccess,
                        HandleToULong(currentProcessId)
                    );

                    // Remove the denied access rights
                    *desiredAccess &= ~deniedAccess;
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    SERVICE_PROTECTOR_PRINT("Exception removing access rights");
                    // Continue execution - we tried our best to protect
                }
            }
        }
        __finally {
            // Always release the mutex if it was acquired
            if (mutexAcquired) {
                __try {
                    ExReleaseFastMutex(&deviceContext->ServiceInfoMutex);
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    SERVICE_PROTECTOR_PRINT("Exception releasing mutex");
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Top-level exception handler - catch anything we missed
        SERVICE_PROTECTOR_PRINT("Unhandled exception in PreOperationCallback");
    }

    // Always succeed - never fail the operation itself
    return OB_PREOP_SUCCESS;
}

// Process notification callback
VOID
ProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PVOID CreateInfoPtr
)
{
    // Check if we're in safety mode - if so, do nothing
    if (InterlockedCompareExchange(&g_DriverSafetyMode, 0, 0) == 1) {
        return;
    }

    PDEVICE_CONTEXT deviceContext = NULL;
    WDFDEVICE device = NULL;
    UNICODE_STRING processName = {0};
    UNICODE_STRING targetServiceName = {0};
    BOOLEAN mutexAcquired = FALSE;

    // Counter for tracking problems - helps detect recurring issues
    static volatile LONG processCallbackExceptionCounter = 0;

    // Safety check for null process ID
    if (ProcessId == NULL) {
        SERVICE_PROTECTOR_PRINT("ProcessNotifyCallback: NULL ProcessId");
        return;
    }

    // Avoid using Process parameter directly as it might be unreliable
    UNREFERENCED_PARAMETER(Process);

    __try {
        // Track problems and activate safety mode if we have too many exceptions
        if (InterlockedIncrement(&processCallbackExceptionCounter) > 5) {
            ActivateSafetyMode();
            return;
        }
        // Handle process creation
        if (CreateInfoPtr != NULL) {
            // Cast the CreateInfoPtr to our custom structure type with validation
            PPS_CREATE_NOTIFY_INFO CreateInfo = NULL;

            // Use exception handling to protect against invalid pointers
            __try {
                CreateInfo = (PPS_CREATE_NOTIFY_INFO)CreateInfoPtr;

                // Verify structure size as basic sanity check
                if (CreateInfo->Size < sizeof(PS_CREATE_NOTIFY_INFO)) {
                    SERVICE_PROTECTOR_PRINT("Invalid CreateInfo size: %zu", CreateInfo->Size);
                    __leave;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                SERVICE_PROTECTOR_PRINT("Exception accessing CreateInfo structure");
                __leave;
            }

            // Validate CreateInfo after safe access check
            if (CreateInfo == NULL) {
                SERVICE_PROTECTOR_PRINT("CreateInfo is NULL after validation");
                __leave;
            }

            // Use our global device reference instead of WdfDriverGetDevice
            device = g_Device;
            if (device == NULL) {
                SERVICE_PROTECTOR_PRINT("Failed to get device from global reference");
                __leave; // Jump to finally block
            }

            deviceContext = GetDeviceContext(device);
            if (deviceContext == NULL) {
                SERVICE_PROTECTOR_PRINT("Failed to get device context");
                __leave;
            }

            // Validate the CreateInfo structure and its fields
            if (CreateInfo->ImageFileName == NULL) {
                SERVICE_PROTECTOR_PRINT("NULL ImageFileName");
                __leave;
            }

            // Check for memory corruption in the CreateInfo structure
            if (IsMemoryCorrupted(CreateInfo, CreateInfo->Size)) {
                SERVICE_PROTECTOR_PRINT("CreateInfo memory corruption detected");
                __leave;
            }

            // Check if this is the target service - first acquire the mutex
            ExAcquireFastMutex(&deviceContext->ServiceInfoMutex);
            mutexAcquired = TRUE;

            // Check if we have a valid service name to protect
            if (deviceContext->ServiceInfo.ServiceName[0] == L'\0') {
                SERVICE_PROTECTOR_PRINT("No target service name set");
                __leave;
            }

            // Initialize target service name string
            RtlInitUnicodeString(&targetServiceName, deviceContext->ServiceInfo.ServiceName);

            // Validate image filename buffer
            if (CreateInfo->ImageFileName->Buffer == NULL) {
                SERVICE_PROTECTOR_PRINT("NULL ImageFileName Buffer");
                __leave;
            }

            // Process the image filename
            processName = *CreateInfo->ImageFileName;
            if (processName.Length == 0 || processName.Buffer == NULL) {
                SERVICE_PROTECTOR_PRINT("Empty process name");
                __leave;
            }

            // Check if the process name ends with the service executable name
            BOOLEAN nameMatches = FALSE;

            // Prevent integer overflow/underflow in length calculations
            if (processName.Length < targetServiceName.Length) {
                // Process name is too short to match the target
                __leave;
            }

            // Calculate pointer to the suffix with proper bounds checking
            SIZE_T suffixOffset = processName.Length - targetServiceName.Length;
            if (suffixOffset > processName.Length) {
                SERVICE_PROTECTOR_PRINT("Invalid suffix offset calculation");
                __leave; // Integer overflow, bail out
            }

            PCWSTR processSuffix = (PCWSTR)((PCHAR)processName.Buffer + suffixOffset);

            // Validate the suffix pointer is within bounds
            if ((ULONG_PTR)processSuffix < (ULONG_PTR)processName.Buffer || 
                (ULONG_PTR)processSuffix >= (ULONG_PTR)processName.Buffer + processName.Length) {
                SERVICE_PROTECTOR_PRINT("Suffix pointer out of bounds");
                __leave;
            }

            // Compare the suffix - case insensitive comparison
            // Upper case both for comparison
            WCHAR processTemp[MAX_SERVICE_NAME_LENGTH] = {0};
            WCHAR targetTemp[MAX_SERVICE_NAME_LENGTH] = {0};

            // Check for null pointers again
            if (processSuffix == NULL || targetServiceName.Buffer == NULL) {
                SERVICE_PROTECTOR_PRINT("NULL buffer for string comparison");
                __leave;
            }

            // Buffer size safety calculations
            ULONG maxCopyChars = MAX_SERVICE_NAME_LENGTH - 1;
            ULONG targetChars = targetServiceName.Length / sizeof(WCHAR);

            // Avoid integer overflow in the division
            if (targetServiceName.Length <= 0 || targetChars * sizeof(WCHAR) != targetServiceName.Length) {
                SERVICE_PROTECTOR_PRINT("Invalid target name length: %d", targetServiceName.Length);
                __leave;
            }

            // Use the smaller of the two to prevent buffer overflows
            ULONG copyLength = (targetChars < maxCopyChars) ? targetChars : maxCopyChars;

            // Final validation before copying
            if (copyLength == 0 || copyLength > MAX_SERVICE_NAME_LENGTH - 1) {
                SERVICE_PROTECTOR_PRINT("Invalid copy length: %u", copyLength);
                __leave;
            }

            // Safe copy with character validation
            for (ULONG i = 0; i < copyLength; i++) {
                // Bounds checking for each character
                if (&processSuffix[i] < processSuffix || 
                    &targetServiceName.Buffer[i] < targetServiceName.Buffer) {
                    SERVICE_PROTECTOR_PRINT("Character access out of bounds");
                    __leave;
                }

                // Copy characters with validation
                WCHAR procChar = processSuffix[i];
                WCHAR targChar = targetServiceName.Buffer[i];

                // Check for invalid characters
                if (procChar == 0 || targChar == 0) {
                    // Early termination found
                    break;
                }

                processTemp[i] = RtlUpcaseUnicodeChar(procChar);
                targetTemp[i] = RtlUpcaseUnicodeChar(targChar);
            }

            // Ensure null termination
            processTemp[copyLength] = L'\0';
            targetTemp[copyLength] = L'\0';

            // Compare the strings
            nameMatches = (wcscmp(processTemp, targetTemp) == 0);

            if (nameMatches) {
                // ProcessName is a UNICODE_STRING so %wZ is the correct format
                SERVICE_PROTECTOR_PRINT("Target service process started: %wZ (PID: %lu)",
                    &processName, HandleToULong(ProcessId));

                // Mark this process as our target for protection
                deviceContext->ServiceInfo.TargetProcessFound = TRUE;
                deviceContext->ServiceInfo.TargetProcessId = ProcessId;
            }
        }
        // Handle process termination
        else {
            // Use our global device reference instead of WdfDriverGetDevice
            device = g_Device;
            if (device == NULL) {
                SERVICE_PROTECTOR_PRINT("Failed to get device from global reference (termination)");
                __leave;
            }

            deviceContext = GetDeviceContext(device);
            if (deviceContext == NULL) {
                SERVICE_PROTECTOR_PRINT("Failed to get device context (termination)");
                __leave;
            }

            // Check if this is our target process
            ExAcquireFastMutex(&deviceContext->ServiceInfoMutex);
            mutexAcquired = TRUE;

            if (deviceContext->ServiceInfo.TargetProcessFound &&
                deviceContext->ServiceInfo.TargetProcessId == ProcessId) {

                // Our target process has terminated
                SERVICE_PROTECTOR_PRINT("Target service process terminated: %ws (PID: %lu)",
                    deviceContext->ServiceInfo.ServiceName, HandleToULong(ProcessId));

                deviceContext->ServiceInfo.TargetProcessFound = FALSE;
                deviceContext->ServiceInfo.TargetProcessId = NULL;
            }
        }
    }
    __finally {
        // Always release the mutex if it was acquired
        if (mutexAcquired && deviceContext != NULL) {
            ExReleaseFastMutex(&deviceContext->ServiceInfoMutex);
        }
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
    WDFDEVICE device = NULL;
    PDEVICE_CONTEXT deviceContext = NULL;
    PVOID inputBuffer = NULL;
    size_t bufferSize = 0;
    BOOLEAN mutexAcquired = FALSE;

    // Safety mode detection and tracking
    static volatile LONG ioctlExceptionCounter = 0;

    // If we're in safety mode, just pass requests through without processing
    if (InterlockedCompareExchange(&g_DriverSafetyMode, 0, 0) == 1) {
        if (Request != NULL) {
            WdfRequestComplete(Request, STATUS_SUCCESS);
        }
        return;
    }

    UNREFERENCED_PARAMETER(OutputBufferLength);

    // Parameter validation to prevent crashes
    if (Queue == NULL) {
        SERVICE_PROTECTOR_PRINT("NULL Queue parameter");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (Request == NULL) {
        SERVICE_PROTECTOR_PRINT("NULL Request parameter");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // Get device from queue with additional safety
    __try {
        // Track IOCTL problems and enter safety mode if we get too many
        if (InterlockedIncrement(&ioctlExceptionCounter) > 5) {
            ActivateSafetyMode();
            status = STATUS_SUCCESS;
            goto Exit;
        }
        device = WdfIoQueueGetDevice(Queue);
        if (device == NULL) {
            SERVICE_PROTECTOR_PRINT("Failed to get device from queue");
            status = STATUS_INVALID_DEVICE_REQUEST;
            __leave;
        }

        deviceContext = GetDeviceContext(device);
        if (deviceContext == NULL) {
            SERVICE_PROTECTOR_PRINT("Failed to get device context");
            status = STATUS_INVALID_DEVICE_REQUEST;
            __leave;
        }

        switch (IoControlCode) {
        case IOCTL_SERVICE_PROTECTOR_SET_TARGET:
            // Retrieve the input buffer with additional safety
            if (InputBufferLength == 0) {
                SERVICE_PROTECTOR_PRINT("Zero-length input buffer");
                status = STATUS_INVALID_PARAMETER;
                __leave;
            }

            status = WdfRequestRetrieveInputBuffer(
                Request,
                InputBufferLength,
                &inputBuffer,
                &bufferSize
            );

            if (!NT_SUCCESS(status)) {
                SERVICE_PROTECTOR_PRINT("WdfRequestRetrieveInputBuffer failed with status 0x%x", status);
                __leave;
            }

            if (inputBuffer == NULL) {
                SERVICE_PROTECTOR_PRINT("NULL input buffer returned");
                status = STATUS_INVALID_PARAMETER;
                __leave;
            }

            // Advanced memory corruption detection beyond ProbeForRead
            if (IsMemoryCorrupted(inputBuffer, bufferSize)) {
                SERVICE_PROTECTOR_PRINT("Memory corruption detected in input buffer");
                status = STATUS_ACCESS_VIOLATION;
                ActivateSafetyMode(); // Be very defensive against bad input
                __leave;
            }

            // Validate buffer size and content
            if (bufferSize < sizeof(WCHAR)) {
                SERVICE_PROTECTOR_PRINT("Input buffer too small");
                status = STATUS_BUFFER_TOO_SMALL;
                __leave;
            }

            if (bufferSize > sizeof(deviceContext->ServiceInfo.ServiceName)) {
                SERVICE_PROTECTOR_PRINT("Input buffer too large");
                status = STATUS_INVALID_PARAMETER;
                __leave;
            }

            // Verify buffer can be read safely
            __try {
                if (inputBuffer != NULL && bufferSize > 0) {
                    // ProbeForRead throws an exception if the buffer is invalid
                    ProbeForRead(inputBuffer, bufferSize, sizeof(WCHAR));
                    // If we reach here, the probe succeeded
                    status = STATUS_SUCCESS;
                } else {
                    status = STATUS_INVALID_PARAMETER;
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                SERVICE_PROTECTOR_PRINT("Input buffer probe failed");
                status = STATUS_ACCESS_VIOLATION;
                __leave;
            }

            // Update the target service name within a controlled try/finally
            ExAcquireFastMutex(&deviceContext->ServiceInfoMutex);
            mutexAcquired = TRUE;

            // Reset current target
            deviceContext->ServiceInfo.TargetProcessFound = FALSE;
            deviceContext->ServiceInfo.TargetProcessId = NULL;

            // Zero out the destination buffer first for safety
            RtlZeroMemory(deviceContext->ServiceInfo.ServiceName, sizeof(deviceContext->ServiceInfo.ServiceName));

            // Calculate safe limits for copying
            size_t maxChars = (sizeof(deviceContext->ServiceInfo.ServiceName) / sizeof(WCHAR)) - 1;

            // Check for division overflow
            if (maxChars * sizeof(WCHAR) > sizeof(deviceContext->ServiceInfo.ServiceName)) {
                SERVICE_PROTECTOR_PRINT("Calculation overflow in character limits");
                status = STATUS_INTEGER_OVERFLOW;
                __leave;
            }

            // Calculate input character count with validation
            if (bufferSize % sizeof(WCHAR) != 0) {
                SERVICE_PROTECTOR_PRINT("Input buffer size is not a multiple of WCHAR size");
                status = STATUS_INVALID_PARAMETER;
                __leave;
            }

            size_t inputChars = bufferSize / sizeof(WCHAR);

            // Perform a character-by-character copy with extensive validation
            for (size_t i = 0; i < inputChars && i < maxChars; i++) {
                // Verify each character access is valid
                if ((ULONG_PTR)&((PWCHAR)inputBuffer)[i] >= (ULONG_PTR)inputBuffer + bufferSize) {
                    SERVICE_PROTECTOR_PRINT("Character access would be out of bounds");
                    status = STATUS_INVALID_PARAMETER;
                    __leave;
                }

                // Read character with validation
                WCHAR currentChar;

                try {
                    // Try to safely read the character
                    currentChar = ((PWCHAR)inputBuffer)[i];
                } except(EXCEPTION_EXECUTE_HANDLER) {
                    SERVICE_PROTECTOR_PRINT("Exception reading character at index %zu", i);
                    status = STATUS_ACCESS_VIOLATION;
                    __leave;
                }

                if (currentChar == L'\0') {
                    // Found null terminator - we're done
                    break;
                }

                // Safe copy of the validated character
                deviceContext->ServiceInfo.ServiceName[i] = currentChar;
            }

            // Explicitly ensure null termination
            deviceContext->ServiceInfo.ServiceName[maxChars] = L'\0';

            // Success, log the new service name
            SERVICE_PROTECTOR_PRINT("Target service set to: %ws", deviceContext->ServiceInfo.ServiceName);
            break;

        default:
            SERVICE_PROTECTOR_PRINT("Unknown IOCTL code: 0x%x", IoControlCode);
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }
    __finally {
        // Always release the mutex if it was acquired
        if (mutexAcquired && deviceContext != NULL) {
            ExReleaseFastMutex(&deviceContext->ServiceInfoMutex);
        }
    }

Exit:
    if (Request != NULL) {
        WdfRequestComplete(Request, status);
    }
}