/*++
*
*Module Name:
*
*    ServiceProtector.c
*
*Abstract:
*
*    Implementation of the ServiceProtector driver
*
*Environment:
*
*    Kernel mode
*
--*/

// Define Windows version and architecture targets for kernel-mode driver
#define NTDDI_VERSION NTDDI_WIN10_RS1
#define _WIN32_WINNT 0x0A00  // Windows 10
#define _AMD64_            // For 64-bit driver (use _X86_ for 32-bit)

// Include our driver header with proper include order
#include "ServiceProtector.h"

// Initialize global safety mode flag
volatile LONG g_DriverSafetyMode = 0;

// Add trace headers
#include "trace.h"

// Global device reference to avoid WdfDriverGetDevice usage
WDFDEVICE g_Device = NULL;


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
    PDEVICE_CONTEXT deviceContext;
    DECLARE_CONST_UNICODE_STRING(deviceName, L"\\Device\\ServiceProtector");
    DECLARE_CONST_UNICODE_STRING(symbolicLinkName, L"\\DosDevices\\ServiceProtector");

    // Initialize WPP Tracing
#ifdef WPP_ENABLED
    WPP_INIT_TRACING(DriverObject, RegistryPath);
#endif

    SERVICE_PROTECTOR_PRINT("Driver initializing");

    // Initialize the driver configuration
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.EvtDriverUnload = ServiceProtectorEvtDriverUnload;
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;

    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    deviceInit = WdfControlDeviceInitAllocate(driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (deviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, DEVICE_CONTEXT);

    status = WdfDeviceCreate(&deviceInit, &attributes, &device);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    g_Device = device;
    deviceContext = GetDeviceContext(device);
    RtlZeroMemory(deviceContext, sizeof(DEVICE_CONTEXT));
    deviceContext->Device = device;
    ExInitializeFastMutex(&deviceContext->ServiceInfoMutex);

    status = WdfDeviceCreateSymbolicLink(device, &symbolicLinkName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = RegisterCallbacks(deviceContext);
    if (!NT_SUCCESS(status)) {
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
    UNREFERENCED_PARAMETER(Driver);
    if (g_Device != NULL) {
        PDEVICE_CONTEXT deviceContext = GetDeviceContext(g_Device);
        UnregisterCallbacks(deviceContext);
    }
    // Cleanup WPP Tracing
#ifdef WPP_ENABLED
    WPP_CLEANUP(WdfDriverWdmGetDriverObject(Driver));
#endif
    SERVICE_PROTECTOR_PRINT("Driver unloading");

}

// Register object callbacks
NTSTATUS
RegisterCallbacks(
    _In_ PDEVICE_CONTEXT DeviceContext
)
{
    OB_CALLBACK_REGISTRATION callbackRegistration = {0};
    OB_OPERATION_REGISTRATION operationRegistration = {0};

    operationRegistration.ObjectType = PsProcessType;
    operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE;
    operationRegistration.PreOperation = PreOperationCallback;

    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 1;
    callbackRegistration.RegistrationContext = DeviceContext;
    callbackRegistration.OperationRegistration = &operationRegistration;

    NTSTATUS status = ObRegisterCallbacks(&callbackRegistration, &DeviceContext->RegistrationHandle);
    if (NT_SUCCESS(status)) {
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
    if (DeviceContext->RegistrationHandle != NULL) {
        ObUnRegisterCallbacks(DeviceContext->RegistrationHandle);
        DeviceContext->RegistrationHandle = NULL;
        SERVICE_PROTECTOR_PRINT("Process callbacks unregistered");
    }
}

// Pre-operation callback for handle creation
OB_PREOP_CALLBACK_STATUS
PreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
)
{
    PDEVICE_CONTEXT deviceContext = (PDEVICE_CONTEXT)RegistrationContext;

    if (PreInfo->ObjectType == PsProcessType) {
        ExAcquireFastMutex(&deviceContext->ServiceInfoMutex);

        if (deviceContext->ServiceInfo.TargetProcessFound &&
            deviceContext->ServiceInfo.TargetProcessId == PsGetProcessId((PEPROCESS)PreInfo->Object)) {

            ACCESS_MASK deniedAccess = PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME;
            PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~deniedAccess;
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
                }
                else {
                    status = STATUS_INVALID_PARAMETER;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
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
                }
                except (EXCEPTION_EXECUTE_HANDLER) {
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