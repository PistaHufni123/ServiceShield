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

#include "ServiceProtector.h"

// Global device reference
WDFDEVICE g_Device = NULL;

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
    WDFDEVICE device;
    PDEVICE_CONTEXT deviceContext;
    DECLARE_CONST_UNICODE_STRING(deviceName, L"\\Device\\ServiceProtector");
    DECLARE_CONST_UNICODE_STRING(symbolicLinkName, L"\\DosDevices\\ServiceProtector");

    // Initialize the driver configuration
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.EvtDriverUnload = ServiceProtectorEvtDriverUnload;
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;

    // Initialize driver without using WDF function table directly
    NTSTATUS status = STATUS_SUCCESS;
    
    // Set up driver unload routine
    DriverObject->DriverUnload = ServiceProtectorEvtDriverUnload;
    
    // Set up IRP handlers if needed
    DriverObject->MajorFunction[IRP_MJ_CREATE] = ServiceProtectorCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = ServiceProtectorCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ServiceProtectorDeviceControl;

    // Create the device object
    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, L"\\Device\\ServiceProtector");
    
    status = IoCreateDevice(
        DriverObject,
        sizeof(DEVICE_CONTEXT),
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &g_Device
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PWDFDEVICE_INIT deviceInit = WdfControlDeviceInitAllocate(driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
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

    WdfControlFinishInitializing(device);
    return STATUS_SUCCESS;
}

// Driver unload handler
VOID
ServiceProtectorEvtDriverUnload(
    _In_ WDFDRIVER Driver
)
{
    UNREFERENCED_PARAMETER(Driver);
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

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (Queue == NULL || Request == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    device = WdfIoQueueGetDevice(Queue);
    if (device == NULL) {
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto Exit;
    }

    deviceContext = GetDeviceContext(device);
    if (deviceContext == NULL) {
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto Exit;
    }

    switch (IoControlCode) {
    case IOCTL_SERVICE_PROTECTOR_SET_TARGET:
        if (InputBufferLength == 0) {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        status = WdfRequestRetrieveInputBuffer(
            Request,
            InputBufferLength,
            &inputBuffer,
            &bufferSize
        );

        if (!NT_SUCCESS(status) || inputBuffer == NULL) {
            goto Exit;
        }

        if (bufferSize > sizeof(deviceContext->ServiceInfo.ServiceName)) {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        ExAcquireFastMutex(&deviceContext->ServiceInfoMutex);
        RtlZeroMemory(deviceContext->ServiceInfo.ServiceName, sizeof(deviceContext->ServiceInfo.ServiceName));
        RtlCopyMemory(deviceContext->ServiceInfo.ServiceName, inputBuffer, bufferSize);
        ExReleaseFastMutex(&deviceContext->ServiceInfoMutex);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

Exit:
    if (Request != NULL) {
        WdfRequestComplete(Request, status);
    }
}