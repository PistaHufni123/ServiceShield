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
    WDFDRIVER driver = NULL;
    WDFDEVICE device;
    PDEVICE_CONTEXT deviceContext;
    DECLARE_CONST_UNICODE_STRING(deviceName, L"\\Device\\ServiceProtector");
    DECLARE_CONST_UNICODE_STRING(symbolicLinkName, L"\\DosDevices\\ServiceProtector");

    // Initialize the driver configuration
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.EvtDriverUnload = ServiceProtectorEvtDriverUnload;
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;

    // Initialize WDF driver
    WDF_OBJECT_ATTRIBUTES driverAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT(&driverAttributes);

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        &driverAttributes,        // Use initialized attributes instead of WDF_NO_OBJECT_ATTRIBUTES
        &config,
        &driver);

    if (!NT_SUCCESS(status)) {
        KdPrint(("WdfDriverCreate failed with status 0x%x\n", status));
        return status;
    }

    // Set up driver unload routine
    DriverObject->DriverUnload = ServiceProtectorEvtDriverUnload;

    // Set up IRP handlers if needed
    DriverObject->MajorFunction[IRP_MJ_CREATE] = ServiceProtectorCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = ServiceProtectorCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ServiceProtectorDeviceControl;

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

    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);

    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &device);
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
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
}

// Handle Create/Close requests
NTSTATUS
ServiceProtectorCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

// Handle Device Control requests
NTSTATUS
ServiceProtectorDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp;
    PDEVICE_CONTEXT deviceContext;
    PVOID inputBuffer = NULL;
    ULONG inputBufferLength = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    if (irpSp == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_SERVICE_PROTECTOR_SET_TARGET:
        if (inputBufferLength == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        inputBuffer = Irp->AssociatedIrp.SystemBuffer;
        if (inputBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        deviceContext = GetDeviceContext(g_Device);
        if (deviceContext == NULL) {
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }

        ExAcquireFastMutex(&deviceContext->ServiceInfoMutex);
        __try {
            RtlZeroMemory(deviceContext->ServiceInfo.ServiceName, sizeof(deviceContext->ServiceInfo.ServiceName));
            RtlCopyMemory(
                deviceContext->ServiceInfo.ServiceName, 
                inputBuffer, 
                min(inputBufferLength, sizeof(deviceContext->ServiceInfo.ServiceName) - sizeof(WCHAR))
            );
            deviceContext->ServiceInfo.ServiceName[MAX_SERVICE_NAME_LENGTH - 1] = L'\0'; // Ensure null termination
        }
        __finally {
            ExReleaseFastMutex(&deviceContext->ServiceInfoMutex);
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

Exit:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}