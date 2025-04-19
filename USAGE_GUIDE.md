# ServiceProtector Driver Usage Guide

## Overview

The ServiceProtector is a Windows kernel-mode driver designed to protect critical Windows services from unauthorized termination or modification. This guide provides instructions on installing, configuring, and using the driver.

## Prerequisites

Before using the ServiceProtector driver, ensure you have:

1. Administrator privileges on the Windows system
2. A signed driver (for production use) or test signing mode enabled (for development)
3. Knowledge of which service you want to protect

## Installation

### Method 1: Using the INF File

1. Copy the following files to a directory on the target system:
   - ServiceProtector.sys (the driver binary)
   - ServiceProtector.inf (the installation information file)

2. Open an Administrator Command Prompt

3. Navigate to the directory containing the files

4. Install the driver using PnPUtil:
   ```
   pnputil /add-driver ServiceProtector.inf /install
   ```

5. Start the driver service:
   ```
   sc start ServiceProtector
   ```

### Method 2: Manual Installation

1. Copy the ServiceProtector.sys file to `%SystemRoot%\System32\drivers\`

2. Open an Administrator Command Prompt

3. Create the driver service:
   ```
   sc create ServiceProtector type= kernel binPath= %SystemRoot%\System32\drivers\ServiceProtector.sys start= demand
   ```

4. Start the driver service:
   ```
   sc start ServiceProtector
   ```

## Configuration

### Default Configuration

By default, the driver is configured to protect the Windows Print Spooler service (spoolsv.exe) as specified in the INF file. This default setting is loaded from the registry:

```
HKR,Parameters,ServiceToProtect,0x00000000,"spoolsv.exe"
```

### Changing the Protected Service

#### Option 1: Using Registry Editor

1. Open Registry Editor (regedit.exe)

2. Navigate to:
   ```
   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ServiceProtector\Parameters
   ```

3. Create or modify the `ServiceToProtect` string value with the executable name of the service you want to protect (e.g., "lsass.exe")

4. Restart the ServiceProtector driver:
   ```
   sc stop ServiceProtector
   sc start ServiceProtector
   ```

#### Option 2: Using a Control Application

For more dynamic control, you can develop a simple user-mode application that communicates with the driver using the provided IOCTL:

```c
#define IOCTL_SERVICE_PROTECTOR_SET_TARGET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

A simple control application would:

1. Open a handle to the driver device (`\\.\ServiceProtector`)
2. Send the IOCTL with the service name as the input buffer
3. Close the handle

Example C code for a control application:

```c
#include <windows.h>
#include <stdio.h>

// Must match the definition in the driver
#define IOCTL_SERVICE_PROTECTOR_SET_TARGET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

int wmain(int argc, wchar_t* argv[])
{
    HANDLE hDevice;
    DWORD bytesReturned;
    BOOL result;

    if (argc < 2) {
        wprintf(L"Usage: ServiceProtectorControl.exe <service_executable_name>\n");
        wprintf(L"Example: ServiceProtectorControl.exe lsass.exe\n");
        return 1;
    }

    // Open a handle to the device
    hDevice = CreateFile(
        L"\\\\.\\ServiceProtector",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to open device. Error: %d\n", GetLastError());
        return 1;
    }

    // Send the IOCTL to set the target service
    result = DeviceIoControl(
        hDevice,
        IOCTL_SERVICE_PROTECTOR_SET_TARGET,
        argv[1],
        (wcslen(argv[1]) + 1) * sizeof(wchar_t),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!result) {
        wprintf(L"Failed to set target service. Error: %d\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }

    wprintf(L"Successfully set target service to: %s\n", argv[1]);
    CloseHandle(hDevice);
    return 0;
}
```

Compile this control application with Visual Studio or the Windows SDK tools.

## Verifying Protection

To verify that the ServiceProtector driver is working correctly:

1. Ensure the driver is loaded:
   ```
   sc query ServiceProtector
   ```
   The "STATE" field should show "RUNNING"

2. Use Task Manager or a tool like Process Explorer to try terminating the protected service

3. Observe that the termination attempt is blocked

4. Check Event Viewer for any driver messages:
   - Open Event Viewer
   - Navigate to "Windows Logs" > "System"
   - Look for events with source "ServiceProtector"

## Common Use Cases

### Protecting Critical System Services

The ServiceProtector driver is ideal for protecting essential system services such as:

- Local Security Authority Subsystem Service (lsass.exe)
- Windows Defender Antimalware Service (MsMpEng.exe)
- Security Center Service (wscsvc.exe)
- Windows Update Service (wuauserv.exe)

### Protecting Custom Line-of-Business Services

For enterprise environments, you might want to protect custom business-critical services:

1. Identify the executable name of your service (from Services.msc)
2. Configure the ServiceProtector to protect that executable
3. Verify that unauthorized termination attempts are blocked

## Troubleshooting

### Driver Not Loading

If the driver fails to load:

1. Check the system event log for specific error messages
2. Verify that test signing is enabled (if using an unsigned driver)
3. Ensure the driver binary is in the correct location
4. Check for conflicting security software

### Protection Not Working

If the protection mechanism isn't blocking termination attempts:

1. Verify the correct service executable name is configured
2. Check if the service is running under a different process name
3. Use a kernel debugger to set breakpoints in the driver callback functions
4. Look for debug messages from the driver in DebugView (if debug build)

### Uninstalling the Driver

If you need to remove the driver:

1. Stop the driver service:
   ```
   sc stop ServiceProtector
   ```

2. Remove the driver service:
   ```
   sc delete ServiceProtector
   ```

3. If installed via INF, uninstall with PnPUtil:
   ```
   pnputil /delete-driver ServiceProtector.inf /uninstall
   ```

## Advanced Configuration

### Customizing Protected Access Rights

By default, the driver blocks these access rights:
- PROCESS_TERMINATE
- PROCESS_VM_WRITE
- PROCESS_SUSPEND_RESUME

To customize these, you would need to modify the driver source code in the `PreOperationCallback` function and rebuild the driver.

### Using with Group Policy

For enterprise environments, you can deploy the ServiceProtector driver using Group Policy:

1. Create a Group Policy Object (GPO)
2. Configure the "Device Installation" settings
3. Add the ServiceProtector.inf to the approved drivers list
4. Configure registry settings to specify the service to protect

## Security Considerations

1. **Privilege Requirements**: The driver device object is restricted to administrators, but ensure that access to the control application is also restricted.

2. **Driver Signing**: For production use, the driver must be signed with a valid certificate from a trusted Certificate Authority.

3. **Limited Protection Scope**: Be aware that the driver cannot protect against attacks from kernel mode or from sufficiently privileged users.

4. **Testing Impact**: Thoroughly test the driver with your protected services to ensure it doesn't interfere with legitimate operations.

## Conclusion

The ServiceProtector driver provides an effective kernel-mode mechanism to protect critical Windows services from unauthorized termination or modification. When properly configured and deployed, it adds a valuable layer of security to your Windows systems.