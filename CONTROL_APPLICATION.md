# ServiceProtector Control Application

## Overview

This document provides a specification and sample implementation for a user-mode control application to configure the ServiceProtector driver. The control application allows administrators to change which Windows service is protected without having to modify registry settings or restart the system.

## Application Requirements

### Functionality

The control application should provide the following features:

1. Display the current protected service
2. Change the protected service to a different service
3. Display the status of the driver (running/stopped)
4. List available Windows services for selection
5. Show protection status and events (optional)

### Technical Requirements

1. Must run with administrative privileges
2. Must communicate with the driver using its IOCTL interface
3. Should include proper error handling and user feedback
4. Should verify driver is installed and running

## Implementation

### Code Sample: ServiceProtectorControl

Below is a complete C++ implementation of a command-line control application for the ServiceProtector driver:

```cpp
//
// ServiceProtectorControl.cpp
// Control application for ServiceProtector driver
//

#define _UNICODE
#define UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <strsafe.h>

// Must match the definition in the driver
#define IOCTL_SERVICE_PROTECTOR_SET_TARGET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAX_SERVICE_NAME_LENGTH 256

void PrintUsage()
{
    wprintf(L"ServiceProtector Control Application\n");
    wprintf(L"------------------------------------\n");
    wprintf(L"Usage:\n");
    wprintf(L"  ServiceProtectorControl.exe [command] [parameters]\n\n");
    wprintf(L"Commands:\n");
    wprintf(L"  status        - Display current driver status and protected service\n");
    wprintf(L"  protect [exe] - Set service executable to protect (e.g., 'spoolsv.exe')\n");
    wprintf(L"  list          - List available Windows services\n");
    wprintf(L"  help          - Display this help information\n\n");
    wprintf(L"Examples:\n");
    wprintf(L"  ServiceProtectorControl.exe status\n");
    wprintf(L"  ServiceProtectorControl.exe protect lsass.exe\n");
    wprintf(L"  ServiceProtectorControl.exe list\n");
}

BOOL IsDriverRunning()
{
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService = NULL;
    SERVICE_STATUS serviceStatus = {0};
    BOOL isRunning = FALSE;

    // Open the service control manager
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (schSCManager == NULL)
    {
        wprintf(L"Error: OpenSCManager failed (%d)\n", GetLastError());
        return FALSE;
    }

    // Open the service
    schService = OpenService(schSCManager, L"ServiceProtector", SERVICE_QUERY_STATUS);
    if (schService == NULL)
    {
        wprintf(L"Error: ServiceProtector driver is not installed (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return FALSE;
    }

    // Query the service status
    if (QueryServiceStatus(schService, &serviceStatus))
    {
        isRunning = (serviceStatus.dwCurrentState == SERVICE_RUNNING);
    }
    else
    {
        wprintf(L"Error: QueryServiceStatus failed (%d)\n", GetLastError());
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return isRunning;
}

BOOL StartDriverService()
{
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService = NULL;
    BOOL success = FALSE;

    // Open the service control manager
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (schSCManager == NULL)
    {
        wprintf(L"Error: OpenSCManager failed (%d)\n", GetLastError());
        return FALSE;
    }

    // Open the service
    schService = OpenService(schSCManager, L"ServiceProtector", SERVICE_START);
    if (schService == NULL)
    {
        wprintf(L"Error: OpenService failed (%d)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return FALSE;
    }

    // Start the service
    if (StartService(schService, 0, NULL))
    {
        wprintf(L"ServiceProtector driver service started successfully.\n");
        success = TRUE;
    }
    else
    {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING)
        {
            wprintf(L"ServiceProtector driver is already running.\n");
            success = TRUE;
        }
        else
        {
            wprintf(L"Error: StartService failed (%d)\n", error);
        }
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return success;
}

BOOL GetCurrentProtectedService(WCHAR* serviceName, DWORD bufferSize)
{
    HKEY hKey = NULL;
    DWORD dataSize = bufferSize * sizeof(WCHAR);
    LONG result;

    // Open the driver's parameters registry key
    result = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\ServiceProtector\\Parameters",
        0,
        KEY_READ,
        &hKey);

    if (result != ERROR_SUCCESS)
    {
        wprintf(L"Error: RegOpenKeyEx failed (%d)\n", result);
        return FALSE;
    }

    // Query the ServiceToProtect value
    result = RegQueryValueEx(
        hKey,
        L"ServiceToProtect",
        NULL,
        NULL,
        (LPBYTE)serviceName,
        &dataSize);

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS)
    {
        if (result == ERROR_FILE_NOT_FOUND)
        {
            wprintf(L"No service is currently configured for protection.\n");
            StringCchCopy(serviceName, bufferSize, L"");
            return TRUE;
        }
        else
        {
            wprintf(L"Error: RegQueryValueEx failed (%d)\n", result);
            return FALSE;
        }
    }

    return TRUE;
}

BOOL SetProtectedService(LPCWSTR serviceName)
{
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    BOOL success = FALSE;
    DWORD bytesReturned = 0;
    size_t nameLen = 0;

    // First check if the driver is running
    if (!IsDriverRunning())
    {
        wprintf(L"The ServiceProtector driver is not running. Attempting to start it...\n");
        if (!StartDriverService())
        {
            wprintf(L"Failed to start the driver service. Cannot set protected service.\n");
            return FALSE;
        }
    }

    // Validate service name length
    if (FAILED(StringCchLength(serviceName, MAX_SERVICE_NAME_LENGTH, &nameLen)))
    {
        wprintf(L"Error: Service name is too long.\n");
        return FALSE;
    }

    // Open the device
    hDevice = CreateFile(
        L"\\\\.\\ServiceProtector",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        wprintf(L"Error: Failed to open driver device. Error code: %d\n", GetLastError());
        wprintf(L"Make sure the ServiceProtector driver is installed and running.\n");
        return FALSE;
    }

    // Send the IOCTL to set the target service
    if (DeviceIoControl(
        hDevice,
        IOCTL_SERVICE_PROTECTOR_SET_TARGET,
        (LPVOID)serviceName,
        (DWORD)((nameLen + 1) * sizeof(WCHAR)), // Include null terminator
        NULL,
        0,
        &bytesReturned,
        NULL))
    {
        wprintf(L"Successfully set target service to: %s\n", serviceName);
        success = TRUE;

        // Also update the registry for persistence across reboots
        HKEY hKey = NULL;
        LONG result;

        // Open or create the driver's parameters registry key
        result = RegCreateKeyEx(
            HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\ServiceProtector\\Parameters",
            0,
            NULL,
            0,
            KEY_WRITE,
            NULL,
            &hKey,
            NULL);

        if (result == ERROR_SUCCESS)
        {
            // Set the ServiceToProtect value
            result = RegSetValueEx(
                hKey,
                L"ServiceToProtect",
                0,
                REG_SZ,
                (BYTE*)serviceName,
                (DWORD)((nameLen + 1) * sizeof(WCHAR)));

            if (result != ERROR_SUCCESS)
            {
                wprintf(L"Warning: Failed to update registry settings (%d).\n", result);
                wprintf(L"The configuration may not persist after a reboot.\n");
            }

            RegCloseKey(hKey);
        }
        else
        {
            wprintf(L"Warning: Failed to open registry key (%d).\n", result);
            wprintf(L"The configuration may not persist after a reboot.\n");
        }
    }
    else
    {
        wprintf(L"Error: Failed to set target service. Error code: %d\n", GetLastError());
    }

    CloseHandle(hDevice);
    return success;
}

BOOL ListWindowsServices()
{
    SC_HANDLE schSCManager = NULL;
    ENUM_SERVICE_STATUS* lpServices = NULL;
    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;
    BOOL success = FALSE;
    DWORD bufSize = 0;

    // Open the service control manager
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (schSCManager == NULL)
    {
        wprintf(L"Error: OpenSCManager failed (%d)\n", GetLastError());
        return FALSE;
    }

    // First call to get required buffer size
    EnumServicesStatus(
        schSCManager,
        SERVICE_WIN32,
        SERVICE_ACTIVE,
        NULL,
        0,
        &bytesNeeded,
        &servicesReturned,
        &resumeHandle);

    // Allocate memory for service list
    bufSize = bytesNeeded;
    lpServices = (ENUM_SERVICE_STATUS*)LocalAlloc(LMEM_FIXED, bufSize);
    if (lpServices == NULL)
    {
        wprintf(L"Error: Memory allocation failed\n");
        CloseServiceHandle(schSCManager);
        return FALSE;
    }

    // Get list of services
    if (EnumServicesStatus(
        schSCManager,
        SERVICE_WIN32,
        SERVICE_ACTIVE,
        lpServices,
        bufSize,
        &bytesNeeded,
        &servicesReturned,
        &resumeHandle))
    {
        // Display header
        wprintf(L"\n%-40s %-40s %-10s\n", L"SERVICE NAME", L"DISPLAY NAME", L"STATUS");
        wprintf(L"------------------------------------------------------------------------------\n");

        // Display each service
        for (DWORD i = 0; i < servicesReturned; i++)
        {
            LPWSTR statusStr = L"";
            switch (lpServices[i].ServiceStatus.dwCurrentState)
            {
            case SERVICE_RUNNING:
                statusStr = L"Running";
                break;
            case SERVICE_STOPPED:
                statusStr = L"Stopped";
                break;
            case SERVICE_PAUSED:
                statusStr = L"Paused";
                break;
            case SERVICE_START_PENDING:
                statusStr = L"Starting";
                break;
            case SERVICE_STOP_PENDING:
                statusStr = L"Stopping";
                break;
            default:
                statusStr = L"Unknown";
                break;
            }

            // Note: This doesn't show the executable name, just the service name
            wprintf(L"%-40s %-40s %-10s\n",
                lpServices[i].lpServiceName,
                lpServices[i].lpDisplayName,
                statusStr);
        }

        wprintf(L"\n");
        wprintf(L"Note: To protect a service, you need to know its executable name (e.g., spoolsv.exe).\n");
        wprintf(L"You can find this in the service properties in the Services Management Console.\n");
        success = TRUE;
    }
    else
    {
        wprintf(L"Error: EnumServicesStatus failed (%d)\n", GetLastError());
    }

    LocalFree(lpServices);
    CloseServiceHandle(schSCManager);
    return success;
}

BOOL DisplayStatus()
{
    WCHAR serviceName[MAX_SERVICE_NAME_LENGTH] = {0};
    BOOL driverRunning = IsDriverRunning();

    wprintf(L"\nServiceProtector Status\n");
    wprintf(L"----------------------\n");
    wprintf(L"Driver Status: %s\n", driverRunning ? L"Running" : L"Not Running");

    if (driverRunning)
    {
        if (GetCurrentProtectedService(serviceName, MAX_SERVICE_NAME_LENGTH))
        {
            if (serviceName[0] != L'\0')
            {
                wprintf(L"Protected Service: %s\n", serviceName);
            }
            else
            {
                wprintf(L"No service is currently configured for protection.\n");
            }
        }
        else
        {
            wprintf(L"Failed to retrieve current protected service information.\n");
        }
    }
    else
    {
        wprintf(L"Driver is not running. Cannot retrieve protected service information.\n");
    }

    return TRUE;
}

int wmain(int argc, wchar_t* argv[])
{
    // Check for administrator privileges
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = NULL;
    
    if (AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    if (!isAdmin)
    {
        wprintf(L"Error: This application requires administrator privileges.\n");
        wprintf(L"Please run as administrator.\n");
        return 1;
    }

    // Parse command line
    if (argc < 2)
    {
        PrintUsage();
        return 1;
    }

    if (_wcsicmp(argv[1], L"help") == 0)
    {
        PrintUsage();
        return 0;
    }
    else if (_wcsicmp(argv[1], L"status") == 0)
    {
        return DisplayStatus() ? 0 : 1;
    }
    else if (_wcsicmp(argv[1], L"list") == 0)
    {
        return ListWindowsServices() ? 0 : 1;
    }
    else if (_wcsicmp(argv[1], L"protect") == 0)
    {
        if (argc < 3)
        {
            wprintf(L"Error: Missing service executable name.\n");
            PrintUsage();
            return 1;
        }
        return SetProtectedService(argv[2]) ? 0 : 1;
    }
    else
    {
        wprintf(L"Error: Unknown command: %s\n", argv[1]);
        PrintUsage();
        return 1;
    }
}
```

### Building the Control Application

The application can be built using Visual Studio or the command line:

1. **Using Visual Studio:**
   - Create a new C++ Console Application project
   - Add the ServiceProtectorControl.cpp file to the project
   - Build the solution

2. **Using Command Line:**
   ```
   cl /EHsc /W4 /DUNICODE /D_UNICODE ServiceProtectorControl.cpp /link /out:ServiceProtectorControl.exe advapi32.lib
   ```

## Using the Control Application

### Command Examples

1. **View Driver Status:**
   ```
   ServiceProtectorControl.exe status
   ```
   Displays whether the driver is running and which service is being protected.

2. **List Available Services:**
   ```
   ServiceProtectorControl.exe list
   ```
   Shows a list of all active Windows services.

3. **Set Protected Service:**
   ```
   ServiceProtectorControl.exe protect spoolsv.exe
   ```
   Configures the driver to protect the Print Spooler service.

### Sample Output

```
ServiceProtector Status
----------------------
Driver Status: Running
Protected Service: spoolsv.exe
```

## Security Considerations

1. **User Privileges**
   - The control application requires administrator privileges
   - It verifies administrator status at runtime
   - Access to the driver device should be restricted in the driver

2. **Input Validation**
   - The application validates service name length
   - Additional validation could be added for service existence

3. **Configuration Persistence**
   - The application updates both the driver and registry settings
   - This ensures the configuration persists across reboots

## Extension Points

The control application could be extended with these additional features:

1. **GUI Interface**
   - Create a graphical interface for easier use
   - Include service selection from a dropdown menu
   - Show real-time protection events

2. **Advanced Configuration**
   - Allow configuring which access rights to block
   - Support protecting multiple services
   - Include whitelist functionality for trusted processes

3. **Monitoring Features**
   - Add a log viewer for protection events
   - Include statistics on blocked access attempts
   - Provide alerts for protection events

## Conclusion

This control application provides a straightforward way to configure the ServiceProtector driver without directly manipulating registry settings. The implementation is robust, handles errors properly, and provides clear feedback to the user.

For production use, consider adding more validation, enhanced logging, and potentially a graphical user interface for easier use by system administrators.