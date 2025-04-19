# ServiceProtector Driver Troubleshooting Guide

This document provides solutions for common issues you might encounter when developing, building, or installing the ServiceProtector driver.

## Compilation Errors

### Missing PPS_CREATE_NOTIFY_INFO Type Definition

**Error:**
```
Error (active) E0020 identifier "PPS_CREATE_NOTIFY_INFO" is undefined
```

**Solution:**
This error occurs because the PPS_CREATE_NOTIFY_INFO structure might not be defined in all WDK versions. To fix this issue:

1. Add a custom definition for the PS_CREATE_NOTIFY_INFO structure in your header file:

```c
// Add to ServiceProtector.h
// Fix for PPS_CREATE_NOTIFY_INFO definition (required for PsSetCreateProcessNotifyRoutineEx)
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
```

2. Ensure proper header inclusion order:
   - Include ntddk.h before any other headers
   - Avoid mixing user-mode and kernel-mode headers
   - Use conditional compilation if needed

3. Verify the WDK documentation for your specific WDK version to ensure the structure matches the expected layout for your target Windows version.

### Missing WdfDriverGetDevice and RtlUnicodeStringEndsWithString Functions

**Error:**
```
Error LNK2019 unresolved external symbol WdfDriverGetDevice referenced in function ProcessNotifyCallback
Error LNK2019 unresolved external symbol __imp_RtlUnicodeStringEndsWithString referenced in function ProcessNotifyCallback
```

**Solution:**
These errors occur when certain WDF functions or string utility functions are not properly linked into the driver. There are two approaches to fix this issue:

1. **Global Device Reference Approach (Recommended):**
   - Declare a global WDFDEVICE variable to store the device handle
   - Initialize it in DriverEntry after device creation
   - Use this global variable instead of WdfDriverGetDevice calls
   
   ```c
   // At the top of your ServiceProtector.c file (after includes):
   WDFDEVICE g_Device = NULL;
   
   // In DriverEntry, after WdfDeviceCreate:
   g_Device = device;
   
   // Instead of using WdfDriverGetDevice:
   device = g_Device;
   ```

2. **Custom String Comparison Implementation:**
   - For RtlUnicodeStringEndsWithString issues, implement your own string comparison function
   - Use RtlUpcaseUnicodeChar for proper case-insensitive comparison
   
   ```c
   // Instead of RtlUnicodeStringEndsWithString, use:
   BOOLEAN nameMatches = FALSE;
   if (processName.Length >= targetServiceName.Length) {
       PCWSTR processSuffix = (PCWSTR)((PCHAR)processName.Buffer + 
           (processName.Length - targetServiceName.Length));
       
       // Compare with case insensitivity using RtlUpcaseUnicodeChar
       // (See implementation in ServiceProtector.c)
   }
   ```

3. **Project Configuration Fix:**
   - Add <DriverSign> configuration with SHA256 as the file digest algorithm:
   
   ```xml
   <DriverSign>
     <FileDigestAlgorithm>sha256</FileDigestAlgorithm>
   </DriverSign>
   ```

### Header File Not Found: wdfldr.h

**Error:**
```
Error C1083 Cannot open include file: 'wdfldr.h': No such file or directory
```

**Solution:**
This error occurs when attempting to include headers that may not be available in all WDK configurations. To fix this:

1. **Remove the dependency:**
   - Replace direct WDF loader function calls with alternative implementations
   - Use global device references instead of WdfDriverGetDevice
   - Avoid the need to include wdfldr.h entirely

2. **Fix include paths:**
   - Ensure proper WDK include paths are set in project properties
   - If a specific header is truly needed, check the WDK install location

### Missing Process Access Rights Definitions

**Error:**
```
Error (active) E0020 identifier "PROCESS_VM_WRITE" is undefined
Error (active) E0020 identifier "PROCESS_TERMINATE" is undefined
Error (active) E0020 identifier "PROCESS_SUSPEND_RESUME" is undefined
```

**Solution:**
These errors occur because the Windows process access rights constants are not automatically defined in all kernel-mode header files. To fix:

1. Include the appropriate header or manually define these constants in your header file:

```c
// Add to ServiceProtector.h
#include <winnt.h>

// Or manually define if the include doesn't resolve the issue
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                  (0x0001)
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE                   (0x0020)
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME             (0x0800)
#endif
```

### INF File Architecture Decoration Errors

**Error:**
```
Error 1423 Primitive drivers require an architecture-decorated [DefaultInstall] section.
Error 1420 [DefaultInstall]-based INF cannot be processed as Primitive.
Error 1421 Section [DefaultInstall] missing an architecture decoration.
```

**Solution:**
These errors occur because modern Windows driver INF files require specific architecture decorations. To fix:

1. Change `[DefaultInstall]` to `[DefaultInstall.NTamd64]` for 64-bit drivers
2. Change `[DefaultInstall.Services]` to `[DefaultInstall.NTamd64.Services]`
3. Add equivalent sections for x86 if needed: `[DefaultInstall.NTx86]` and `[DefaultInstall.NTx86.Services]`

Example:
```
[DefaultInstall.NTamd64]
CopyFiles=ServiceProtector_CopyFiles

[DefaultInstall.NTamd64.Services]
AddService=%ServiceName%,0x00000800,ServiceProtector_Service_Inst
```

### WPP Tracing Errors

**Error:**
```
Error wpp Unable to open file 'trace.h': CreateFile error 2.
Error wpp Fatal: CreateFile
```

**Solution:**
These errors occur because the Windows Software Tracing Preprocessor (WPP) is looking for a missing file called trace.h. To fix:

1. **Option 1 - Create the trace.h file:**
   - Create a new file called `trace.h` in the project directory
   - Add the required WPP tracing definitions to the file
   - Include the file in your driver source files

   Example trace.h:
   ```c
   #pragma once

   // Define the tracing flags
   #define WPP_CONTROL_GUIDS \
       WPP_DEFINE_CONTROL_GUID( \
           ServiceProtectorTraceGuid, (2b5e7e47,3936,4f31,b7e3,f58fa344f84c), \
           WPP_DEFINE_BIT(TRACE_FLAG_GENERAL) \
           WPP_DEFINE_BIT(TRACE_FLAG_PROTECTION) \
       )

   // Define the tracing functions
   // begin_wpp config
   // FUNC Trace{FLAG=TRACE_FLAG_GENERAL}(LEVEL, MSG, ...);
   // end_wpp
   ```

2. **Option 2 - Disable WPP Tracing:**
   - Open the project file (ServiceProtector.vcxproj)
   - Set `WppEnabled` and `WppRecorderEnabled` to `false` for both Debug and Release configurations
   - If you're not using WPP tracing, this is the simpler solution

3. **Additional Step - Update Source Files:**
   - If using WPP tracing, add WPP initialization/cleanup to your driver
   - In the driver entry point: `WPP_INIT_TRACING(DriverObject, RegistryPath);`
   - In the driver unload routine: `WPP_CLEANUP(WdfDriverWdmGetDriverObject(Driver));`
   - Include the generated TMH file: `#include "ServiceProtector.tmh"`
   - Conditionally include the TMH file: `#ifdef WPP_ENABLED #include "ServiceProtector.tmh" #endif`

### Windows Type Definition Errors

**Error:**
```
Error (active) E0020 identifier "WORD" is undefined
Error (active) E0020 identifier "DWORD" is undefined
Error (active) E0020 identifier "BYTE" is undefined
```

**Solution:**
These errors occur because Windows kernel-mode drivers require specific header files and include order to properly define base Windows types.

1. **Fix Header Include Order:**
   - Kernel-mode drivers need the correct include order for Windows types to be defined properly
   - Update your headers as follows:

   ```c
   // Define Windows version targets for kernel-mode driver
   #define NTDDI_VERSION NTDDI_WIN10_RS1
   #define _WIN32_WINNT 0x0A00  // Windows 10
   
   // Include order is important for kernel-mode drivers
   #include <ntdef.h>      // Basic NT definitions
   #include <wdm.h>        // Windows Driver Model
   #include <ntddk.h>      // NT Driver Development Kit
   #include <wdf.h>        // Windows Driver Framework
   ```

2. **Add Architecture Definitions:**
   - Some headers need architecture information to properly define types
   - Add the following before your includes:

   ```c
   // Define architecture (choose the appropriate one)
   #define _X86_       // For 32-bit x86
   // OR
   #define _AMD64_     // For 64-bit x64
   ```

3. **Fix Project Configuration:**
   - Update preprocessor definitions in the project file to include:
   ```
   _WIN64;_AMD64_;AMD64;NTDDI_VERSION=NTDDI_WIN10_RS1;_WIN32_WINNT=0x0A00
   ```
   - Add the kernel libraries to link against:
   ```
   $(DDK_LIB_PATH)\ntoskrnl.lib;$(DDK_LIB_PATH)\hal.lib;$(DDK_LIB_PATH)\wmilib.lib
   ```
   - Set `EntryPointSymbol` to `DriverEntry`
   - Add the WDK include paths: `$(DDK_INC_PATH)`

### Missing PPS_CREATE_NOTIFY_INFO Definition

**Error:**
```
Error (active) E0020 identifier "PPS_CREATE_NOTIFY_INFO" is undefined
```

**Solution:**
This error occurs because the PS_CREATE_NOTIFY_INFO structure and its pointer type are not defined in older WDK versions or might be missing in some headers.

1. **Define the Structure:**
   - Add the definition to your header file:

   ```c
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
   #endif
   ```

2. **Target Specific Windows Version:**
   - Ensure you're targeting a Windows version that supports this feature:
   ```c
   #define NTDDI_VERSION NTDDI_WIN10_RS1
   #define _WIN32_WINNT 0x0A00  // Windows 10
   ```

3. **Check Function Declaration:**
   - Make sure your function prototype matches the exact required signature:
   ```c
   VOID ProcessNotifyCallback(
       _In_ PEPROCESS Process,
       _In_ HANDLE ProcessId,
       _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
   );
   ```

## Runtime Errors

### Blue Screen of Death (BSOD) Issues

**Symptoms:**
- Computer crashes with a blue screen when the driver is loaded
- BSOD shows error codes like DRIVER_IRQL_NOT_LESS_OR_EQUAL, DRIVER_FAULT, or SYSTEM_SERVICE_EXCEPTION
- System event log shows crashes in ServiceProtector.sys

**Solutions:**

1. **Buffer handling improvements:**
   - Add proper NULL pointer checks throughout the code
   - Implement bounds checking for all array and buffer operations
   - Add try/except blocks around memory access operations
   - Always initialize variables to safe default values

   Example for string buffer processing:
   ```c
   // Zero out the buffer first
   RtlZeroMemory(buffer, bufferSize);
   
   // Validate the buffer before access
   if (buffer == NULL || bufferSize < sizeof(WCHAR)) {
       return STATUS_INVALID_PARAMETER;
   }
   
   // Always ensure NULL termination
   buffer[bufferSize/sizeof(WCHAR) - 1] = L'\0';
   ```

2. **Proper exception handling:**
   - Use structured exception handling (__try/__except/__finally) around critical code
   - Always release resources in __finally blocks
   - Use a mutex tracking variable to ensure proper cleanup
   
   Example for mutex handling:
   ```c
   BOOLEAN mutexAcquired = FALSE;
   
   __try {
       ExAcquireFastMutex(&mutex);
       mutexAcquired = TRUE;
       
       // Critical section code...
   }
   __finally {
       if (mutexAcquired) {
           ExReleaseFastMutex(&mutex);
       }
   }
   ```

3. **Reliable global device reference:**
   - Add proper validation of the global device reference
   - Use interlocked operations for setting/clearing the reference
   - Add additional NULL checks before dereferencing

4. **Debugging technique for BSOD:**
   - Enable Driver Verifier for detailed error checking
   - Use kernel debugger to analyze crash dumps
   - Set up a kernel-mode debugging session on a test machine
   - Use WPP tracing to log detailed operations before crash

### Driver Fails to Load

**Symptoms:**
- Driver service fails to start
- Error: "The system cannot find the file specified"
- Error: "The service did not start due to a logon failure"

**Solutions:**

1. Verify the service binary path is correct:
   - Check the registry: `HKLM\SYSTEM\CurrentControlSet\Services\ServiceProtector\ImagePath`
   - Ensure the .sys file exists at the specified location

2. Check driver signing:
   - For development/testing, ensure test signing is enabled:
     ```
     bcdedit /set testsigning on
     ```
   - For production, ensure the driver is properly signed with a trusted certificate

3. Check for dependencies:
   - Some drivers depend on other drivers or services
   - Check the event logs for specific error messages

### Driver Loads But Protection Doesn't Work

**Symptoms:**
- Driver loads successfully
- Protected service can still be terminated
- No protection events are logged

**Solutions:**

1. Verify the correct service is configured:
   - Check the registry: `HKLM\SYSTEM\CurrentControlSet\Services\ServiceProtector\Parameters\ServiceToProtect`
   - Use the control application to set the correct service executable name

2. Check process monitoring:
   - Add additional debug prints to `ProcessNotifyCallback` function
   - Verify the service process is correctly identified

3. Check object callbacks:
   - Add debug prints to `PreOperationCallback` function
   - Verify the callback is being called when handle requests are made
   - Check that access rights are being properly filtered

## Installation Issues

### INF Installation Fails

**Symptoms:**
- "Driver not installed" error during installation
- Error in the setup log related to the INF file
- "The third-party INF does not contain digital signature information" error
- "Cannot list CAT files under [SourceDisksFiles]" error

**Solutions:**

1. Verify INF file syntax:
   - Check for proper section names and architecture decoration
   - Validate all referenced files exist
   - Use the INF Verification Utility (InfVerif.exe) from the WDK

2. Add proper catalog file reference:
   ```
   [Version]
   Signature="$WINDOWS NT$"
   Class=System
   ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}
   Provider=%ManufacturerName%
   DriverVer=01/01/2023,1.0.0.1
   CatalogFile=ServiceProtector.cat
   PnpLockdown=1
   ```

3. Use architecture-specific source disk sections:
   ```
   [SourceDisksNames.amd64]
   1 = %DiskName%,,,""

   [SourceDisksFiles.amd64]
   ServiceProtector.sys = 1,,

   [SourceDisksNames.x86]
   1 = %DiskName%,,,""

   [SourceDisksFiles.x86]
   ServiceProtector.sys = 1,,
   ```

4. **IMPORTANT: Don't list catalog files in INF file source sections**:
   - CAT files should *not* be listed in [SourceDisksFiles] sections
   - CAT files should *not* be listed in [YourDriver_CopyFiles] sections
   - Catalog files are automatically handled by the installation process
   - Only reference catalog files in the [Version] section via CatalogFile entry

5. Generate a catalog file:
   - Run `Inf2Cat.exe /driver:path_to_driver_folder /os:10_X64` to generate a catalog file
   - Sign the catalog file using `SignTool.exe sign /fd SHA256 /f certificate.pfx /p password ServiceProtector.cat`

6. Check driver signing requirements:
   - Windows 10+ requires drivers to be signed for installation
   - For development, use test signing mode with `bcdedit /set testsigning on`
   - For production, obtain proper EV certificate and WHQL certification

### Access Denied During Installation

**Symptoms:**
- "Access denied" error during driver installation
- "The installation failed" message with permission errors

**Solutions:**

1. Run the installation with administrator privileges:
   - Right-click the installer and select "Run as administrator"
   - Use an elevated command prompt for manual installation

2. Check file system permissions:
   - Ensure you have write access to the system directories
   - Check for any file locks by other processes

## Debugging Techniques

### Using Debug Print Statements

Add debug print statements to trace the execution path:

```c
SERVICE_PROTECTOR_PRINT("ProcessNotifyCallback called for PID: %lu", HandleToULong(ProcessId));
```

View these prints using:
- DebugView (SysInternals tool)
- Kernel debugger (WinDbg) with `!dbgprint` command

### Using WinDbg Kernel Debugger

1. Set up kernel debugging between two machines or using a virtual machine
2. Set breakpoints at key functions:
   ```
   bp ServiceProtector!PreOperationCallback
   bp ServiceProtector!ProcessNotifyCallback
   ```
3. Use data inspection commands to examine variables:
   ```
   dt ServiceProtector!_DEVICE_CONTEXT <address>
   ```

### Using Driver Verifier

Enable Driver Verifier to catch common driver issues:

1. Open Command Prompt as Administrator
2. Run: `verifier /standard /driver ServiceProtector.sys`
3. Restart the system
4. If crashes occur, analyze the crash dump with WinDbg

## Performance Issues

### System Slowdown with Driver Loaded

**Symptoms:**
- System performance degrades after driver installation
- High CPU usage when the driver is running

**Solutions:**

1. Check for excessive logging:
   - Reduce debug prints in production builds
   - Use conditional compilation for debug functionality

2. Optimize callback filtering:
   - Add early-exit conditions to avoid unnecessary processing
   - Use more specific object type filtering

3. Check for synchronization issues:
   - Ensure mutexes are not held for long periods
   - Avoid excessive locking and unlocking operations

## Common Error Codes

| Error Code | Description | Common Cause |
|------------|-------------|--------------|
| 0xC0000022 | STATUS_ACCESS_DENIED | Insufficient privileges or driver is not properly signed |
| 0xC0000035 | STATUS_OBJECT_NAME_COLLISION | A device with the same name already exists |
| 0xC0000225 | STATUS_NOT_FOUND | Driver file not found at the specified location |
| 0xC000003A | STATUS_OBJECT_PATH_NOT_FOUND | The specified path to the driver does not exist |
| 0xC0000428 | STATUS_DRIVER_FAILED_PRIOR_UNLOAD | Previous instance of the driver failed to unload properly |

## Additional Resources

- [Windows Driver Kit Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [Debugging Tools for Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/)
- [Windows INF File Reference](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/inf-file-reference)
- [Driver Signing Requirements](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy)