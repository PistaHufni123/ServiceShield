# ServiceProtector Driver Development Guide

## Overview

This document provides detailed instructions for setting up a development environment for the ServiceProtector Windows kernel-mode driver project. The ServiceProtector driver is designed to protect specific Windows services by preventing unauthorized process termination or modification.

## Development Environment Requirements

### Hardware Requirements
- Computer with virtualization support (for testing in virtual machines)
- 8GB RAM minimum (16GB or more recommended)
- 50GB+ available disk space

### Software Requirements
1. **Windows 10/11 64-bit** (Professional, Enterprise, or Education edition recommended)
2. **Visual Studio**
   - Visual Studio 2019 or newer (2022 recommended)
   - Workloads: "Desktop development with C++" and "Windows Driver Kit"
3. **Windows Driver Kit (WDK)**
   - Must match your Visual Studio version
4. **Windows SDK**
   - Must match your WDK version
5. **Debugging Tools for Windows**
   - Included in WDK installation

## Setup Instructions

### 1. Install Visual Studio

1. Download Visual Studio from [Visual Studio Downloads](https://visualstudio.microsoft.com/downloads/)
2. Run the installer
3. Select the following workloads:
   - Desktop development with C++
   - Universal Windows Platform development
4. Under "Individual components", select:
   - MSVC C++ x64/x86 build tools
   - Windows 10/11 SDK
5. Complete the installation

### 2. Install Windows Driver Kit (WDK)

1. Visit the [WDK download page](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
2. Download the WDK installer matching your Visual Studio version
3. Run the WDK installer
4. Ensure "Windows Driver Kit" is selected
5. Complete the installation
6. If prompted, also install the "WDK Visual Studio Extension"

### 3. Configure Test Signing for Driver Development

To test unsigned drivers during development:

1. Open an Administrator Command Prompt
2. Enable test signing mode:
   ```
   bcdedit /set testsigning on
   ```
3. Restart your computer

### 4. Set Up a Test Environment (Recommended)

It's highly recommended to test kernel drivers in a virtual machine to avoid system instability on your development machine.

#### Option 1: Hyper-V (Windows 10/11 Pro, Enterprise, or Education)

1. Enable Hyper-V:
   - Open "Control Panel" > "Programs" > "Programs and Features" > "Turn Windows features on or off"
   - Check "Hyper-V" and click OK
   - Restart when prompted

2. Create a virtual machine:
   - Open Hyper-V Manager
   - Click "New" > "Virtual Machine"
   - Follow the wizard to create a VM with at least 4GB RAM and 60GB disk
   - Install Windows 10/11 on the VM
   - Install Visual Studio and WDK on the VM for debugging

#### Option 2: VMware Workstation/VirtualBox

1. Install VMware Workstation/Player or VirtualBox
2. Create a new VM with at least 4GB RAM and 60GB disk
3. Install Windows 10/11
4. Configure the VM for kernel debugging (instructions below)

### 5. Configure Kernel Debugging

#### On the Target (Test) Machine:

1. Open an Administrator Command Prompt
2. Enable kernel debugging:
   ```
   bcdedit /debug on
   bcdedit /dbgsettings net hostip:x.x.x.x port:50000
   ```
   Replace x.x.x.x with the IP address of your host machine
3. Restart the target machine

#### On the Host (Development) Machine:

1. Open WinDbg from the WDK installation
2. Configure the debugger connection:
   - Select "File" > "Kernel Debug"
   - Choose "Net" tab
   - Enter the port number (50000) and key from the target machine
   - Click "OK"

## Building the ServiceProtector Driver

1. Open Visual Studio as Administrator
2. Open the ServiceProtector.vcxproj project file
3. Select the appropriate configuration (Debug/Release) and platform (x64)
4. Build the solution (F7 or Build > Build Solution)

## Deploying the Driver for Testing

### Manual Deployment

1. Generate the catalog file for the driver package:
   ```
   Inf2Cat.exe /driver:path_to_driver_folder /os:10_X64,10_X86
   ```

2. Sign the catalog file (for testing):
   ```
   SignTool.exe sign /fd SHA256 /f test_certificate.pfx /p password ServiceProtector.cat
   ```

3. Copy the built driver (.sys file) to the test machine
4. Copy the ServiceProtector.inf and ServiceProtector.cat files to the test machine
5. On the test machine, open an Administrator Command Prompt
6. Navigate to the directory containing the files
7. Install the driver:
   ```
   pnputil /add-driver ServiceProtector.inf /install
   ```

**Important Notes on Catalog Files:**
- The catalog file (ServiceProtector.cat) contains digital signatures that Windows uses to verify driver integrity
- Do NOT list the .cat file in [SourceDisksFiles] sections of the INF file
- Do NOT list the .cat file in [YourDriver_CopyFiles] sections of the INF file
- Only reference the catalog file in the [Version] section via the CatalogFile entry
- The catalog file should be present in the same directory as the INF file during installation

### Using Visual Studio Deployment

1. Right-click the project in Solution Explorer
2. Select "Properties"
3. Navigate to "Driver" > "Deployment"
4. Configure the target computer information
5. Choose "Install and Verify"
6. Click "Apply" and "OK"
7. Right-click the project and select "Deploy Solution"

## Testing the Driver

1. After deployment, the driver should be loaded automatically
2. To verify the driver is loaded, run in an Administrator Command Prompt:
   ```
   sc query ServiceProtector
   ```
3. To test protection, attempt to terminate the protected service (default is spoolsv.exe) using Task Manager or Process Explorer
4. Verify that termination attempts are blocked

## Debugging the Driver

1. Connect WinDbg to the target machine as described above
2. Set breakpoints as needed:
   ```
   bp ServiceProtector!PreOperationCallback
   bp ServiceProtector!ProcessNotifyCallback
   ```
3. Trigger the driver by attempting operations on the protected service
4. Examine the call stack and variables in WinDbg

## Driver Signing for Production

For production deployment, the driver must be signed with a valid certificate using SHA256 digest algorithms:

1. Generate a catalog file for the driver package:
   ```
   Inf2Cat.exe /driver:path_to_driver_folder /os:10_X64,10_X86,Server10_X64
   ```

2. Ensure the INF file includes a proper CatalogFile entry:
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

3. Use architecture-specific Source Disk sections in the INF:
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

4. Obtain an EV Code Signing Certificate from a trusted CA

5. Sign the catalog file using the SHA256 digest algorithm:
   ```
   signtool sign /fd SHA256 /v /ac "EVCertCA.cer" /n "Your Company Name" /t http://timestamp.digicert.com ServiceProtector.cat
   ```

6. For additional security, also sign the driver file itself:
   ```
   signtool sign /fd SHA256 /v /ac "EVCertCA.cer" /n "Your Company Name" /t http://timestamp.digicert.com ServiceProtector.sys
   ```

7. Submit the driver to the Windows Hardware Developer Center for WHQL certification (recommended for wide distribution)

Note: Windows 10 and newer require SHA256 for driver signing. SHA1 is no longer accepted for driver signatures in modern Windows versions.

## Troubleshooting

### Common Issues

1. **Build Errors**
   - Ensure WDK and Visual Studio versions are compatible
   - Check that all required components are installed

2. **Driver Loading Fails**
   - Verify test signing is enabled
   - Check system event logs for specific errors
   - Use `driverquery` command to list installed drivers

3. **Debugging Connection Issues**
   - Verify firewall settings allow debugging traffic
   - Check IP configurations on both machines
   - Ensure kernel debugging is properly enabled

4. **Protection Not Working**
   - Use DbgPrint messages to trace execution (viewable in DebugView or WinDbg)
   - Verify the correct service name is configured
   - Check process ID detection logic in `ProcessNotifyCallback`

## Additional Resources

- [Windows Driver Kit Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [Kernel-Mode Driver Framework Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/wdf/kernel-mode-driver-framework)
- [Windows Driver Samples on GitHub](https://github.com/Microsoft/Windows-driver-samples)
- [Windows Internals Book](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals)