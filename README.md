# ServiceProtector Driver

A Windows kernel-mode driver using KMDF that protects a specific Windows service by preventing unauthorized termination or modification.

## Overview

The ServiceProtector driver is designed to protect critical Windows services from being tampered with or terminated by unauthorized processes. It operates by intercepting handle creation requests to the protected service's process and filtering out access rights that could be used to harm the service.

## Key Features

- Prevents unauthorized termination of protected Windows services
- Blocks memory modification attempts (to prevent code injection)
- Prevents process suspension
- Configurable via IOCTL interface
- Monitors process creation to automatically identify and protect the target service process

## Technical Implementation

- Windows Kernel-Mode Driver using KMDF framework
- Uses ObRegisterCallbacks to filter process handle creation
- Uses PsSetCreateProcessNotifyRoutineEx to monitor process creation
- Thread-safe design with proper synchronization

## Documentation

Detailed documentation is available in the following files:

- [Setup Guide](SETUP_GUIDE.md) - Instructions for setting up the development environment
- [Architecture Overview](ARCHITECTURE.md) - Technical details about the driver design and implementation
- [Usage Guide](USAGE_GUIDE.md) - How to install, configure, and use the driver

## Requirements

### Development Requirements

- Windows 10/11 64-bit (Professional, Enterprise, or Education edition)
- Visual Studio 2019 or newer with "Desktop development with C++" workload
- Windows Driver Kit (WDK) matching your Visual Studio version
- Windows SDK

### Runtime Requirements

- Windows 10/11 64-bit
- Administrator privileges for driver installation
- Test signing mode enabled (for development) or properly signed driver (for production)

## Building the Driver

The driver can be built using Visual Studio with the WDK installed:

1. Open the `ServiceProtector.vcxproj` file in Visual Studio
2. Select the desired configuration (Debug/Release) and platform (x64)
3. Build the solution

Note: This project is a Windows kernel driver that requires the Windows Driver Kit (WDK) to properly build. The Replit environment doesn't support full Windows driver compilation, but the code can be reviewed and analyzed here.

## Default Configuration

By default, the driver is configured to protect the Windows Print Spooler service (spoolsv.exe), as specified in the INF file. This can be customized through registry settings or using a control application.

## Security Considerations

- The driver operates in kernel mode and must be thoroughly tested in a development environment before deployment
- For production use, the driver should be properly signed with a trusted certificate
- The protection mechanism is designed to block user-mode attacks and is not effective against kernel-mode attacks

## License

This project is provided as a learning resource and security tool. Use at your own risk and in compliance with all applicable laws and regulations.

## Disclaimer

Kernel-mode drivers can cause system instability if not properly implemented or tested. Always develop and test drivers in a sandboxed environment such as a virtual machine.