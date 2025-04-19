# ServiceProtector Driver Testing Guide

## Overview

This document provides comprehensive guidance for testing the ServiceProtector Windows kernel-mode driver. Testing a kernel driver requires careful planning and execution due to the potential for system instability if issues occur. This guide covers functional testing, stress testing, and debugging techniques.

## Test Environment Setup

### Recommended Test Environment

1. **Virtual Machine Setup**
   - Use a virtual machine for all testing to prevent affecting your primary system
   - Recommended platforms: VMware Workstation, VirtualBox, or Hyper-V
   - Take snapshots before driver installation to allow easy recovery

2. **Test System Configuration**
   - Windows 10/11 64-bit installation (preferably the same version as target systems)
   - Minimum 4GB RAM, 2 CPU cores
   - Enable kernel debugging
   - Enable test signing mode:
     ```
     bcdedit /set testsigning on
     ```

3. **Debugging Tools Installation**
   - Install Debugging Tools for Windows (part of the WDK)
   - Configure WinDbg or KD for kernel debugging
   - Set up kernel debugging between host and test VM

## Functional Testing

### Basic Driver Functionality

1. **Driver Installation Test**
   - Install the driver using the INF file
   - Verify the service is created in the Services control panel
   - Check for any errors in the System Event Log
   - Verify driver files are correctly placed in System32\drivers

2. **Driver Loading Test**
   - Start the driver service:
     ```
     sc start ServiceProtector
     ```
   - Verify the driver loads without errors
   - Check System Event Log for successful initialization

3. **Device Interface Test**
   - Verify the device interface is created:
     ```
     findstr /s ServiceProtector *
     ```
   - Attempt to open the device with a simple test application

### Protection Mechanism Tests

1. **Service Protection Test**
   - Start the target Windows service (e.g., Print Spooler)
   - Verify the ServiceProtector driver identifies the process
   - Use Task Manager to attempt terminating the service process
   - Verify the termination is blocked
   - Check for appropriate log messages

2. **Termination Protection Test**
   - Write a test program that attempts to terminate the protected process:
     ```c
     HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, targetPID);
     TerminateProcess(hProcess, 1);
     ```
   - Verify that the operation fails with "Access Denied" or similar error
   - Test both as a standard user and as administrator

3. **Memory Write Protection Test**
   - Write a test program that attempts memory modification:
     ```c
     HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE, FALSE, targetPID);
     WriteProcessMemory(hProcess, targetAddress, data, dataSize, NULL);
     ```
   - Verify that the operation fails with "Access Denied" or similar error
   - Verify that the program does get PROCESS_VM_READ access successfully

4. **Process Suspension Test**
   - Write a test program that attempts to suspend the process:
     ```c
     HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, targetPID);
     NtSuspendProcess(hProcess);
     ```
   - Verify that the operation fails with "Access Denied" or similar error

### Configuration Tests

1. **IOCTL Interface Test**
   - Write a test program that sends the IOCTL_SERVICE_PROTECTOR_SET_TARGET IOCTL
   - Test with valid service names of different lengths
   - Test with invalid or extremely long service names
   - Verify proper error handling

2. **Service Targeting Test**
   - Configure the driver to protect a different service
   - Verify the driver correctly identifies the new target
   - Verify protection works for the new target
   - Verify the previous target is no longer protected

3. **Startup Configuration Test**
   - Modify the registry configuration for service targeting
   - Restart the driver and verify it picks up the new configuration
   - Test with both valid and invalid configurations

## Stress Testing

### Load Tests

1. **Multiple Access Attempts**
   - Create a program that rapidly opens and closes handles to the protected process
   - Run multiple instances simultaneously
   - Monitor system stability and driver behavior
   - Verify that protection remains effective

2. **Rapid Configuration Changes**
   - Create a program that rapidly changes the protected service target
   - Verify the driver handles configuration changes properly
   - Check for memory leaks or resource exhaustion

3. **System Stress Test**
   - Run system stress tools (e.g., Prime95, AIDA64) during driver operation
   - Start and stop protected services repeatedly
   - Monitor system stability and driver behavior

### Edge Case Tests

1. **Service Restart Test**
   - Start the driver and configure it to protect a service
   - Stop and restart the target service multiple times
   - Verify the driver correctly tracks the process ID changes
   - Test with rapid start/stop cycles

2. **Multi-Service Test**
   - Modify the driver to protect multiple services (requires code changes)
   - Verify protection works for all specified services
   - Test with services starting and stopping in different orders

3. **System State Transition Tests**
   - Test driver behavior during system sleep/hibernate/resume
   - Verify protection remains active after resume
   - Check driver behavior during Windows Update installations

## Performance Testing

### Performance Measurements

1. **Handle Creation Overhead**
   - Measure process handle creation time with and without the driver
   - Measure impact on various access right combinations
   - Document performance impact under normal conditions

2. **System Resource Usage**
   - Monitor driver memory usage over time
   - Check for memory leaks during extended operation
   - Measure CPU usage during normal operation and stress conditions

3. **Boot Time Impact**
   - Measure system boot time with and without the driver
   - Compare early-load vs. demand-start configurations
   - Document any impact on overall system startup

## Security Testing

### Protection Bypass Tests

1. **Handle Duplication Test**
   - Attempt to duplicate a handle from a process with existing access
   - Verify the driver intercepts and filters duplicate handle operations
   - Test with various access rights combinations

2. **Privilege Escalation Test**
   - Test accessing the protected process with debug privileges
   - Test with other special Windows privileges
   - Document which privileges can bypass protection

3. **APC Injection Test**
   - Attempt to inject an Asynchronous Procedure Call into the protected process
   - Verify if this can bypass the protection mechanism
   - Document any successful bypass techniques

### Driver Security Tests

1. **Device Interface Security Test**
   - Verify non-admin users cannot access the device interface
   - Attempt to send IOCTLs from low-privilege contexts
   - Verify proper access control enforcement

2. **Input Validation Test**
   - Send malformed or boundary case inputs to all IOCTL handlers
   - Test with extremely large data buffers
   - Test with null or invalid pointers
   - Verify the driver handles all cases gracefully

## Debugging and Monitoring

### Debug Techniques

1. **Enabling Debug Output**
   - Set registry value to enable debug prints:
     ```
     reg add "HKLM\SYSTEM\CurrentControlSet\Services\ServiceProtector\Parameters" /v DebugFlags /t REG_DWORD /d 0xFFFFFFFF
     ```
   - Use DbgView to capture debug output

2. **Kernel Debugging**
   - Set breakpoints at key functions:
     ```
     bp ServiceProtector!PreOperationCallback
     bp ServiceProtector!ProcessNotifyCallback
     ```
   - Examine variables and trace execution path
   - Use `dt` command to dump key data structures

3. **Code Coverage Analysis**
   - Use the GFlags tool to enable special pool for the driver
   - Consider using Microsoft Driver Verifier
   - Enable code coverage tracking in test builds

### Monitoring Tools

1. **Process Monitor**
   - Monitor process and thread creation
   - Track handle operations
   - Filter for operations related to the protected service

2. **Event Tracing for Windows (ETW)**
   - Create custom ETW traces for driver events
   - Use Windows Performance Recorder/Analyzer
   - Correlate driver events with system events

3. **Performance Monitor**
   - Track system performance counters
   - Monitor memory usage and handle counts
   - Create baseline measurements for comparison

## Test Automation

### Automated Test Framework

1. **Test Script Development**
   - Create PowerShell or batch scripts for basic tests
   - Develop a C/C++ test harness for detailed tests
   - Implement automated verification of test results

2. **Continuous Integration**
   - Configure CI system to build and test the driver
   - Run automated tests on each code change
   - Include static analysis in the CI pipeline

3. **Test Result Documentation**
   - Automatically generate test reports
   - Track test coverage over time
   - Document performance metrics across driver versions

## Troubleshooting Common Issues

### Common Problems and Solutions

1. **Driver Fails to Load**
   - Check system event log for specific error codes
   - Verify driver binary is in the correct location
   - Check test signing mode is enabled if using unsigned driver
   - Verify driver service is configured correctly

2. **Protection Not Working**
   - Check if the correct service name is configured
   - Verify the target process ID is being identified correctly
   - Enable debug output and trace the handle request path
   - Check for conflicting security software

3. **System Crashes**
   - Analyze crash dumps using WinDbg
   - Look for stack traces involving the driver
   - Check for common issues like NULL pointer dereferences
   - Verify synchronization is working correctly

## Test Case Documentation

### Sample Test Case Format

```
Test ID: TC-SP-001
Title: Basic Service Protection Test
Description: Verify that the driver prevents termination of the protected service
Preconditions:
  1. Driver is installed and loaded
  2. Target service is running
  3. Service name is correctly configured

Test Steps:
  1. Identify the process ID of the protected service
  2. Attempt to terminate the process using Task Manager
  3. Attempt to terminate the process using taskkill command
  4. Attempt to terminate using a custom program with PROCESS_TERMINATE rights

Expected Results:
  1. All termination attempts should fail
  2. Driver should log protection events
  3. Service should continue running uninterrupted

Pass/Fail Criteria:
  - The test passes if all termination attempts are blocked
  - The test fails if any termination attempt succeeds
```

Create similar detailed test cases for all functional areas of the driver.

## Conclusion

Thorough testing is critical for kernel-mode drivers to ensure stability, security, and performance. Follow this guide to create a comprehensive test plan for the ServiceProtector driver. Remember to always test in a safe environment to prevent system instability on production systems.