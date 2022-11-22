# Interceptor

Author: [@Cerbersec](https://twitter.com/cerbersec)

Interceptor is a kernel driver focused on tampering with EDR/AV solutions in kernel space by patching kernel callbacks and hooking IRPs.
Interceptor was made as part of an internship at NVISO Security's Red Team. The associated blogposts can be found [here (kernel karnage)](https://blog.nviso.eu/2021/10/21/kernel-karnage-part-1/).

In 2022, Kernel Karnage was presented at [SANS Pen Test HackFest](https://www.sans.org/cyber-security-training-events/pen-test-hackfest-2022/), prompting the release of this repository to the public as well as the following demo's:
* [https://www.youtube.com/watch?v=QHEzyCGz-rk](https://www.youtube.com/watch?v=QHEzyCGz-rk)
* [https://www.youtube.com/watch?v=EQqxQk7ytjw](https://www.youtube.com/watch?v=EQqxQk7ytjw)

## Build

Requirements:
* Windows 10 SDK 10.0 or above [link](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)
* Windows 10 WDK 10.0 or above [link](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

Build steps:
1. `git clone https://github.com/NVISO-ARES/Interceptor.git`
2. Select the appropriate configuration in Visual Studio. The configuration should be x64 Debug or Release.
3. Verify the selected configuration has Driver Signing correctly configured. 
    1. Sign Mode: Test Sign
    2. File Digest Algorithm: sha256
4. Build solution

## Installation

The driver can be installed on machines which have Driver Signature Enforcement (DSE) disabled or are in test signing mode. For a solution to disable DSE see [here](https://github.com/NVISO-ARES/CobaltWhispers#disabledse). Alternative options include signing the driver with a valid code signing certificate.

> Note: Machines with Secure Boot or Hypervisor-Protected Code Integrity (HVCI) enabled are not vulnerable

The driver can be created and started from a command prompt or PowerShell (mind the spaces):

```
sc create Interceptor type= kernel binPath= C:\Path\To\Driver\Interceptor.sys
sc start Interceptor
sc stop Interceptor
sc delete Interceptor
```

## Usage

```
Usage: InterceptorCLI.exe <option> <parameter> <values>
Options:
  -list <parameter>
        vendors                         List all supported EDR vendors and their modules
        modules                         List all loaded drivers
        hooked                          List all hooked drivers
        callbacks                       List all registered callbacks

  -hook <parameter>
        index           <values>        Hook driver(s) by index
        name            <device name>   Hook driver by name (\Device\Name)

  -unhook <parameter>
        index           <values>        Unhook driver(s) by index
        all                             Unhook all drivers

  -patch <parameter>
        vendor          <name>          Patch all modules associated with vendor
        module          <names>         Patch all callbacks associated with module(s)
        process         <values>        Patch process callback(s) by index
        thread          <values>        Patch thread callback(s) by index
        image           <values>        Patch image callback(s) by index
        registry        <values>        Patch registry callback(s) by index
        objectprocess   <values>        Patch object process callback(s) by index
        objectthread    <values>        Patch object thread callback(s) by index

  -restore <parameter>
        vendor          <name>          Restore all modules associated with vendor
        module          <names>         Restore all callbacks associated with module(s)
        process         <values>        Restore process callback(s) by index
        thread          <values>        Restore thread callback(s) by index
        image           <values>        Restore image callback(s) by index
        registry        <values>        Restore registry callback(s) by index
        objectprocess   <values>        Restore object process callback(s) by index
        objectthread    <values>        Restore object thread callback(s) by index
        all                             Restore all callbacks

Values: space separated. see -list <modules | hooked | callbacks>
Name: case sensitive. see -list <vendors>
```

## Improvements
- [ ] Port extra client functionality from [BOF version](https://github.com/NVISO-ARES/CobaltWhispers#intercept) to InterceptCLI
- [ ] Add/validate EDR vendors
- [ ] Find alternative to SysWhispers --> static detections
- [ ] Parse intercepted IRPs to determine if it should be blocked or not
- [ ] Configure valid code signing
- [ ] Implement PPL tampering ([reference](https://elastic.github.io/security-research/whitepapers/2022/02/02.sandboxing-antimalware-products-for-fun-and-profit/article/))
- [ ] Implement AMSI/ETW tampering
