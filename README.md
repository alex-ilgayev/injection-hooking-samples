# Sample Hooks and Injections

This repository contains various implementation for injection and hooking techniques.</br>
It made it so I can learn better the various methods and was curious about their implementation mechanics.</br>
I also recommend this great repository: [https://github.com/theevilbit/injection] which helped me in the process.
</br>
The solution contains multiple projects:

## injection-cli

Command line interface for testing and experimenting.
The project contains the next injection techniques:

- Standard Injection
  - Searching for `LoadLibraryW` address. We assuming `kernel32` libraries are loaded in same addresses for all processes.
  - Invoking `VirtualAllocEx` to allocate injected DLL name string. 
  - Invoking `WriteProcessMemory` to write that string.
  - Invoking `CreateRemoteProcess` which will run `LoadLibraryW` with the dll name as a parameter.
- APC Injection
  - Searching for `LoadLibraryW` address. We assuming `kernel32` libraries are loaded in same addresses for all processes.
  - Invoking `VirtualAllocEx` to allocate injected DLL name string. 
  - Invoking `WriteProcessMemory` to write that string.
  - Enumerating all threads of the specified process using `CreateToolhelp32Snapshot`.
  - For each such thread we are invoking `QueueUserAPC` with `LoadLibraryW` procedure and DLL name as a parameter. This function queues asynchronous procedure to the therad when he returns from **alertable** state. That state includes returning from the next functions:
    - `kernel32!SleepEx`
    - `kernel32!SignalObjectAndWait`
    - `kernel32!WaitForSingleObject`
    - `kernel32!WaitForSingleObjectEx`
    - `kernel32!WaitForMultipleObjects`
    - `kernel32!WaitForMultipleObjectsEx`
    - `user32!MsgWaitForMultipleObjectsEx`
  - Most of the time one of the threads will be returning from that state, and reload the library. I had 100% success with that method.
- Early Bird Technique
  - **The only difference here from APC Injection is the creation of a new process instead of injecting a existing one.** 
  - Searching for `LoadLibraryW` address. We assuming `kernel32` libraries are loaded in same addresses for all processes.
  - Creating new process in suspended state. The executable is passed by param to the injection function.
  - Invoking `VirtualAllocEx` to allocate injected DLL name string. 
  - Invoking `WriteProcessMemory` to write that string.
  - Invoking `QueueUserAPC` with `LoadLibraryW` procedure and DLL name as a parameter.
  - Invoking `ResumeThread`. Because thread was in suspended state, starting it causes the operating system to invoke the APC, means the injected code.
- Process Hollowing. TBD.

### inline-hooking

Dll which can be injected into `cmd.exe` process and implements sample inline hooking technique.</br>
The Dll uses inline hooking on function `FindNextFileW` which is being called upon directory enumeration using command `dir`.</br>
The functionality of the hooking function is to remove the file `mal.exe` if exists in directory.

### iat-hooking

Dll which can be injected into `cmd.exe` process and implements sample IAT (Import Address Table) hooking technique.</br>
The Dll "parse" current loaded module PE file, searches for Import directory, search for specified dll and function in the directory, and overwrite it with our hooked function.</br>
Our sample overwrites function `FindNextFileW` which is called upon directory enumeration, and change the address to our "malicious" function.

### sample-dll

Sample test Dll which pops message box on DllEntry. used for injection testing.