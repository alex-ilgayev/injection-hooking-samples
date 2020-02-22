# Sample Hooks and Injections

This repository contains various implementation for injection and hooking techniques.</br>
It made it so I can learn better the various methods and was curious about their implementation mechanics.</br>
I also recommend this great repository: [https://github.com/theevilbit/injection] which helped me in the process.
</br>
The solution contains multiple projects:

## injection-cli

Command line interface for testing and experimenting.
It invokes the next injection techniques:

- Standard Injection
- APC Injection
- TBD

### inline-hooking

Dll which can be injected into `cmd.exe` process.
The Dll uses inline hooking on function `FindNextFileW` which is being called upon directory enumeration using command `dir`.
The functionality of the hooking function is to remove the file `mal.exe` if exists in directory.

### sample-dll

Sample test Dll which pops message box on DllEntry. used for injection testing.