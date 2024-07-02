
# seccomp

## Intro
seccomp - Used to filter allowed syscalls

## Description
seccomp is a Linux-specific syscall used to restrict system calls available to a process and as such, can be used to harden system security.
It utilizes a secure computing mode (hence the acronym) to place limitations on what a process can do. This limitation is applied to any system call made within the secure computing environment.

There are a number of drawbacks to using seccomp, such as the difficulty in configuring it due to its restrictive nature, as well as the black box nature of the call, which can hamper debugging. Additionally, runtime errors can be difficult to diagnose and handle as the underlying cause may be hidden from the developer.

Overall, seccomp is a powerful tool that can help strengthen security in cases where it is necessary. The best use case is one where there are specific system calls a process must avoid.

## Arguments
* `operation`:`unsigned int`[K] - Sets the operation of seccomp.
* `flags`:`unsigned int`[K] - Sets the flags that control the behavior of seccomp.
* `args`:`const void*`[K] - Source of additional information used in setting up seccomp.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available (passed with null value)

## Hooks
### sys_seccomp
#### Type
Kprobe
#### Purpose
Hook the system call to filter allowed syscalls

## Example Use Case
seccomp could be used as an addition to existing firewall configurations to restrict the kinds of system calls that can be made by different processes. 

## Issues
Due to seccomp's restrictive nature, it can be difficult to configure and maintain. Additionally, runtime errors can be particularly perplexing to debug due to the opaque nature of the syscall. 

## Related Events
* prctl() - Used to set seccomp rules on a process.

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.