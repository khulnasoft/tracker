
# kill

## Intro
kill - send a signal to a process

## Description
The kill syscall allows a process to send a signal to another process. This can be used to "kill" or terminate the process, or send other signals to it, such as for pausing or restarting the process. The signal that is sent will depend on the value of the sig argument, which can take values from any of the signal constants defined in the signal.h header file. The privileged version of this syscall, kill(), can be used to send signals to any process running on the system, while the unprivileged version, tkill(), can only be used to send signals to processes owned by the calling process.

One disadvantage of using kill() is that it is vulnerable to a TOCTOU race condition. If the process being killed has changed its state in the window between the time of check and the time of use, the kill() might be attempted on the wrong process.

## Arguments
* `pid`:`pid_t`[K] - Identifier of the process the signal is being sent to.
* `sig`:`int`[K] - Signal that is being sent. Can be one of the constants defined in the signal.h header file.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available (passed with null value)

## Hooks
### do_kill
#### Type
Kprobes
#### Purpose
To trace when a process is killed by another process.

### sys_kill
#### Type
Kretprobes
#### Purpose
To trace when a process is killed by another process and retrieve the arguments passed. 

## Example Use Case
The kill syscall can be used in a monitoring system, where a signal can be sent to a particular process to pause it, then analyse the data and restart it. This can be used to understand how a particular processes behaves over time or over different input values.

## Issues
The kill() syscall is vulnerable to a TOCTOU race condition, meaning that the signal might be sent to the wrong process if the one being killed changes its state in the window between the time of check and the time of use.

## Related Events
The kill syscall is often used with the fork() syscall. The fork() syscall allows a process to create a new process, while the kill() syscall can be used to terminate the new process when it is no longer needed.

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.