
# wait4

## Intro
wait4 - wait for a process to change state.

## Description
The `wait4()` system call suspends execution of the calling process until a 
specified process has changed state, or until a signal is received, or until the 
delay, as specified by an argument, has passed. This syscall allows to retrieve 
information about the child process which changed from the provided parameters. 
The main purpose of this call is to allow the process to wait for the termination 
of a child that it created using one of the `fork()` syscall family functions.

The `wait4()` syscall attempts to return the exit status of the process 
specified by `pid`. If `pid` is equal to -1, it matches any process whose 
process group ID is equal to the process group ID of the caller, or any process 
when it is not a member of a process group.

When `options` is set to 0, the status is returned immediately. If `pid` is equal 
to 0, `wait4()` matches any process with the same process group ID as the caller.

If `rusage` is not NULL, the resource usage of the terminating process and its 
children is returned as part of `rusage`.

## Arguments
* `pid`:`pid_t`[K] - the process ID of a child process for which status is 
requested.
* `wstatus`:`int*`[K] - the address of a buffer where the status of the 
terminated process is to be stored.
* `options`:`int`[K] - the options argument can be used to change the behavior of 
`wait4()`.
* `rusage`:`struct rusage*`[K] - a pointer to a `struct rusage` where the resource 
usage information of the terminated process (and its children) will be stored.

### Available Tags
* K - Originated from kernel-space.

## Hooks
### sys_wait4
#### Type
Kprobe + Kretprobe
#### Purpose
Hooked to trace information about a process and collect the return code value of 
`wait4()`.

## Example Use Case
The `wait4()` syscall is useful whenever processes need to be monitored. It can 
be used to track the execution of a child process and react accordingly if it 
fails. For example, an Alert rule can be triggered if the child process leaves 
the system in an unexpected state. 

## Issues
It should be noted that `wait4()`'s status value is the same as that of the 
`wait()` syscall.

## Related Events
* `exit()`
* `wait()`
* `fork()`

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.
