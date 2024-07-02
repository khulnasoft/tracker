
# rt_sigtimedwait

## Intro
rt_sigtimedwait - a system call that waits for a signal to arrive

## Description
rt_sigtimedwait is a system call that atomically waits for a signal to arrive and removes the signal from the queue. It operates similarly to the pselect() system call, except it waits for a signal instead of a file descriptor to become readable and writable. The set parameter specifies the set of signals to wait for, info points to a structure where information about the signal caught is stored, timeout specifies an upper limit on the amount of time that the call should block, and sigsetsize specifies the size of the signal set in bytes. 

This system call should not be used if the signal being waited for is handled by a signal handler registered by sigaction(). In such cases, the signal is delivered directly to the signal handler instead of the process's signal queue.

The event can cause the calling process to sleep until the signal is received or the timeout has reached. Additionally, real-time signals that are not caught or ignored by the process may cause it to terminate.

## Arguments
* `set`:`const sigset_t*`[K] - a pointer to a structure to examine a set of signals that the process may be waiting for.
* `info`:`siginfo_t*`[U] - a pointer to a structure where information about the signal caught is stored.
* `timeout`:`const struct timespec*`[K] - a pointer to a structure that specifies an upper limit on the amount of time that the call should block.
* `sigsetsize`:`size_t`[K] - the size of the signal set in bytes.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available (passed with null value)

## Hooks
### rt_sigtimedwait
#### Type
Kernel function
#### Purpose
Hooked to monitor the use and arguments of the system call.

## Example Use Case
rt_sigtimedwait can be used to create a timeout mechanism by waiting for a signal in a loop. 

## Issues
One of the key drawbacks of using rt_sigtimedwait is that the process may sleep until the signal arrives or the timeout has been reached, which may be undesirable in cases where having a responsive application is important.

## Related Events
* sigaction() - the system call to register a signal handler
* sigprocmask() - the system call to examine and change the currently blocked signals

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.