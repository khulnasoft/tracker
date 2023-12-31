
# unshare

## Intro
unshare - separate a process's execution context into its own process.

## Description
The unshare system call allows a process to separate its execution context into its own process. This system call can be used to create a new process from an existing one, or to create a new "lightweight" process (LWP), which executes in a shared memory context with the creating process. The flags parameter specifies which parts of the execution context to unshare, with CLONE_NEW[CGROUP|IPC|NET|NS|PID|USER]. It returns 0 on success, or a negative error code on error.

## Arguments
* `flags`:`int`[K] - specifies the type of context to unshare. See flags section in man page for more details.

### Available Tags
* K - Originated from kernel-space.

## Hooks
### sys_unshare
#### Type
Kprobe
#### Purpose
To detect the unshare syscall.

### task_unshare
#### Type
Kprobe
#### Purpose
To detect the task_unshare function call.

## Example Use Case
An example of using unshare is a container. By using this system call, a process can separate its execution context, thus creating a new process (or LWP) in a shared memory context with its parent while also allowing it to have its own environment variables and IPC namespaces, among others.

## Issues
When unsharing a process, all of its children must also be unshared or they will remain in the original process's context.

## Related Events
* fork - Create a child process.
* clone - Create a child process in a different memory address space. 
* setns - Set namespace for process.

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.
