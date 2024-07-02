
# fstatfs

## Intro
fstatfs - retrieves information about a mounted file system

## Description
`fstatfs()` is used to retrieve relevant information about a mounted file system. It returns information like the file system type, size, blocks, and block size. It is useful for getting information about drives and determining their capacity. The `fstatfs()` system call can be used to check for errors or malfunctioning disks.

## Arguments
* `fd`: `int` - A file descriptor associated with the mounted file system.
* `buf`: `struct statfs*` - A pointer to a `struct statfs` object which will contain information about the mounted file system after the system call returns.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available (passed with null value)

## Hooks
### sys_fstatfs
#### Type
Kprobe + Kretprobe
#### Purpose
To show when a filesystem is queried for information.

### sys_statfs
#### Type
Kprobe + Kretprobe
#### Purpose
To show when a filesystem is queried for information.

## Example Use Case
The `fstatfs()` system call can be used to check for errors or malfunctioning disks. For example, there may be an application that regularly checks disk space and reports errors if a disk is malfunctioning or full. The `fstatfs()` system call can be used to get the disk size, detect any errors, and report any issue to the user.

## Issues
There is no issue known with `fstatfs()`.

## Related Events
`fstatfs64()`, `statfs()`, `statfs64()`

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.