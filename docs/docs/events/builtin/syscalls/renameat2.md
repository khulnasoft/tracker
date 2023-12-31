
# renameat2

## Intro
renameat2 - Atomically change the name and/or location of a file relative to two directories.

## Description
renameat2 is used to rename or move a file from one directory to another. It is similar to renameat, but allows for additional flags to be specified for more fine grained control. The flags can be used to set the behavior when the target of the rename operation is a non-directory file, when a rename operation is attempted across file system boundaries, and when the target of the rename operation already exists. 

## Arguments
* `olddirfd`:`int`[K] - A file descriptor referring to the old directory, or AT_FDCWD (use the current working directory). 
* `oldpath`:`const char*`[U] - The relative pathname of the file to be renamed.
* `newdirfd`:`int`[K] - A file descriptor referring to the new directory, or AT_FDCWD (use the current working directory).
* `newpath`:`const char*`[U] - The relative pathname of the file to be created. 
* `flags`:`unsigned int`[K] - Flags which can be used to change the behavior of the call. These flags are specified as bitwise OR of the values, RENAME_EXCHANGE, RENAME_NOREPLACE, and RENAME_WHITEOUT.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available (passed with null value)

## Hooks
### do_rename
#### Type 
Ftrace

#### Purpose
To track all rename operations across multiple subsystems for debugging and to detect malicious files.

## Example Use Cases
One example of a use case for this event would be a security audit of a system. By analyzing the flow of files and processes, an auditor could identify any suspicious events such as potential malware or privilege escalation attempts.

## Issues
This syscall is vulnerable to race conditions, as the former and new paths of the file are evaluated at different times. The RENAME_EXCHANGE flag can be used to atomically trade two files, which solves the race condition issue.

## Related Events
The renameat syscall can be used in a similar fashion as renameat2, though it does not have the flags parameter and cannot set the behavior in edge cases. Additionally, the process_exec syscall can be used to detect when a user is attempting to execute a malicious file.

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.
