
# pkey_alloc

## Intro
pkey_alloc - allocate an protection key

## Description
The pkey_alloc system call is used to allocate a protection key; these are used to give a process access to privileges and other capabilities. The flags argument takes an ORed bitmask of options to control access to the key, such as whether or not it can be used with certain instructions like load_exclusive. The access_rights argument specifies the access rights allowed by the key, such as RWX (read-write-execute).

## Arguments
* `flags`:`unsigned int` - the set of flags controlling access of the key.
* `access_rights`:`unsigned long` - the set of access rights allowed by the key.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available (passed with null value)

## Hooks
### pkey_alloc
#### Type
Kprobes
#### Purpose
To monitor any syscall invocation of the function.

## Example Use Case
Using pkey_alloc can be used to control which users have access to privileged instructions.

## Issues
No known issues.

## Related Events
The related system call for this event is [pkey_free](https://man7.org/linux/man-pages/man2/pkey_free.2.html) which is used to deallocate a protection key.

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.
