# memfd_create

## Intro

memfd_create - create an anonymous file.

## Description

The `memfd_create()` system call creates an anonymous file and returns a file
descriptor that refers to it. The file behaves like a regular file and can be
modified, mapped, and can also grow as required. This is typically used for
in-memory storage without the need for a backing file on the filesystem, thus
providing a mechanism for efficient inter-process communication and temporary
storage.

Files created using `memfd_create()` are automatically removed once the last
reference to them is closed, ensuring they don't persist beyond their required
lifespan.

## Arguments

* `name`:`const char *`[U] - An optional name for the file, mainly used for debugging purposes.
* `flags`:`unsigned int`[K] - Flags to modify the behavior. Notable flags include:
    * `MFD_CLOEXEC`: Set the close-on-exec flag for the new file descriptor.
    * `MFD_ALLOW_SEALING`: Allow the file to be sealed, preventing further modifications.

### Available Tags

* K - Originated from kernel-space.
* U - Originated from user space.
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use).
* OPT - Optional argument - might not always be available (passed with null value).

## Hooks

### sys_memfd_create

#### Type

Tracepoint (through `sys_enter`).

#### Purpose

To monitor and trace when the `memfd_create()` system call is invoked, capturing
details about the file's creation, its name, and any flags set.

## Example Use Case

Implementing a high-performance caching mechanism where data is stored in memory
but accessed through a file descriptor. This can be used in scenarios where data
needs to be shared between processes or stored temporarily without the overhead
of disk I/O.

## Issues

Since `memfd_create()` provides an in-memory file storage mechanism, overuse
without proper monitoring could lead to excessive memory consumption. Moreover,
if not appropriately managed, this could be exploited by malicious actors to
create a denial-of-service condition.

## Related Events

* `ftruncate()` - To resize the in-memory file.
* `mmap()` - To map the file into the process's address space.

> This document was automatically generated by OpenAI and reviewed by a Human.
