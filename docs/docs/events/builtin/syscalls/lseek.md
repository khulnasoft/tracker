
# lseek

## Intro
lseek - Moves read/write file offset

## Description
This event is used to move the file offset of a specified file descriptor. The `fd` argument specifies the file descriptor on which to move the offset and the `offset` argument specifies the offset relative to `whence`. The `whence` argument specifies the location for the offset relative to the beginning of the file, the current position, or the end of the file, respectively.

There are some edge cases to be aware of when using lseek. If lseek is used with `whence` set to SEEK_END and offset set to 0, it logically sets the read/write pointer of the original file. This can make it difficult to track the offset of the original file. Additionally, lseek can be used to extend the file size, allowing users to write beyond the current file size without an explicit write system call. This is not secure and should be use carefully.

## Arguments
* `fd`:`int`[K] - File descriptor value.
* `offset`:`off_t`[K] - Offset to move the read/write pointer to.
* `whence`:`unsigned int`[K] - Specifies the location for the offset relative the beginning of the file, the current position, or the end of the file.

### Available Tags
* K - Originated from kernel-space.

## Hooks
### sys_lseek
#### Type
Kprobe + Kretprobe
#### Purpose
Track the syscall invocation and returns.

## Example Use Case
The lseek event can be used to monitor any attempts at shrinking or extending the size of an open file. A program can use the lseek event to detect an attempt to extend the file size and alert the user accordingly.

## Issues
In certain cases, lseek can be used to extend the length of a file without explicitly calling a write systemcall. This lack of control can lead to security vulnerabilities in programs which process files of a predefined length.

## Related Events
* fstat - Monitor calls to fstat to detect changes in the file size.

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.