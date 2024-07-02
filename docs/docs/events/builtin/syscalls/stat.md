
# stat

## Intro
stat - Obtains information about a file, given its pathname

## Description
The `stat` syscall is used to obtain information about a file or directory, 
given its pathname. The information is retrieved in the form of a `struct stat` 
object, which contains information such as the file's size, last access and modification times, and owner. It is also used to detect if a file exists, 
or why it does not exist, so that proper exception handling can be done.

There is a potential Time of Check, Time of Use (TOCTOU) race condition when using `stat` to check the existence of a file. If used in the wrong context, it can lead to errors.

## Arguments
* `pathname`:`const char*`[U] - Pathname of the file or directory being examined.   
* `statbuf`:`struct stat*`[K] - Pointer to the location of the `stat` struct in memory, where all the results of the function call will be stored.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available (passed with null value)

## Hooks
### do_sys_stat
#### Type
Kprobes
#### Purpose
To detect stat syscalls and collect information about them.

## Example Use Case
A user-space program might use `stat` to check the existence of a file, and then take some action based on the result.

## Issues
There is a potential TOCTOU race condition when using `stat` to check the existence of a file. 

## Related Events
* `lstat` - A related syscall which facilitates the acquisition of information about a file on a filesystem. It does not follow symbolic links.  
* `fstat` - A related syscall which regards an already opened file for information instead of a pathname.

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.