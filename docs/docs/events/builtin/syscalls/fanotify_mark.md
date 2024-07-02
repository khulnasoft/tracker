
# fanotify_mark

## Intro
fanotify_mark - add an fanotify mark to a file or directory

## Description
The `fanotify_mark` system call adds an fanotify mark to a file or directory. The fanotify mark contains the mask argument, used to indicate the events we want to receive notifications about. This call allows for finer grained control over which filesystem events we monitor. The `fanotify_mark` system call also allows to set flags which control the behavior of the fanotify marks. This system call can be used to monitor files or directories on both block-level devices and in file systems.

There are some drawbacks to using fanotify marks. First, when used on a directory, the `fanotify_mark` system call will only monitor the events related to the directory itself. It won't monitor any events occurring in the subdirectories or files underneath it. Second, fanotify marks only support limited types of events, such as open, read, write, and delete.

## Arguments
* `fanotify_fd`:`int`[K] - File descriptor identifying fanotify instance.
* `flags`:`unsigned int`[K] - Flags which control the behaviour of the fanotify marks.
* `mask`:`u64`[K] - Mask of the filesystem events to be monitored.
* `dirfd`:`int`[K] - File descriptor identifying the directory.
* `pathname`:`const char*`[U] - Pathname Relative to the file descriptor. The fanotify mark will be placed on all files and directories within this pathname, even if the file/directories don’t exist yet.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available (passed with null value)

## Hooks
### inotify_init
#### Type
KProbe
#### Purpose
To monitor the `inotify_init` functions

## Example Use Case
The fanotify_mark system call can be used to monitor access and changes made to files or directories. For example, this could be used to gain insight into application behavior. For example, an application could have access to a file and modify it, change the permission of a file, or delete a file, and these events would be tracked using the fanotify_mark system call.

## Issues
The fanotify_mark system call can only monitor fragments of the filesystem and can’t track events that happen inside subdirectories or files. Also, some flags might not be supported in some kernel versions. 

## Related Events
`fanotify_init` - create a file access notification event.  
` fanotify_init_group` - create a file access notification event (for groups).

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.