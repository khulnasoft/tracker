
# pivot_root

## Intro
pivot_root - change the root file system of the current process

## Description
The pivot_root() system call makes the directory put_old the new root file system.
 It moves the current root file system to the directory new_root. 
This comparison is done by making the parent of the old PWD as the new PWD. 

pivot_root() is typically used in the final stages of a shift of a system into a chroot
 environment. The old root directory is placed in put_old and can be used later to switch
 back or unmount the old root directory (pivot/unpivot).

The both directories must be on the same file system. This can also be used to change to
 a different root file system if necessary.

## Arguments

* `new_root`:`const char*`[K] - a pointer to a pathname of the new  directory  which  will  become  the  root  directory  (the  starting  point  for absolute paths).
* `put_old`:`const char*`[K] - a pointer to a pathname of the directory which will be the new parent of the old root directory.

### Available Tags

* K - Originated from kernel-space.

## Hooks
### sys_pivot_root
#### Type
Kprobe 
#### Purpose
To audit attempts to pivot_root.

## Example Use Case
When a process wants to enter a chroot jail for more security, it can use pivot_root() to change its root file system to the one inside the jail. 

## Issues
pivot_root() cannot be used across file systems.

## Related Events
chdir, chroot

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.
