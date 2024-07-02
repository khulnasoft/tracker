
# kexec_load 

## Intro
kexec_load - loads a new kernel for later execution.

## Description
kexec_load allows loading or relocating the currently running kernel for later execution. It loads the new kernel from the values provided by its arguments. It allows to perform sanity and memory integrity checks on the new kernel before it is loaded. It also allows for kexec_file_load which does the same job, except it loads the new kernel from a binary on the filesystem.

The main advantage of using 'kexec_load' is that it allows the user to safely hotpatch the kernel without rebooting the system. The drawbacks are the relatively low speed of kernel hotpatching and the complexity of relocating the kernel.

## Arguments
* `entry`:`unsigned long`[K] - Contains the starting address of the new kernel.
* `nr_segments`:`unsigned long`[K] - Contains the number of segments of the new kernel.
* `segments`: `struct kexec_segment*`[K] - Contains an array of kexec_segment structures, representing the different address ranges of the new kernel.
* `flags`:`unsigned long`[K] - Contains the flags used to load the new kernel. Possible flags are KEXEC_ARCH_MASK, KEXEC_FILE_UNLOAD, KEXEC_ON_CRASH, KEXEC_PRESERVE_CONTEXT, KEXEC_CLONE_KERNEL, KEXEC_ON_CRASH_UNLOAD, KEXEC_CLONE_INIT, KEXEC_PRESERVE_PCI and KEXEC_IGNORE_SEGV.

### Available Tags
* K - Originated from kernel-space.

## Hooks
### do_sys_kexec 
#### Type
kprobe + kretprobe
#### Purpose
Identify kexec system calls, arguments, return values and execution times. 

### load_segments
#### Type
kretprobe 
#### Purpose
Identify the segments used for the new kernel loading.

## Example Use Case
An example of kexec_load being used is when the user wants to hotpatch the kernel without rebooting the system. The 'kexec_load' will load the new kernel from the values provided and perform sanity and memory checks to ensure the integrity. It can be used to identify kernel bugs and other system inconsistencies without having to reboot the system. 

## Issues
The main issue with kexec_load is that it is relatively slow compared to other hotpatching methods. It also requires a certain level of complexity as there is a need to relocate the kernel.

## Related Events
* kexec_file_load - Similar to kexec_load, but it loads the kernel from a file on the filesystem instead. 
* kexec_unload - Unloads a previously loaded kernel.

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.