
# swapoff

## Intro
swapoff - unregister a path from the list of used swap devices

## Description
The `swapoff()` function unregisters the path pointed to by the `path` parameter from the list of used swap devices. This call can be used to deactivate swap devices without reboot. Since the Linux kernel version 4.14, swap devices can also be limited to a specific range of physical memory pages. This allows creating swap devices out of unused physical memory. 

## Arguments
* `path`:`const char*`[K] - path to the swap device.  

### Available Tags
* K - Originated from kernel space.

## Hooks
### sys_swapoff
#### Type
kprobe
#### Purpose
Used to unregister the path pointed to by the path parameter from the list of used swap devices.

## Example Use Case
When we want to unregister a swap device without rebooting the system.

## Issues
On some systems, swapoff() fails with an "Operation not permitted" error if called from a non-root process.

## Related Events
The `swapon()` syscall can be used in combination with `swapoff()` to activate and deactivate swap devices.

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.