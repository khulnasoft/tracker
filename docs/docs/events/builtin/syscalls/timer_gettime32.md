
# timer_gettime32

## Intro
timer_gettime32 - Gets a timer expiration and interval for a 32-bit specific timer

## Description
The timer_gettime32() system call gets the expiration and interval for the
timer specified by `timer_id`. If `setting` is not NULL, the structure pointed
to by `setting` is used to return the expiration and interval of the timer.
The structure used is the 32-bit version of `itimerspec`: `struct
old_itimerspec32`.

This system call is specific to 32-bit architectures, and should not be used on
64-bit architectures, where the `timer_gettime` system call should be used
instead.

## Arguments
* `timer_id`:`timer_t`[KU] - The timer for which the expiration and interval
should be retrieved.
* `setting`:`struct old_itimerspec32*`[KU] - A pointer to a
`struct old_itimerspec32` structure. The expiration and interval will be stored
in this structure.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it).

## Hooks
### timer_gettime32
#### Type
Kprobe + Kretprobe
#### Purpose
The purpose of hooking this function is to gain visibility into the timer
expiration and interval requested for a specific timer.

## Example Use Case
This event can be used to observe what timers are being used in a system.
This can be used in conjunction with other tracepoints and events to answer
questions such as what timers are the longest running, or when something is
timed out.

## Issues
This system call is specific to 32-bit Linux architectures and should not be used on 64-bit architectures.

## Related Events
* `timer_settime32` - Used to set a timer expiration and interval for a 32-bit specific timer
* `timer_create` - Creates a timer with a given expiration and interval
* `timer_delete` - Deletes a timer

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.
