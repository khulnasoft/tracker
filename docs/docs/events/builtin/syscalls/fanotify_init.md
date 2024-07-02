
# fanotify_init

## Intro
fanotify_init - initialize fanotify handle

## Description
The fanotify_init() system call initializes the fanotify handle, which is  used  to  register  fanotify  events  and  mark  paths  and  files  to  be  monitored with the `fanotify_mark` system call. This call allocates the required structures, sets the given flags and allocates an event queue.

A fanotify handle can be used to monitor events in multiple directories by calling the `fanotify_mark` system call and the returned file descriptor can be monitored with `select()`, `poll()` or `epoll_wait()`.

The flags used in fanotify_init determine the behavior of the fanotify handle. Some of the available flags are `FAN_CLOEXEC`, `FAN_NONBLOCK` and `FAN_UNLIMITED_QUEUE`.

## Arguments
* `flags`:`unsigned int`[K] - set of flags used to determine the behavior of the fanotify handle.
* `event_f_flags`:`unsigned int`[K] - set of event flags used to select the events to report to the fanotify handle.

### Available Tags
* K - Originated from kernel-space.

## Hooks
### fanotify_init
#### Type
Probe
#### Purpose
To monitor events related to fanotify_init.

## Example Use Case
A monitoring tool could use fanotify_init to create handles which it can then use to monitor files and directories for any changes and act on them.

## Issues
There is a known issue that fanotify_init does not support 64-bit arguments.

## Related Events
* fanotify_mark - set up fanotify notification
* fanotify_close - close fanotify notification

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.