
# epoll_wait_old

## Intro
epoll_wait_old - waits for events on an epoll file descriptor

## Description
The `epoll_wait_old` function is used to retrieve events associated with an epoll instance. It will block until an event from the epoll instance is available, and then return a list of events that were associated with the epoll instance when the call occurred. The maximum number of events returned by a single call is specified by the `maxevents` argument. 

This system call is the older version of the `epoll_wait()` system call which itself is replaced by the `epoll_pwait()` system call which allows for setting a timeout value for the total amount of time to wait for events. The `epoll_wait_old` system call does not support a timeout value and instead only blocks until an event is available. 

The epoll event type of the returned events can be determined from the `events` field of the `struct epoll_event` returned from the call. The data associated with the returned events can be determined from the `data` field of the struct.

## Arguments
* `epfd`: `int`[K] - The file descriptor for the epoll instance. Must be a valid file descriptor that was returned from a call to `epoll_create()`. 
* `events`: `struct epoll_event *`[K] - A pointer to an array of `struct epoll_event`s to be filled with events associated with the epoll instance.
* `maxevents`: `int`[K] - The maximum number of events to be present in the `events` array when the call returns. 

### Available Tags
* K - Originated from kernel-space.

## Hooks
### do_sys_epoll_wait()
#### Type
Kprobe
#### Purpose
To capture when the system call is called and have access to all the arguments passed to it.

## Example Use Case
`epoll_wait_old` might be used in a program that uses asynchronous I/O to read data from multiple sources. The program could use `epoll_create()` to create an instance of an epoll file descriptor, then use `epoll_ctl()` to add one or more file descriptors to the instance. The program could then call `epoll_wait_old()` to wait for events on the epoll file descriptor, when an event is available, the `events` array will be populated with events related to the epoll instance.

## Issues
* This system call does not support a timeout value and instead only blocks until an event is available. This may cause the program to hang if no events occur before the program is killed.

## Related Events
* `epoll_pwait()` - The newer version of the `epoll_wait()` system call.

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.