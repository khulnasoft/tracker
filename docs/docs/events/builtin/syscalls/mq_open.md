
# mq_open

## Intro
mq_open - open a message queue

## Description
The `mq_open` function opens a POSIX message queue, attempting to create it if `O_CREAT` is specified in the `oflag` argument. If successful, it returns a message queue descriptor for use in later `mq_*` calls.

The `name` argument gives the name of the message queue and `mode` is the working mode, which is related to the protection of the created message queue. The `oflag` argument is a flag argument that may be made up of one or more of the following specified in `<fcntl.h>`:

* `O_RDONLY` - Open the message queue for reading only.
* `O_WRONLY` - Open the message queue for writing only.
* `O_RDWR` - Open the message queue for both reading and writing.
* `O_CREAT` - Create the message queue if it does not already exist.
* `O_EXCL` - When used with `O_CREAT`, if the queue already exists, the call fails.

If the `O_CREAT` is specified in `oflag` the `mode` argument specifies the initial permissions of the newly created queue, as in `open(2)`. It is modified by the process's `umask` in the usual way. The `attr` argument pointer can be used to set the initial attributes of the queue.

## Arguments
* `name`:`const char*`[KU] - Name of the message queue to be opened. Must begin with a '/' character.
* `oflag`:`int`[KU] - Flag argument used to determine how the queue should be opened.
* `mode`:`mode_t`[KU] - Permission bits used when setting the queue's initial permissions.
* `attr`:`struct mq_attr*`[KU] - Pointer to a structure containing the queue's initial attributes.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available (passed with null value)

## Hooks
### do_mq_open
#### Type
Kprobe
#### Purpose
To capture information about when and where the `mq_open` syscall is invoked.

## Example Use Case
Using the `mq_open` event can be used to monitor the creation and access of message queues, logging any relevant information pertaining to the queue and the process that invoked it.

## Issues
The `mq_open` event occurs when the message queue is opened and does not indicate that it was *successfully* opened.

## Related Events
* mq_timedsend
* mq_receive
* mq_timedreceive

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.