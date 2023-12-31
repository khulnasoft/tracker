
# sched_getparam

## Intro
sched_getparam - fetch scheduling parameters of the target process

## Description
sched_getparam is a function used to modify the scheduling parameters of the target process with the given pid according to the changes specified in the second argument, the parameters of the used scheduling policy. It is often used by system administrators to make sure that a certain process is always given the same priority relative to other processes on the system.

One of the advantages of using this function over other methods of setting policy parameters is that it works with any policy, regardless of the number of parameters. This can save time when configuring policies that have a large number of parameters, as the system administrator does not have to manually set each parameter individually.

One of the drawbacks is that it is not an atomic operation. If the pid argument provided is the same as the pid of the calling process, then the operation may take a relatively long time, as the operation must first be carried out on the caller's process, then on the target process. This operation can also lead to race conditions if the pid of the calling process and the pid of the target process are both the same.

## Arguments
* `pid`:pid_t[K] - pid of the process to query the parameters of.
* `param`:struct sched_param*[K+U] - pointer to a struct sched_param to store the policy information in.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available (passed with null value)

## Hooks
### do_sys_sched_getparam
#### Type
Kprobe + Kretprobe
#### Purpose
Collecting information about the scheduling parameters of a particular process.

## Example Use Case
sched_getparam can be used in a monitoring process which keeps track of the scheduling parameters of processes, in order to ensure that they do not "starve" in terms of resources and can run to completion.

## Issues
The operation is not atomic, which may lead to race conditions with multiple threads trying to access the same process.

## Related Events
* sched_setscheduler - set scheduling policy and parameters of the target process 
* sched_get_priority_min - get the minimum priority value for the given scheduling policy

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.
