
# ulimit

## Intro
ulimit - set or get the resource limit of the current process

## Description
ulimit is a command provides control over the resourcing of a process. The ulimit
command can be used to set the limits on the system resources that can be used by
the process. The limits can be set for any of the following that the system
supports: files, memory, number of processes, maximum CPU time, and more. With
some limits, ulimit also has the ability to query the current limit. 

Ulimit can be used to protect systems from resource abuse by allowing users to put
an upper limit on the amount of certain resources they can allocate to their
processes. This ensures that runaway processes or user abuse of resources is
avoided. 

## Arguments
* `resource`:`int`[K,U] - the resource to use.
* `limit`:`string`[K,U] - the new resource limit. Can be a number, 'hard' or 'soft'.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available (passed with null value)

## Hooks
### do_ulimit
#### Type
Kprobe
#### Purpose
to monitor the resource limit of the current process.

## Example Use Case
Ulimit can be used to guard against an individual user or process from going wild
and consuming too much resources by putting a limit on the resources that can be used.

## Issues
Ulimit might not be available in all systems, so it is important to check what the
supported resources are before using it.

## Related Events
setrlimit

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.
