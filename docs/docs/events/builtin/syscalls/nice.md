
# nice

## Intro
nice - Change the nice value of the current process, influence scheduling priority

## Description
The nice() system call can be used to change the nice value of the current process, which influences its scheduling priority. A lower nice value causes more favorable scheduling, and a process with a "high" nice value will be scheduled less often than other processes. A process must be privileged to raise its nice value (i.e., to decrease its priority).

There are some edge-cases with nice(): if a privileged process calls nice() with a non-zero value, then it might cause the scheduling priority to drop too far or become too favorable; this could put system instability. Additionally, even a process with the correct privileges cannot raise its nice value above its current value.

## Arguments
* `inc`:`int` - The 'inc' argument specifies an increment to be added to the nice value of the current process. A positive value adds to the nice value and a negative value subtracts from it. For the superuser, the range of valid nice values is from -20 (most favorable) to +19 (least favorable). For a normal process, the range is from 0 to PRIO_MAX (usually 20).

## Hooks
### sys_nice
#### Type
kprobe
#### Purpose
To monitor and log when the `nice` syscall is used.

## Example Use Case
 Nice() can be used to measure the relative performance of two applications running against each other on a system. By setting one application to a slightly higher nice value, you can prioritize the other application, thus obtaining an accurate performance measurement.

## Issues
No known issues.

## Related Events
The sched_setscheduler function can be used to change the scheduling policy and priority of a process. This event is typically a better option than the nice() system call if you want to tailor the scheduling priority of a process.

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.
