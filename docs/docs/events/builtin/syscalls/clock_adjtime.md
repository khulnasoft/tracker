
# clock_adjtime

## Intro
`clock_adjtime()` - set, get and adjust a clock's offset and frequency

## Description
The clock_adjtime() system call sets, gets and adjusts (i.e. corrects) the time or frequency of the clock designated by clock_id. buf is a pointer to a `struct timex` data structure which is used to obtain further details about the operation to be performed by clock_adjtime.

The main purpose of this system call is to allow an applications to modify the offset and/or frequency of a time source/clock to ensure time-stamp accuracy, as well as to compensate for any skews in the clocks' frequency caused by environmental factors such as temperature variations. Furthermore, it allows the clock offset of a given clock to be set, directly, to a given value.

## Arguments
* `clk_id`: `const clockid_t` - Identifies the clock to be affected by the call. There are a number of predefined clocks which can exist in the system, each given a specific clock ID, and further application-defined clocks can be created with `timer_create()`. 
* `buf`: `struct timex*` - A pointer to a `struct timex` data structure, which contains the clock adjustments to be made as well as a number of other related parameters.

### Available Tags
No available tags.

## Hooks
### `sys_clock_adjtime`
#### Type
Kprobes
#### Purpose
Determine clock offset and frequency.

### `do_adjtimex`
#### Type
Kprobes + Tracepoints
#### Purpose
The purpose of hooking do_adjtimex is to determine whether the clock offset and frequency is being adjusted by a given clock, as well as to record any error values that may be returned.

## Example Use Case
Consider an application for which time stamp accuracy is paramount. This system could use the `clock_adjtime()` system call to make adjustments to the clock's frequency and offset. This could be, for example, when the clock source is experiencing temperature-based frequency drift. The `clock_adjtime()` can be used to correct this drift, ensuring that timestamps are accurate and allowing the application to continue functioning without any substantial interruptions.

## Issues
This system call requires root privileges. This can be a potential security issue if too many users have access to the call. Furthermore, the system call can be prone to TOCTOU (Time of check, time of use) attacks, as some of the values provided by the caller might have changed by the time the call is executed by the kernel.

## Related Events
* `clock_gettime` - returns the time information from the specified 'clock_id'
* `clock_settime` - sets the given clock to a specified time value

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.
