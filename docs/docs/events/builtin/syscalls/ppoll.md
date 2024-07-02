
# ppoll

## Intro
ppoll - poll file descriptors with a timeout given with nanosecond precision

## Description
ppoll is a Linux syscall that polls a list of file descriptors provided in a
struct pollfd array with the expectation of a response within a given
timespec timeout. It also serves to allow certain interrupts or signals to be
temporarily ignored while ppoll is running. It is very similar to the [poll
syscall](http://man7.org/linux/man-pages/man2/poll.2.html) but with the
timespec capability for nanosecond level timeouts.

The advantages of using ppoll over poll are that it can provide a much finer
grained control when setting a timeout, and can block signals from interrupting
it while it runs. The main potential drawback is that since it is a newer
syscall, it may not be supported by all distributions.

## Arguments
* `fds`:`struct pollfd*`[K] - Pointer to the array of pollfd structures.
* `nfds`:`unsigned int`[K] - Number of pollfd structures in the array.
* `tmo_p`:`struct timespec*`[K] - Pointer to an object of type timespec that
specifies the maximum amount of time (in nanoseconds) that the call will block
waiting for a response.
* `sigmask`:`const sigset_t*`[K] - Optional pointer to a signal set that is
carefully managed while ppoll is running, to prevent system interrupts (such as
signals) from interfering with the response time of the call.
* `sigsetsize`:`size_t`[K] - Optional value for size of the sigmask. If a
sigmask is passed in, then sigsetsize must provide the size of the sigmask
including any padding.

### Available Tags
* K - Originated from kernel-space.

## Hooks
### do_sys_ppoll
#### Type
TRACE_IRQS_OFF
#### Purpose
Hooks the functions that handles the `ppoll` syscall, to allow for monitoring its
execution.

## Example Use Case
A process needs to read multiple files concurrently but not take too long to
return a result. ppoll could be used with short timeout values to make sure
that the call doesn't wait too long on any single file, while still allowing
it to monitor multiple files.

## Issues
Since ppoll is a relatively new syscall, there may be compatibility issues when
running on older versions of Linux that don't support it. Additionally, the
fine-grained timeout values may not work on certain systems, especially when
those systems use slower hard drives.

## Related Events
[poll](http://man7.org/linux/man-pages/man2/poll.2.html) - simpler syscall
performing similar action without nanosecond-level timeouts

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.