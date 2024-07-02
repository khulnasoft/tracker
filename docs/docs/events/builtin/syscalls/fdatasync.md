
# fdatasync

## Intro
fdatasync - Synchronizes file data on disk with the fd.

## Description
fdatasync is a system call used to synchronize the data stored in the memory with the disk associated to the fd. It ensures that the file will be written in the disk, as is visible to any process that has the file opened. This differs from fsync, which also synchronizes the file metadata (like access and modification times).

The main advantage of using fdatasync is that it can be executed more efficiently, since it does not require a full flush of the file metadata. In addtion, the updated file data can be visible to other processes faster. However, this smaller efficiency comes with the cost of not being able to guarantee the integrity of the file metadata. A possible downside of using fdatasync is that it increases the chances of data corruption in case of power failures

## Arguments
* `fd`:`int`[K] - File descriptor associated to the file that will be synchronize.

### Available Tags
* K - Originated from kernel-space.

## Hooks
### sys_fdatasync
#### Type
Kprobe
#### Purpose
To monitor when the fdatasync system call is executed.

## Example Use Case
fdatasync can be used in a backup software. By calling the fdatasync system call, it will make sure that the file is properly updated and synced in the disk before the backup takes place, thus avoiding any kind of data corruption if the system was to crash in the midst of the backup.

## Issues
Since the file metadata is not synced, in a power-loss situation it could lead to data inconsistency or corruption.

## Related Events
* fsync - Will make sure that the file data, and metadata, is correctly synchronize with the disk. This can provide a higher level of security but with a higher cost of performance.

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.