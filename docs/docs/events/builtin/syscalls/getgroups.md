
# getgroups

## Intro
getgroups - get group access list for user

## Description
The getgroups() system call gets the group access list for the current user, and places it in the array pointed to by list. It returns the size of the group access list in size.

Access list is that set of supplementary group IDs associated with the calling process, initialised from the /etc/passwd file when each user first logs in. 

## Arguments
* `size`:`int`[K] - the size of the array in list
* `list`:`gid_t*`[KU] - pointer to an array of gid_t which will be filled with the group access list

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available (passed with null value)

## Hooks
### sys_getgroups
#### Type
Kprobes 
#### Purpose
To get group access list for user.

## Example Use Case
getgroups() is often used before setgroups() to obtain the list of current group IDs associated with the calling process, so it can be used for auditing and logging changes to the group access list. 

## Issues
No known issues.

## Related Events
setgroups() - set group access list for user

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.
