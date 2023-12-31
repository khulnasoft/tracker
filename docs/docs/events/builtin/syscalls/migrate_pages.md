
# Migrate_pages

## Intro
migrate_pages - Moves pages from one node set to another

## Description  
Migrate_pages is a syscall that moves pages from one node set to another. It does so by taking the pages from the old_nodes nodes, moving them to the new_nodes nodes, and counting the number of pages moved successfully. The process used is specified by the pid argument.  

Migrate_pages can be beneficial when used properly. It can move pages around a node set quickly and with minimal effort. However, this syscall can be vulnerable to TOCTOU (time-of-check to time-of-use) attacks. Furthermore, if the nodes are not setup properly, pages may not move.

## Arguments
* `pid`:`int`[K] - The pid of the process to migrate pages from.
* `maxnode`:`unsigned long`[K] - The maximum number of nodes to migrate between.
* `old_nodes`:`const unsigned long*`[K] - Pointer to an array of unsigned long representing the nodes that the pages to be moved away from.
* `new_nodes`:`const unsigned long*`[K] - Pointer to an array of unsigned long representing the nodes that the pages to be migrated to.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available (passed with null value)

## Hooks
### sys_migrate_pages
#### Type
KProbes
#### Purpose
Tracking page movements across nodes.

## Example Use Case
migrate_pages can be used when migrations need to happen quickly and resources are limited. For example, when a system needs to be partitioned in order to reserve resources for a certain process.

## Issues
migrate_pages is vulnerable to TOCTOU attacks and should be used with caution. Furthermore, as the maximum number of nodes to be migrated can be specified, migration may fail depending on how the nodes are setup.

## Related Events
* move_pages
* get_mempolicy

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracker recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.
