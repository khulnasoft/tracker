# tracker_info

## Intro

tracker_info - An event that exports some relevant data of Tracker upon startup.

## Description

This event, created in user-mode during Tracker's initialization, is typically the first event emitted. It provides valuable metadata about Tracker's configuration and runtime environment, which can be helpful for event processing and troubleshooting.

The event was created also with Tracker's File Source in mind, to provide information about how Tracker ran during the original capture.

## Arguments

* `boot_time`:`u64`[U] - the boot time of the system that Tracker is running on, relative to the Unix epoch.
* `start_time`:`u64`[U] - the time the Tracker process started relative to system boot time.
* `version`:`const char*`[U] - Tracker version.

## Hooks

## Example Use Case

The event could be used to calculate the relative time of events since Tracker's start.

## Related Events

`init_namespaces`