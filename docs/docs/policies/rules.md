# Rules

Rules are part of the Tracker Policy, which defines which events to trace. The events that are part of a specific policy are recorded in the `rules` section of the Tracker Policy. It is possible to define multiple events within each policy. The [events](../events/index.md) section provides further information on the type of events that Tracker can track.

Below are several examples on configuring events in the Tracker Policy.

## Events

Every event that is specified within the `rules` section supports three types of filters: `scope`, `data` and `return value`.

### Type of Events

**[A syscall](../events/builtin/syscalls/index.md)**

Example Scope Section referencing the `open` syscall:

```bash
spec:
	scope:
	    - global
	rules:
	    event: open
```

The name of the syscall is going to be the name of the event.

**[Network Events](../events/builtin/network/index.md)**

Network Events can be specified from the list of `Available network events`.

For example:

```bash
spec:
	scope:
	    - global
	rules:
	    event: net_packet_ipv4
```

**[A behavioural Signature](../events/builtin/signatures/index.md)**

To specify one of the behavioral signatures as an event, use the name of the signature from the table in the documentation as the event name:

```bash
spec:
	scope:
	    - global
	rules:
	    event: anti_debugging
```

**[Any of our extra events](../events/builtin/extra/bpf_attach.md)**

Any of the extra events listed in the Tracker documentation can be listed in the Tracker Policy.

For instance, to specify the [do_sigaction](../events/builtin/extra/do_sigaction.md) event, provide the name in the YAML manifest:

```bash
spec:
	scope:
	    - global
	rules:
	    event: do_sigaction
```

## Scope filters

Further refinement of the policy's scope is achievable through the application of scope filters:

```yaml
apiVersion: tracker.khulnasoft.com/v1beta1
kind: Policy
metadata:
	name: sample-scope-filter
	annotations:
		description: sample scope filter
spec:
	scope:
	    - global
	rules:
	    event: sched_process_exec
	    filters:
		- pid=1000
```

The scope filters supported are:

#### p, pid, processId

```yaml
event: sched_process_exec
filters:
    - pid=1000
```

#### tid, threadId

```yaml
event: sched_process_exec
filters:
    - tid=13819
```

#### ppid, parentProcessId

```yaml
event: sched_process_exec
filters:
    - ppid=1000
```

#### hostTid, hostThreadId

```yaml
event: sched_process_exec
filters:
    - hostTid=1000
```

#### hostPid

```yaml
event: sched_process_exec
filters:
    - hostPid=1000
```

#### hostParentProcessId

```yaml
event: sched_process_exec
filters:
    - hostParentProcessId=1
```

#### uid, userId

```yaml
event: sched_process_exec
filters:
    - uid=0
```

#### mntns, mountNamespace

```yaml
event: sched_process_exec
filters:
    - mntns=4026531840
```

#### pidns, pidNamespace

```yaml
event: sched_process_exec
filters:
    - pidns=4026531836
```

#### comm, processName

```yaml
event: sched_process_exec
filters:
    - comm=uname
```

#### hostName

```yaml
event: sched_process_exec
filters:
    - hostName=hostname
```

#### cgroupId

```yaml
event: sched_process_exec
filters:
    - cgroupId=5247
```

#### container

```yaml
event: sched_process_exec
filters:
    - container=66c2778945e29dfd36532d63c38c2ce4ed1
```

#### containerId

```yaml
event: sched_process_exec
filters:
    - containerId=66c2778945e29dfd36532d63c38c2ce4ed1
```

#### containerImage

```yaml
event: sched_process_exec
filters:
    - containerImage=ubuntu:latest
```

#### containerName  

```yaml
event: sched_process_exec
filters:
    - containerName=test
```

#### podName

```yaml
event: sched_process_exec
filters:
    - podName=daemonset/test
```

#### podNamespace

```yaml
event: sched_process_exec
filters:
    - podNamespace=production
```

#### podUid

```yaml
event: sched_process_exec
filters:
    - podUid=66c2778945e29dfd36532d63c38c2ce4ed16a002c44cb254b8e
```

        
## Data filter

Events contain data that can be filtered.

```yaml
apiVersion: tracker.khulnasoft.com/v1beta1
kind: Policy
metadata:
	name: sample-data-filter
	annotations:
		description: sample data filter
spec:
	scope:
	    - global
	rules:
	    event: security_file_open
	    filters:
		- data.pathname=/tmp*
```

Data fields can be found on the respective event definition, in this case [security_file_open](https://github.com/khulnasoft/tracker/blob/656eb976fbb66aba54c5f306019258e436d4814a/pkg/events/core.go#L11502-L11533) - be aware of possible changes to the definition linked above, so always check the main branch.

 Or the user can test the event output in CLI before defining a policy, e.g:

```console
tracker -e security_file_open --output json
```

```json
{"timestamp":1680182976364916505,"threadStartTime":1680179107675006774,"processorId":0,"processId":676,"cgroupId":5247,"threadId":676,"parentProcessId":1,"hostProcessId":676,"hostThreadId":676,"hostParentProcessId":1,"userId":131,"mountNamespace":4026532574,"pidNamespace":4026531836,"processName":"systemd-oomd","hostName":"josedonizetti-x","container":{},"kubernetes":{},"eventId":"730","eventName":"security_file_open","matchedPolicies":[""],"argsNum":6,"returnValue":0,"syscall":"openat","stackAddresses":null,"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"pathname","type":"const char*","value":"/proc/meminfo"},{"name":"flags","type":"string","value":"O_RDONLY|O_LARGEFILE"},{"name":"dev","type":"dev_t","value":45},{"name":"inode","type":"unsigned long","value":4026532041},{"name":"ctime","type":"unsigned long","value":1680179108391999988},{"name":"syscall_pathname","type":"const char*","value":"/proc/meminfo"}]}
```

## Return value filter

Return values can also be filtered.

```yaml
apiVersion: tracker.khulnasoft.com/v1beta1
kind: Policy
metadata:
	name: sample-return-value
	annotations:
		description: sample return value
spec:
	scope:
	    - global
	rules:
	    event: close
	    filters:
		- retval!=0
```
