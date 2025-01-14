// Invoked tracker-ebpf events from user mode
//
// This utility can be useful to generate information needed by signatures that
// is not provided by normal events in the kernel.
//
// Because the events in the kernel are invoked by other programs behavior, we
// cannot anticipate which events will be invoked and as a result what
// information will be extracted.
//
// This is critical because tracker-rules is independent, and doesn't have to run
// on the same machine as tracker-ebpf. This means that tracker-rules might lack
// basic information of the operating machine needed for some signatures.
//
// By creating user mode events this information could be intentionally
// collected and passed to tracker-ebpf afterwards.
package events

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/khulnasof/tracker/pkg/containers/runtime"
	"github.com/khulnasof/tracker/pkg/logger"
	trackerversikhulnasof/trackerhulnasof/tracker/pkg/version"
	"github.com/khulnasof/trackkhulnasof/tracker
	"github.com/khulnasof/tracker/pkg/containers"
)

const InitProcNsDir = "/proc/1/ns"

// InitNamespacesEvent collect the init process namespaces and create event from
// them.
func InitNamespacesEvent() trace.Event {
	initNamespacesDef := Core.GetDefinitionByID(InitNamespaces)
	initNamespacesArgs := getInitNamespaceArguments()

	initNamespacesEvent := trace.Event{
		Timestamp:   int(time.Now().UnixNano()),
		ProcessName: "tracker-ebpf",
		EventID:     int(InitNamespaces),
		EventName:   initNamespacesDef.GetName(),
		ArgsNum:     len(initNamespacesArgs),
		Args:        initNamespacesArgs,
	}

	return initNamespacesEvent
}

// TrackerInfoEvent exports data related to Tracker's initialization
func TrackerInfoEvent(bootTime uint64, startTime uint64) trace.Event {
	def := Core.GetDefinitionByID(TrackerInfo)
	fields := def.GetFields()
	args := []trace.Argument{
		{ArgMeta: fields[0], Value: bootTime},
		{ArgMeta: fields[1], Value: startTime},
		{ArgMeta: fields[2], Value: trackerversion.GetVersion()},
	}

	trackerInfoEvent := trace.Event{
		Timestamp:   int(time.Now().UnixNano()),
		ProcessName: "tracker",
		EventID:     int(def.GetID()),
		EventName:   def.GetName(),
		ArgsNum:     len(args),
		Args:        args,
	}

	return trackerInfoEvent
}

// getInitNamespaceArguments fetches the namespaces of the init process and
// parse them into event arguments.
func getInitNamespaceArguments() []trace.Argument {
	initNamespaces := fetchInitNamespaces()
	eventDefinition := Core.GetDefinitionByID(InitNamespaces)
	initNamespacesArgs := make([]trace.Argument, len(eventDefinition.GetFields()))

	fields := eventDefinition.GetFields()

	for i, arg := range initNamespacesArgs {
		arg.ArgMeta = fields[i]
		arg.Value = initNamespaces[arg.Name]
		initNamespacesArgs[i] = arg
	}

	return initNamespacesArgs
}

// fetchInitNamespaces fetches the namespaces values from the /proc/1/ns
// directory
func fetchInitNamespaces() map[string]uint32 {
	var err error
	var namespacesLinks []os.DirEntry

	initNamespacesMap := make(map[string]uint32)
	namespaceValueReg := regexp.MustCompile(":[[[:digit:]]*]")

	namespacesLinks, err = os.ReadDir(InitProcNsDir)
	if err != nil {
		logger.Errorw("fetching init namespaces", "error", err)
	}
	for _, namespaceLink := range namespacesLinks {
		linkString, _ := os.Readlink(filepath.Join(InitProcNsDir, namespaceLink.Name()))
		trim := strings.Trim(namespaceValueReg.FindString(linkString), "[]:")
		namespaceNumber, _ := strconv.ParseUint(trim, 10, 32)
		initNamespacesMap[namespaceLink.Name()] = uint32(namespaceNumber)
	}

	return initNamespacesMap
}

// ExistingContainersEvents returns a list of events for each existing container
func ExistingContainersEvents(cts *containers.Containers, enrichDisabled bool) []trace.Event {
	var events []trace.Event

	def := Core.GetDefinitionByID(ExistingContainer)
	existingContainers := cts.GetContainers()
	for id, info := range existingContainers {
		cgroupId := uint64(id)
		cRuntime := info.Runtime.String()
		containerId := info.Container.ContainerId
		ctime := info.Ctime.UnixNano()
		container := runtime.ContainerMetadata{}
		if !enrichDisabled {
			container, _ = cts.EnrichCgroupInfo(cgroupId)
		}
		fields := def.GetFields()
		args := []trace.Argument{
			{ArgMeta: fields[0], Value: cRuntime},
			{ArgMeta: fields[1], Value: containerId},
			{ArgMeta: fields[2], Value: ctime},
			{ArgMeta: fields[3], Value: container.Image},
			{ArgMeta: fields[4], Value: container.ImageDigest},
			{ArgMeta: fields[5], Value: container.Name},
			{ArgMeta: fields[6], Value: container.Pod.Name},
			{ArgMeta: fields[7], Value: container.Pod.Namespace},
			{ArgMeta: fields[8], Value: container.Pod.UID},
			{ArgMeta: fields[9], Value: container.Pod.Sandbox},
		}
		existingContainerEvent := trace.Event{
			Timestamp:   int(time.Now().UnixNano()),
			ProcessName: "tracker-ebpf",
			EventID:     int(ExistingContainer),
			EventName:   def.GetName(),
			ArgsNum:     len(args),
			Args:        args,
		}
		events = append(events, existingContainerEvent)
	}

	return events
}
