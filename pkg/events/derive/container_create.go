package derive

import (
	"github.com/khulnasoft/tracker/pkg/cgroup"
	"github.com/khulnasoft/tracker/pkg/containers"
	"github.com/khulnasoft/tracker/pkg/errfmt"
	"github.com/khulnasoft/tracker/pkg/events"
	"github.com/khulnasoft/tracker/pkg/events/parse"
	"github.com/khulnasoft/tracker/pkg/logger"
	"github.com/khulnasoft/tracker/types/trace"
)

// ContainerCreate receives a containers as a closure argument to track it's containers.
// If it receives a cgroup_mkdir event, it can derive a container_create event from it.
func ContainerCreate(cts *containers.Containers) DeriveFunction {
	return deriveSingleEvent(events.ContainerCreate, deriveContainerCreateArgs(cts))
}

func deriveContainerCreateArgs(cts *containers.Containers) func(event trace.Event) ([]interface{}, error) {
	return func(event trace.Event) ([]interface{}, error) {
		// if cgroup_id is from non default hid (v1 case), the cgroup info query will fail, so we skip
		if check, err := isCgroupEventInHid(&event, cts); !check {
			return nil, errfmt.WrapError(err)
		}
		cgroupId, err := parse.ArgVal[uint64](event.Args, "cgroup_id")
		if err != nil {
			return nil, errfmt.WrapError(err)
		}
		if info := cts.GetCgroupInfo(cgroupId); info.ContainerRoot {
			logger.Debugw("derive container_create from cgroup", "cgroup_id", cgroupId, "container_id", info.Container.ContainerId)
			args := []interface{}{
				info.Runtime.String(),
				info.Container.ContainerId,
				info.Ctime.UnixNano(),
				info.Container.Image,
				info.Container.ImageDigest,
				info.Container.Name,
				info.Container.Pod.Name,
				info.Container.Pod.Namespace,
				info.Container.Pod.UID,
				info.Container.Pod.Sandbox,
			}
			return args, nil
		}
		return nil, nil
	}
}

// isCgroupEventInHid checks if cgroup event is relevant for deriving container event in its hierarchy id.
// in tracker we only care about containers inside the cpuset controller, as such other hierarchy ids will lead
// to a failed query.
func isCgroupEventInHid(event *trace.Event, cts *containers.Containers) (bool, error) {
	if cts.GetCgroupVersion() == cgroup.CgroupVersion2 {
		return true, nil
	}
	hierarchyID, err := parse.ArgVal[uint32](event.Args, "hierarchy_id")
	if err != nil {
		return false, errfmt.WrapError(err)
	}
	return cts.GetDefaultCgroupHierarchyID() == int(hierarchyID), nil
}
