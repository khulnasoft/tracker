package main

import (
	"fmt"
	"path"
	"strings"

	"github.com/khulnasoft/tracker/signatures/helpers"
	"github.com/khulnasoft/tracker/types/detect"
	"github.com/khulnasoft/tracker/types/protocol"
	"github.com/khulnasoft/tracker/types/trace"
)

type ScheduledTaskModification struct {
	cb           detect.SignatureHandler
	cronFiles    []string
	cronDirs     []string
	cronCommands []string
}

func (sig *ScheduledTaskModification) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.cronFiles = []string{"/etc/crontab", "/etc/anacrontab", "/etc/cron.deny", "/etc/cron.allow"}
	sig.cronDirs = []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.d", "/var/spool/cron/crontabs", "var/spool/anacron"}
	sig.cronCommands = []string{"crontab", "at", "batch", "launchd"}
	return nil
}

func (sig *ScheduledTaskModification) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-1027",
		Version:     "1",
		Name:        "Scheduled tasks modification detected",
		EventName:   "scheduled_task_mod",
		Description: "The task scheduling functionality or files were modified. Crontab schedules task execution or enables task execution at boot time. Adversaries may add or modify scheduled tasks in order to persist a reboot, thus maintaining malicious execution on the affected host.",
		Properties: map[string]interface{}{
			"Severity":             2,
			"Category":             "persistence",
			"Technique":            "Cron",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--2acf44aa-542f-4366-b4eb-55ef5747759c",
			"external_id":          "T1053.003",
		},
	}, nil
}

func (sig *ScheduledTaskModification) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracker", Name: "security_file_open", Origin: "*"},
		{Source: "tracker", Name: "security_inode_rename", Origin: "*"},
		{Source: "tracker", Name: "sched_process_exec", Origin: "*"},
	}, nil
}

func (sig *ScheduledTaskModification) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "security_file_open":
		pathname, err := helpers.GetTrackerStringArgumentByName(eventObj, "pathname")
		if err != nil {
			return err
		}

		flags, err := helpers.GetTrackerStringArgumentByName(eventObj, "flags")
		if err != nil {
			return err
		}

		if helpers.IsFileWrite(flags) {
			return sig.checkFileOrDir(event, pathname)
		}
	case "security_inode_rename":
		newPath, err := helpers.GetTrackerStringArgumentByName(eventObj, "new_path")
		if err != nil {
			return err
		}

		return sig.checkFileOrDir(event, newPath)
	case "sched_process_exec":
		pathname, err := helpers.GetTrackerStringArgumentByName(eventObj, "pathname")
		if err != nil {
			return err
		}
		basename := path.Base(pathname)

		for _, cronCommand := range sig.cronCommands {
			if basename == cronCommand {
				return sig.match(event)
			}
		}
	}

	return nil
}

func (sig *ScheduledTaskModification) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *ScheduledTaskModification) Close() {}

func (sig *ScheduledTaskModification) checkFileOrDir(event protocol.Event, pathname string) error {
	for _, cronFile := range sig.cronFiles {
		if pathname == cronFile {
			return sig.match(event)
		}
	}

	for _, cronDir := range sig.cronDirs {
		if strings.HasPrefix(pathname, cronDir) {
			return sig.match(event)
		}
	}

	return nil
}

func (sig *ScheduledTaskModification) match(event protocol.Event) error {
	metadata, err := sig.GetMetadata()
	if err != nil {
		return err
	}
	sig.cb(&detect.Finding{
		SigMetadata: metadata,
		Event:       event,
		Data:        nil,
	})

	return nil
}
