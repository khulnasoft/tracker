package main

import (
	"fmt"

	"github.com/khulnasoft/tracker/signatures/helpers"
	"github.com/khulnasoft/tracker/types/detect"
	"github.com/khulnasoft/tracker/types/protocol"
	"github.com/khulnasoft/tracker/types/trace"
)

type FilelessExecution struct {
	cb detect.SignatureHandler
}

func (sig *FilelessExecution) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *FilelessExecution) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-105",
		Version:     "1",
		Name:        "Fileless execution detected",
		EventName:   "fileless_execution",
		Description: "Fileless execution was detected. Executing a process from memory instead from a file in the filesystem may indicate that an adversary is trying to avoid execution detection.",
		Properties: map[string]interface{}{
			"Severity":             3,
			"Category":             "defense-evasion",
			"Technique":            "Reflective Code Loading",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--4933e63b-9b77-476e-ab29-761bc5b7d15a",
			"external_id":          "T1620",
		},
	}, nil
}

func (sig *FilelessExecution) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracker", Name: "sched_process_exec", Origin: "*"},
	}, nil
}

func (sig *FilelessExecution) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "sched_process_exec":
		pathname, err := helpers.GetTrackerStringArgumentByName(eventObj, "pathname")
		if err != nil {
			return err
		}

		if helpers.IsMemoryPath(pathname) {
			metadata, err := sig.GetMetadata()
			if err != nil {
				return err
			}
			sig.cb(&detect.Finding{
				SigMetadata: metadata,
				Event:       event,
				Data:        nil,
			})
		}
	}

	return nil
}

func (sig *FilelessExecution) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *FilelessExecution) Close() {}
