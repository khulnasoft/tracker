package main

import (
	"fmt"
	"regexp"

	"github.com/khulnasoft/tracker/signatures/helpers"
	"github.com/khulnasoft/tracker/types/detect"
	"github.com/khulnasoft/tracker/types/protocol"
	"github.com/khulnasoft/tracker/types/trace"
)

type ProcMemAccess struct {
	cb                 detect.SignatureHandler
	procMemPathPattern string
	compiledRegex      *regexp.Regexp
}

func (sig *ProcMemAccess) Init(ctx detect.SignatureContext) error {
	var err error
	sig.cb = ctx.Callback
	sig.procMemPathPattern = `/proc/(?:\d.+)/mem$`
	sig.compiledRegex, err = regexp.Compile(sig.procMemPathPattern)
	return err
}

func (sig *ProcMemAccess) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-1023",
		Version:     "1",
		Name:        "Process memory access detected",
		EventName:   "proc_mem_access",
		Description: "Process memory access detected. Adversaries may access other processes memory to steal credentials and secrets.",
		Properties: map[string]interface{}{
			"Severity":             3,
			"Category":             "credential-access",
			"Technique":            "Proc Filesystem",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--3120b9fa-23b8-4500-ae73-09494f607b7d",
			"external_id":          "T1003.007",
		},
	}, nil
}

func (sig *ProcMemAccess) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracker", Name: "security_file_open", Origin: "*"},
	}, nil
}

func (sig *ProcMemAccess) OnEvent(event protocol.Event) error {
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

		if helpers.IsFileRead(flags) && sig.compiledRegex.MatchString(pathname) {
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

func (sig *ProcMemAccess) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *ProcMemAccess) Close() {}
