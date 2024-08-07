package main

import (
	"fmt"

	"github.com/khulnasoft/tracker/signatures/helpers"
	"github.com/khulnasoft/tracker/types/detect"
	"github.com/khulnasoft/tracker/types/protocol"
	"github.com/khulnasoft/tracker/types/trace"
)

type e2eHookedSyscall struct {
	cb detect.SignatureHandler
}

func (sig *e2eHookedSyscall) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eHookedSyscall) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "HOOKED_SYSCALL",
		EventName:   "HOOKED_SYSCALL",
		Version:     "0.1.0",
		Name:        "Hooked Syscall Test",
		Description: "Instrumentation events E2E Tests: Hooked Syscall",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eHookedSyscall) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracker", Name: "hooked_syscall"},
	}, nil
}

func (sig *e2eHookedSyscall) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "hooked_syscall":
		syscall, err := helpers.GetTrackerStringArgumentByName(eventObj, "syscall")
		if err != nil {
			return err
		}
		owner, err := helpers.GetTrackerStringArgumentByName(eventObj, "owner")
		if err != nil {
			return err
		}

		if syscall == "uname" && owner == "hijack" {
			m, _ := sig.GetMetadata()
			sig.cb(&detect.Finding{
				SigMetadata: m,
				Event:       event,
				Data:        map[string]interface{}{},
			})
		}
	}

	return nil
}

func (sig *e2eHookedSyscall) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eHookedSyscall) Close() {}
