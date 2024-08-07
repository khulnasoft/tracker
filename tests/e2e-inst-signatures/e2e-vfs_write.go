package main

import (
	"fmt"
	"strings"

	"github.com/khulnasoft/tracker/signatures/helpers"
	"github.com/khulnasoft/tracker/types/detect"
	"github.com/khulnasoft/tracker/types/protocol"
	"github.com/khulnasoft/tracker/types/trace"
)

type e2eVfsWrite struct {
	cb detect.SignatureHandler
}

func (sig *e2eVfsWrite) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eVfsWrite) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "VFS_WRITE",
		EventName:   "VFS_WRITE",
		Version:     "0.1.0",
		Name:        "Vfs Write Test",
		Description: "Instrumentation events E2E Tests: Vfs Write",
		Tags:        []string{"e2e", "instrumentation"},
	}, nil
}

func (sig *e2eVfsWrite) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracker", Name: "vfs_write"},
	}, nil
}

func (sig *e2eVfsWrite) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	switch eventObj.EventName {
	case "vfs_write":
		filePath, err := helpers.GetTrackerStringArgumentByName(eventObj, "pathname")
		if err != nil {
			return err
		}

		// check expected values from test for detection

		if !strings.HasSuffix(filePath, "/vfs_write.txt") {
			return nil
		}

		m, _ := sig.GetMetadata()

		sig.cb(&detect.Finding{
			SigMetadata: m,
			Event:       event,
			Data:        map[string]interface{}{},
		})
	}

	return nil
}

func (sig *e2eVfsWrite) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eVfsWrite) Close() {}
