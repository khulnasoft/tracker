package main

import (
	"fmt"

	"github.com/khulnasoft/tracker/signatures/helpers"
	"github.com/khulnasoft/tracker/types/detect"
	"github.com/khulnasoft/tracker/types/protocol"
	"github.com/khulnasoft/tracker/types/trace"
)

type DynamicCodeLoading struct {
	cb        detect.SignatureHandler
	alertText string
}

func (sig *DynamicCodeLoading) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.alertText = "Protection changed from W to E!"
	return nil
}

func (sig *DynamicCodeLoading) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-104",
		Version:     "1",
		Name:        "Dynamic code loading detected",
		EventName:   "dynamic_code_loading",
		Description: "Possible dynamic code loading was detected as the binary's memory is both writable and executable. Writing to an executable allocated memory region could be a technique used by adversaries to run code undetected and without dropping executables.",
		Properties: map[string]interface{}{
			"Severity":             2,
			"Category":             "defense-evasion",
			"Technique":            "Software Packing",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--deb98323-e13f-4b0c-8d94-175379069062",
			"external_id":          "T1027.002",
		},
	}, nil
}

func (sig *DynamicCodeLoading) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracker", Name: "mem_prot_alert", Origin: "*"},
	}, nil
}

func (sig *DynamicCodeLoading) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "mem_prot_alert":
		alert, err := helpers.GetTrackerStringArgumentByName(eventObj, "alert")
		if err != nil {
			return err
		}

		if alert == sig.alertText {
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

func (sig *DynamicCodeLoading) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *DynamicCodeLoading) Close() {}
