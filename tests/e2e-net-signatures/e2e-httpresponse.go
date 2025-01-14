package main

import (
	"fmt"
	"strings"

	"github.com/khulnasof/tracker/signatures/helpers"
	"github.com/khulnasof/tracker/types/detect"
	"github.com/khulnasof/tracker/types/protocol"
	"github.com/khulnasof/tracker/types/trace"
)

//
// HOWTO: The way to trigger this test signature is to execute:
//
//        curl google.com
//
//        This will cause it trigger once and reset it status.

type e2eHTTPResponse struct {
	cb detect.SignatureHandler
}

func (sig *e2eHTTPResponse) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *e2eHTTPResponse) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "HTTPResponse",
		EventName:   "HTTPResponse",
		Version:     "0.1.0",
		Name:        "Network HTTP Response Test",
		Description: "Network E2E Tests: HTTP Response",
		Tags:        []string{"e2e", "network"},
	}, nil
}

func (sig *e2eHTTPResponse) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracker", Name: "net_packet_http_response"},
	}, nil
}

func (sig *e2eHTTPResponse) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	if eventObj.EventName == "net_packet_http_response" {
		// validate tast context
		if eventObj.HostName == "" {
			return nil
		}

		httpResponse, err := helpers.GetProtoHTTPResponseByName(eventObj, "http_response")
		if err != nil {
			return err
		}

		if !strings.HasPrefix(httpResponse.Protocol, "HTTP/") {
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

func (sig *e2eHTTPResponse) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *e2eHTTPResponse) Close() {}
