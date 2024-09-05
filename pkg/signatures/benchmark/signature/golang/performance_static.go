package golang

import (
	"fmt"
	"regexp"

	"github.com/khulnasoft/tracker/signatures/helpers"
	"github.com/khulnasoft/tracker/types/detect"
	"github.com/khulnasoft/tracker/types/protocol"
	"github.com/khulnasoft/tracker/types/trace"
)

type performanceStatic struct {
	processMemFileRegexp *regexp.Regexp
	cb                   detect.SignatureHandler
}

var performanceStaticRegexp = regexp.MustCompile(`^/proc/(?:\d+|self)/mem$`)

var performanceStaticMetadata = detect.SignatureMetadata{
	Name:        "Code injection",
	EventName:   "test_event_name",
	Description: "Possible process injection detected during runtime",
	Tags:        []string{"linux", "container"},
	Properties: map[string]interface{}{
		"Severity":     3,
		"MITRE ATT&CK": "Defense Evasion: Process Injection",
	},
}

func NewPerformanceStatic() (detect.Signature, error) {
	return &performanceStatic{
		processMemFileRegexp: performanceStaticRegexp,
	}, nil
}

func (sig *performanceStatic) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback

	return nil
}

func (sig *performanceStatic) GetMetadata() (detect.SignatureMetadata, error) {
	return performanceStaticMetadata, nil
}

func (sig *performanceStatic) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracker", Name: "ptrace"},
		{Source: "tracker", Name: "open"},
		{Source: "tracker", Name: "openat"},
		{Source: "tracker", Name: "execve"},
	}, nil
}

func (sig *performanceStatic) OnEvent(event protocol.Event) error {
	// event example:
	// { "eventName": "ptrace", "args": [{"name": "request", "value": "PTRACE_POKETEXT" }]}
	// { "eventName": "open", "args": [{"name": "flags", "value": "o_wronly" }, {"name": "pathname", "value": "/proc/self/mem" }]}
	// { "eventName": "execve" args": [{"name": "envp", "value": ["FOO=BAR", "LD_PRELOAD=/something"] }, {"name": "argv", "value": ["ls"] }]}
	ee, ok := event.Payload.(trace.Event)

	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}
	switch ee.EventName {
	case "open", "openat":
		flags, err := helpers.GetTrackerArgumentByName(ee, "flags", helpers.GetArgOps{DefaultArgs: false})
		if err != nil {
			return fmt.Errorf("%v %#v", err, ee)
		}
		if helpers.IsFileWrite(flags.Value.(string)) {
			pathname, err := helpers.GetTrackerArgumentByName(ee, "pathname", helpers.GetArgOps{DefaultArgs: false})
			if err != nil {
				return err
			}
			if sig.processMemFileRegexp.MatchString(pathname.Value.(string)) {
				metadata, err := sig.GetMetadata()
				if err != nil {
					return err
				}
				sig.cb(&detect.Finding{
					SigMetadata: metadata,
					Event:       event,
					Data: map[string]interface{}{
						"file flags": flags,
						"file path":  pathname.Value.(string),
					},
				})
			}
		}
	case "ptrace":
		request, err := helpers.GetTrackerArgumentByName(ee, "request", helpers.GetArgOps{DefaultArgs: false})
		if err != nil {
			return err
		}

		requestString, ok := request.Value.(string)
		if !ok {
			return fmt.Errorf("failed to cast request's value")
		}

		if requestString == "PTRACE_POKETEXT" || requestString == "PTRACE_POKEDATA" {
			metadata, err := sig.GetMetadata()
			if err != nil {
				return err
			}
			sig.cb(&detect.Finding{
				SigMetadata: metadata,
				Event:       event,
				Data: map[string]interface{}{
					"ptrace request": requestString,
				},
			})
		}
	}
	return nil
}

func (sig *performanceStatic) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *performanceStatic) Close() {}
