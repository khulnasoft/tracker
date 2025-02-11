package flags

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/khulnasoft/tracker/pkg/config"
)

func TestPrepareTrackerEbpfOutput(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		testName       string
		outputSlice    []string
		expectedOutput PrepareOutputResult
		expectedError  error
	}{
		{
			testName:    "invalid output option",
			outputSlice: []string{"foo"},
			// it's not the preparer job to validate input. in this case foo is considered an implicit output format.
			expectedError: errors.New("unrecognized output format: foo. Valid format values: 'table', 'table-verbose', 'json', or 'gotemplate='. Use '--output help' for more info"),
		},
		{
			testName:      "invalid output option",
			outputSlice:   []string{"option:"},
			expectedError: errors.New("invalid output option: , use '--output help' for more info"),
		},
		{
			testName:      "invalid output option 2",
			outputSlice:   []string{"option:foo"},
			expectedError: errors.New("invalid output option: foo, use '--output help' for more info"),
		},
		{
			testName:      "empty val",
			outputSlice:   []string{"out-file"},
			expectedError: errors.New("unrecognized output format: out-file. Valid format values: 'table', 'table-verbose', 'json', or 'gotemplate='. Use '--output help' for more info"),
		},
		{
			testName:    "default format",
			outputSlice: []string{},
			expectedOutput: PrepareOutputResult{
				TrackerConfig: &config.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "table format always parse arguments",
			outputSlice: []string{"table"},
			expectedOutput: PrepareOutputResult{
				TrackerConfig: &config.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option stack-addresses",
			outputSlice: []string{"option:stack-addresses"},
			expectedOutput: PrepareOutputResult{
				TrackerConfig: &config.OutputConfig{
					StackAddresses: true,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option exec-env",
			outputSlice: []string{"option:exec-env"},
			expectedOutput: PrepareOutputResult{
				TrackerConfig: &config.OutputConfig{
					ExecEnv:        true,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option exec-hash=inode",
			outputSlice: []string{"option:exec-hash=inode"},
			expectedOutput: PrepareOutputResult{
				TrackerConfig: &config.OutputConfig{
					CalcHashes:     config.CalcHashesInode,
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option parse-arguments",
			outputSlice: []string{"json", "option:parse-arguments"},
			expectedOutput: PrepareOutputResult{
				TrackerConfig: &config.OutputConfig{
					ParseArguments: true,
				},
			},
		},
		{
			testName:    "option parse-arguments-fds",
			outputSlice: []string{"json", "option:parse-arguments-fds"},
			expectedOutput: PrepareOutputResult{
				TrackerConfig: &config.OutputConfig{
					ParseArguments:    true,
					ParseArgumentsFDs: true,
				},
			},
		},
		{
			testName:    "option sort-events",
			outputSlice: []string{"option:sort-events"},
			expectedOutput: PrepareOutputResult{
				TrackerConfig: &config.OutputConfig{
					ParseArguments: true,
					EventsSorting:  true,
				},
			},
		},
		{
			testName: "all options",
			outputSlice: []string{
				"json",
				"option:stack-addresses",
				"option:exec-env",
				"option:exec-hash=none",
				"option:parse-arguments",
				"option:parse-arguments-fds",
				"option:sort-events",
			},
			expectedOutput: PrepareOutputResult{
				TrackerConfig: &config.OutputConfig{
					StackAddresses:    true,
					ExecEnv:           true,
					CalcHashes:        config.CalcHashesNone,
					ParseArguments:    true,
					ParseArgumentsFDs: true,
					EventsSorting:     true,
				},
			},
		},
	}
	for _, testcase := range testCases {
		testcase := testcase

		t.Run(testcase.testName, func(t *testing.T) {
			t.Parallel()

			output, err := TrackerEbpfPrepareOutput(testcase.outputSlice, false)
			if err != nil {
				assert.ErrorContains(t, err, testcase.expectedError.Error())
			} else {
				assert.Equal(t, testcase.expectedOutput.TrackerConfig, output.TrackerConfig)
			}
		})
	}
}
