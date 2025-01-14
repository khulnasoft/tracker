package cobra

import (
	"github.com/khulnasof/tracker/pkg/cmd/flags"
	k8s "github.com/khulnasof/tracker/pkg/k8s/apis/tracker.khulnasoft.com/v1beta1"
	"github.com/khulnasof/tracker/pkg/policy"
	"github.com/khulnasof/tracker/pkg/policy/v1beta1"
)

func createPoliciesFromK8SPolicy(policies []k8s.PolicyInterface) ([]*policy.Policy, error) {
	policyScopeMap, policyEventsMap, err := flags.PrepareFilterMapsFromPolicies(policies)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventsMap, true)
}

func createPoliciesFromPolicyFiles(policyFlags []string) ([]*policy.Policy, error) {
	policyFiles, err := v1beta1.PoliciesFromPaths(policyFlags)
	if err != nil {
		return nil, err
	}

	policyScopeMap, policyEventsMap, err := flags.PrepareFilterMapsFromPolicies(policyFiles)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventsMap, true)
}

func createPoliciesFromCLIFlags(scopeFlags, eventFlags []string) ([]*policy.Policy, error) {
	policyScopeMap, err := flags.PrepareScopeMapFromFlags(scopeFlags)
	if err != nil {
		return nil, err
	}

	policyEventsMap, err := flags.PrepareEventMapFromFlags(eventFlags)
	if err != nil {
		return nil, err
	}

	return flags.CreatePolicies(policyScopeMap, policyEventsMap, true)
}
