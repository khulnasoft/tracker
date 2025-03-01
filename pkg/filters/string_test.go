package filters

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft/tracker/pkg/filters/sets"
)

func TestStringFilterParse(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		expressions []string
		vals        []string
		expected    []bool
		expectedErr error
	}{
		{
			name: "normal case - only equality",
			expressions: []string{
				"=abc,abcd",
			},
			vals:     []string{"abc", "abcd", "abcde", "aaaaaa"},
			expected: []bool{true, true, false, false},
		},
		{
			name: "normal case - only non equals",
			expressions: []string{
				"!=abc,abcd",
			},
			vals:     []string{"abc", "abcd", "abcde", "aaaaaa"},
			expected: []bool{false, false, true, true},
		},
		{
			name: "conflict - same equal and not equal",
			expressions: []string{
				"!=abc,abcd",
				"=abc",
			},
			vals:     []string{"abc", "abcd", "abcde", "aaaaaa"},
			expected: []bool{true, false, true, true},
		},
		{
			name: "real example - from signature filters",
			expressions: []string{
				"!=flanneld,kube-proxy,etcd,kube-apiserver,coredns,kube-controller,kubectl",
				"=kube-apiserver,kubelet,kube-controller,etcd",
			},
			vals:     []string{"flanneld", "kube-proxy", "etcd", "kube-apiserver", "coredns", "kube-controller", "kubectl", "kubelet", "bruh"},
			expected: []bool{false, false, true, true, false, true, false, true, true},
		},
		{
			name: "real example - test prefix, suffix and contains",
			expressions: []string{
				"=*/release_agent,/etc/kubernetes/pki/*,*secrets/kubernetes.io/serviceaccount*,*token,/etc/ld.so.preload",
			},
			vals: []string{
				"xd/bruh/release_agent",
				"/etc/kubernetes/pki/true",
				"/nottrue/etc/kubernetes/pki/",
				"anythingheresecrets/kubernetes.io/serviceaccountanythingthere",
				"secrets/kubernetes.io/serviceaccount",
				"secrets/notkubernetes.io/serviceaccount",
				"token",
				"something_token",
				"token_withsomething",
				"/etc/ld.so.preload",
				"/etc/ld.so..preload",
			},
			expected: []bool{true, true, false, true, true, false, true, true, false, true, false},
		},
		{
			name: "real  example - security_bprm_check",
			expressions: []string{
				"=mysqld*,postgres*,sqlplus*,couchdb*,memcached*,redis-server*,rabbitmq-server*,mongod*,runc:[2:INIT],nginx*,httpd*,httpd-foregroun*,http-nio*,lighttpd*,apache*,apache2*,runc:*",
				"!=runc*,containerd*,(kubelet)",
			},
			vals: []string{
				"reality", "can", "be", "whatever", "i", "want", "containerd-nothis", "(kubelet)", "runc:[2:INIT]", "runc-else",
			},
			expected: []bool{true, true, true, true, true, true, false, false, true, false},
		},
		{
			name: "error - unsupported operator Greater",
			expressions: []string{
				">*/release_agent,/etc/kubernetes/pki/*,*secrets/kubernetes.io/serviceaccount*,*token,/etc/ld.so.preload",
			},
			expectedErr: UnsupportedOperator(Greater),
		},
		{
			name: "error - equal double wildcard",
			expressions: []string{
				"=**",
			},
			expected:    []bool{},
			expectedErr: InvalidValue("**"),
		},
		{
			name: "error - equal single wildcard",
			expressions: []string{
				"=*",
			},
			expected:    []bool{},
			expectedErr: InvalidValue("*"),
		},
		{
			name: "error - not equal double wildcard",
			expressions: []string{
				"!=**",
			},
			expected:    []bool{},
			expectedErr: InvalidValue("**"),
		},
		{
			name: "error - not equal single wildcard",
			expressions: []string{
				"!=*",
			},
			expected:    []bool{},
			expectedErr: InvalidValue("*"),
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			filter := NewStringFilter(nil)
			for _, expr := range tc.expressions {
				err := filter.Parse(expr)
				if tc.expectedErr != nil {
					assert.ErrorContains(t, err, tc.expectedErr.Error())
				}
			}
			if tc.expectedErr == nil {
				result := make([]bool, len(tc.vals))
				for i, val := range tc.vals {
					result[i] = filter.Filter(val)
				}
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestStringFilterMatchIfKeyMissing(t *testing.T) {
	t.Parallel()

	sf1 := NewStringFilter(nil)

	err := sf1.Parse("=some")
	require.NoError(t, err)
	err = sf1.Parse("=word")
	require.NoError(t, err)
	err = sf1.Parse("=here")
	require.NoError(t, err)

	assert.False(t, sf1.MatchIfKeyMissing())

	sf2 := NewStringFilter(nil)

	err = sf2.Parse("=some")
	require.NoError(t, err)
	err = sf2.Parse("!=word")
	require.NoError(t, err)
	err = sf2.Parse("=here")
	require.NoError(t, err)

	assert.True(t, sf2.MatchIfKeyMissing())

	sf3 := NewStringFilter(nil)

	err = sf3.Parse("!=some")
	require.NoError(t, err)
	err = sf3.Parse("=word")
	require.NoError(t, err)
	err = sf3.Parse("!=here")
	require.NoError(t, err)

	assert.True(t, sf3.MatchIfKeyMissing())

	sf4 := NewStringFilter(nil)

	err = sf4.Parse("!=some")
	require.NoError(t, err)
	err = sf4.Parse("!=word")
	require.NoError(t, err)
	err = sf4.Parse("!=here")
	require.NoError(t, err)

	assert.True(t, sf4.MatchIfKeyMissing())
}

func TestStringFilterClone(t *testing.T) {
	t.Parallel()

	valueHandler := func(val string) (string, error) {
		return val, nil
	}

	filter := NewStringFilter(valueHandler)
	err := filter.Parse("=abc,abcd")
	assert.NoError(t, err)
	err = filter.Parse("!=abc")
	assert.NoError(t, err)

	copy := filter.Clone()

	opt1 := cmp.AllowUnexported(
		StringFilter{},
		sets.PrefixSet{},
		sets.SuffixSet{},
	)
	opt2 := cmp.FilterPath(
		func(p cmp.Path) bool {
			// ignore the function field
			// https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/reflect/deepequal.go;l=187
			return p.Last().Type().Kind() == reflect.Func
		},
		cmp.Ignore(),
	)

	if !cmp.Equal(filter, copy, opt1, opt2) {
		diff := cmp.Diff(filter, copy, opt1, opt2)
		t.Errorf("Clone did not produce an identical copy\ndiff: %s", diff)
	}

	// ensure that changes to the copy do not affect the original
	copy.Parse("=xyz")
	if cmp.Equal(filter, copy, opt1, opt2) {
		t.Errorf("Changes to copied filter affected the original")
	}
}
