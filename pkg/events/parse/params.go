package parse

import (
	"github.com/khulnasoft/tracker/pkg/errfmt"
	"github.com/khulnasoft/tracker/types/trace"
)

func ArgVal[T any](args []trace.Argument, argName string) (T, error) {
	for _, arg := range args {
		if arg.Name == argName {
			val, ok := arg.Value.(T)
			if !ok {
				zeroVal := *new(T)
				return zeroVal, errfmt.Errorf(
					"argument %s is not of type %T, is of type %T",
					argName,
					zeroVal,
					arg.Value,
				)
			}
			return val, nil
		}
	}
	return *new(T), errfmt.Errorf("argument %s not found", argName)
}
