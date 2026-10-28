package webhook

import (
	"fmt"
	"net/http"
	"strings"
)

// headerValues returns every non-empty value of the named header, with surrounding
// whitespace removed. The lookup ignores case, so it works for canonical http.Header
// keys as well as for hand-built maps with arbitrary casing.
func headerValues(h http.Header, name string) []string {
	var values []string
	for key, vs := range h {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, v := range vs {
			if v = strings.TrimSpace(v); v != "" {
				values = append(values, v)
			}
		}
	}
	return values
}

// singleHeader returns the value of a header that must occur exactly once. It
// returns ErrMissingHeader when the header is absent or empty, and ErrInvalidSignature
// when it carries conflicting values.
func singleHeader(h http.Header, name string) (string, error) {
	values := headerValues(h, name)
	if len(values) == 0 {
		return "", newError(ErrMissingHeader, name)
	}
	for _, other := range values[1:] {
		if other != values[0] {
			return "", newError(ErrInvalidSignature, fmt.Sprintf("%s has conflicting values", name))
		}
	}
	return values[0], nil
}

func errorf(format string, args ...any) error {
	return fmt.Errorf("webhook: "+format, args...)
}
