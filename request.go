package webhook

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// VerifyRequest reads the body of r, verifies it with Verify, and then restores
// r.Body so that a handler can read the same bytes again.
//
// It returns the raw body. Check err before using the body: the body is returned
// even when verification fails, so that it can be logged. Callers should wrap
// r.Body with http.MaxBytesReader beforehand to bound how much is read.
func VerifyRequest(r *http.Request, opts Options) ([]byte, error) {
	if r == nil {
		return nil, errors.New("webhook: nil request")
	}

	var body []byte
	if r.Body != nil {
		var readErr error
		body, readErr = io.ReadAll(r.Body)
		// The server owns the original body and closes it. It is replaced below.
		_ = r.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("webhook: read request body: %w", readErr)
		}
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	return body, Verify(body, r.Header, opts)
}
