package webhook

import "errors"

// Sentinel errors that identify the failure kind of an *Error. Use errors.Is to
// test for them.
var (
	// ErrMissingHeader means a required signature header is absent or empty.
	ErrMissingHeader = errors.New("missing header")

	// ErrInvalidSignature means no signature matches, or the signature data is malformed.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrTimestampOutOfTolerance means the signed timestamp is too old or too far in the future.
	ErrTimestampOutOfTolerance = errors.New("timestamp outside tolerance")

	// ErrMalformedSecret means the secret does not match the format of the scheme.
	ErrMalformedSecret = errors.New("malformed secret")

	// ErrUnsupportedScheme means the scheme is unknown.
	ErrUnsupportedScheme = errors.New("unsupported scheme")
)

// Error is returned by Verify and VerifyRequest when a request cannot be verified.
//
// Kind is one of the Err sentinels and is also reachable through errors.Is.
// The message never contains the secret or any signature bytes.
type Error struct {
	// Kind is the failure category, one of the Err sentinels.
	Kind error

	// Detail adds context that is safe to log, such as the header name.
	Detail string
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Detail == "" {
		return "webhook: " + e.Kind.Error()
	}
	return "webhook: " + e.Kind.Error() + ": " + e.Detail
}

// Unwrap returns the Kind sentinel so that errors.Is matches it.
func (e *Error) Unwrap() error {
	return e.Kind
}

func newError(kind error, detail string) *Error {
	return &Error{Kind: kind, Detail: detail}
}
