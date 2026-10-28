// Package webhook verifies webhook signatures against the raw request body.
//
// It supports the Standard Webhooks, Stripe, GitHub and generic HMAC-SHA256
// signature schemes and uses only the standard library. Verification must run
// on the exact bytes that arrived on the wire: parsing or re-serializing the
// body before the check makes a genuine signature fail.
package webhook

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"
)

// Scheme selects the signature scheme used by Verify.
type Scheme string

const (
	// StandardWebhooks verifies the Standard Webhooks specification
	// (webhook-id, webhook-timestamp and webhook-signature headers).
	StandardWebhooks Scheme = "standard-webhooks"

	// Stripe verifies the Stripe-Signature header ("t=<unix>,v1=<hex>,...").
	Stripe Scheme = "stripe"

	// GitHub verifies the X-Hub-Signature-256 header ("sha256=<hex>").
	// GitHub sends no timestamp, so the scheme offers no replay protection.
	GitHub Scheme = "github"

	// HMACSHA256 verifies a generic HMAC-SHA256 signature found in the header
	// named by Options.HMACHeader. The value may be hex or base64 encoded.
	HMACSHA256 Scheme = "hmac-sha256"
)

// DefaultTolerance is the replay window used when Options.Tolerance is zero.
const DefaultTolerance = 5 * time.Minute

// Infinity disables the timestamp window for StandardWebhooks and Stripe.
// Zero never disables it; only this explicit value does.
const Infinity time.Duration = math.MaxInt64

// Options configures Verify.
type Options struct {
	// Scheme selects the signature scheme. It is required.
	Scheme Scheme

	// Secret is the shared signing secret. StandardWebhooks expects the form
	// "whsec_<base64>". The other schemes use the value as UTF-8 bytes.
	Secret string

	// Tolerance is the maximum distance between the signed timestamp and the
	// current time, in either direction. Zero selects DefaultTolerance, and
	// Infinity disables the window. It applies to StandardWebhooks and Stripe.
	Tolerance time.Duration

	// Now returns the current time. Nil selects time.Now.
	Now func() time.Time

	// HMACHeader names the header that carries the signature. It is required
	// for HMACSHA256 and ignored by the other schemes.
	HMACHeader string
}

// Verify checks the signature of body against headers using opts.
//
// body must be the raw request body exactly as received. headers may be a
// header map with any key casing. Verify returns nil when the signature
// matches and the timestamp (if the scheme has one) is within the tolerance.
//
// Verification failures return an *Error whose Kind is one of the Err
// sentinels. Invalid options return a plain error.
func Verify(body []byte, headers http.Header, opts Options) error {
	tolerance, err := opts.tolerance()
	if err != nil {
		return err
	}

	switch opts.Scheme {
	case StandardWebhooks:
		return verifyStandardWebhooks(body, headers, opts.Secret, opts.now(), tolerance)
	case Stripe:
		return verifyStripe(body, headers, opts.Secret, opts.now(), tolerance)
	case GitHub:
		return verifyGitHub(body, headers, opts.Secret)
	case HMACSHA256:
		return verifyHMAC(body, headers, opts.Secret, opts.HMACHeader)
	default:
		return newError(ErrUnsupportedScheme, fmt.Sprintf("scheme %q", string(opts.Scheme)))
	}
}

// tolerance returns the effective replay window.
func (o Options) tolerance() (time.Duration, error) {
	switch {
	case o.Tolerance == 0:
		return DefaultTolerance, nil
	case o.Tolerance < 0:
		return 0, errors.New("webhook: Tolerance must not be negative")
	default:
		return o.Tolerance, nil
	}
}

// now returns the current time from Now, or from time.Now when Now is nil.
func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}
