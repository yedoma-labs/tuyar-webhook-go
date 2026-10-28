package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	whsecPrefix = "whsec_"

	headerStandardID        = "webhook-id"
	headerStandardTimestamp = "webhook-timestamp"
	headerStandardSignature = "webhook-signature"
	headerStripeSignature   = "Stripe-Signature"
	headerGitHubSignature   = "X-Hub-Signature-256"

	// futureBuffer is the largest clock skew accepted for a timestamp in the future.
	// The effective limit is the smaller of this value and the tolerance.
	futureBuffer = 30 * time.Second
)

// base64Std decodes standard padded base64.
var base64Std = base64.StdEncoding.Strict()

// verifyStandardWebhooks checks a Standard Webhooks signature over
// "<webhook-id>.<webhook-timestamp>.<body>". The signature check runs before the
// timestamp check, so an unauthenticated request learns nothing about its timestamp.
func verifyStandardWebhooks(body []byte, h http.Header, secret string, now time.Time, tolerance time.Duration) error {
	key, err := standardWebhooksKey(secret)
	if err != nil {
		return err
	}
	id, err := singleHeader(h, headerStandardID)
	if err != nil {
		return err
	}
	tsRaw, err := singleHeader(h, headerStandardTimestamp)
	if err != nil {
		return err
	}
	signatures := headerValues(h, headerStandardSignature)
	if len(signatures) == 0 {
		return newError(ErrMissingHeader, headerStandardSignature)
	}

	ts, ok := parseUnixSeconds(tsRaw)
	if !ok {
		return newError(ErrInvalidSignature, headerStandardTimestamp+" is not a Unix time in seconds")
	}

	var candidates [][]byte
	for _, value := range signatures {
		for _, entry := range strings.Fields(value) {
			encoded, found := strings.CutPrefix(entry, "v1,")
			if !found {
				continue
			}
			if sig, ok := decodeCanonicalBase64(encoded); ok {
				candidates = append(candidates, sig)
			}
		}
	}
	if len(candidates) == 0 {
		return newError(ErrInvalidSignature, "no v1 entry in "+headerStandardSignature)
	}

	expected := hmacSHA256(key, []byte(id+"."+tsRaw+"."), body)
	if !matchAny(expected, candidates) {
		return newError(ErrInvalidSignature, "")
	}
	return checkTimestamp(ts, now, tolerance)
}

// verifyStripe checks a Stripe signature over "<t>.<body>". Every v1 entry is
// tried, which supports secret rotation. v0 and other entries are ignored.
func verifyStripe(body []byte, h http.Header, secret string, now time.Time, tolerance time.Duration) error {
	if secret == "" {
		return newError(ErrMalformedSecret, "secret is empty")
	}
	values := headerValues(h, headerStripeSignature)
	if len(values) == 0 {
		return newError(ErrMissingHeader, headerStripeSignature)
	}

	var timestamps []string
	var candidates [][]byte
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			name, val, found := strings.Cut(part, "=")
			if !found {
				continue
			}
			name = strings.TrimSpace(name)
			val = strings.TrimSpace(val)
			switch name {
			case "t":
				timestamps = append(timestamps, val)
			case "v1":
				if sig, err := hex.DecodeString(val); err == nil {
					candidates = append(candidates, sig)
				}
			}
		}
	}
	if len(timestamps) == 0 || len(candidates) == 0 {
		return newError(ErrInvalidSignature, "Stripe-Signature needs a t and a v1 entry")
	}
	tsRaw := timestamps[0]
	for _, other := range timestamps[1:] {
		if other != tsRaw {
			return newError(ErrInvalidSignature, "Stripe-Signature has conflicting t entries")
		}
	}
	ts, ok := parseUnixSeconds(tsRaw)
	if !ok {
		return newError(ErrInvalidSignature, "t is not a Unix time in seconds")
	}

	expected := hmacSHA256([]byte(secret), []byte(tsRaw+"."), body)
	if !matchAny(expected, candidates) {
		return newError(ErrInvalidSignature, "")
	}
	return checkTimestamp(ts, now, tolerance)
}

// verifyGitHub checks an X-Hub-Signature-256 header over the raw body. GitHub
// sends no timestamp, so this check cannot detect replays.
func verifyGitHub(body []byte, h http.Header, secret string) error {
	if secret == "" {
		return newError(ErrMalformedSecret, "secret is empty")
	}
	values := headerValues(h, headerGitHubSignature)
	if len(values) == 0 {
		return newError(ErrMissingHeader, headerGitHubSignature)
	}

	var candidates [][]byte
	for _, value := range values {
		encoded, found := strings.CutPrefix(value, "sha256=")
		if !found {
			continue
		}
		if sig, err := hex.DecodeString(encoded); err == nil {
			candidates = append(candidates, sig)
		}
	}
	if len(candidates) == 0 {
		return newError(ErrInvalidSignature, "no sha256= entry in "+headerGitHubSignature)
	}

	expected := hmacSHA256([]byte(secret), body)
	if !matchAny(expected, candidates) {
		return newError(ErrInvalidSignature, "")
	}
	return nil
}

// verifyHMAC checks a generic HMAC-SHA256 over the raw body. The header may hold
// several signatures separated by commas or whitespace, each hex or base64.
func verifyHMAC(body []byte, h http.Header, secret, name string) error {
	if name == "" {
		return errorf("HMACHeader is required for the %s scheme", HMACSHA256)
	}
	if secret == "" {
		return newError(ErrMalformedSecret, "secret is empty")
	}
	values := headerValues(h, name)
	if len(values) == 0 {
		return newError(ErrMissingHeader, name)
	}

	var candidates [][]byte
	for _, value := range values {
		for _, entry := range strings.FieldsFunc(value, isSignatureSeparator) {
			if sig := decodeMAC(entry); sig != nil {
				candidates = append(candidates, sig)
			}
		}
	}
	if len(candidates) == 0 {
		return newError(ErrInvalidSignature, "no decodable signature in "+name)
	}

	expected := hmacSHA256([]byte(secret), body)
	if !matchAny(expected, candidates) {
		return newError(ErrInvalidSignature, "")
	}
	return nil
}

// standardWebhooksKey decodes the key from a "whsec_<base64>" secret.
func standardWebhooksKey(secret string) ([]byte, error) {
	encoded, found := strings.CutPrefix(secret, whsecPrefix)
	if !found {
		return nil, newError(ErrMalformedSecret, `expected the form whsec_<base64>`)
	}
	key, ok := decodeCanonicalBase64(encoded)
	if !ok || len(key) == 0 {
		return nil, newError(ErrMalformedSecret, `expected the form whsec_<base64> with a non-empty key`)
	}
	return key, nil
}

// checkTimestamp rejects timestamps older than tolerance, and timestamps in the
// future by more than the smaller of tolerance and futureBuffer. Infinity skips both checks.
func checkTimestamp(ts int64, now time.Time, tolerance time.Duration) error {
	if tolerance == Infinity {
		return nil
	}
	signed := time.Unix(ts, 0)
	if now.Sub(signed) > tolerance {
		return newError(ErrTimestampOutOfTolerance, "timestamp is too old")
	}
	if signed.Sub(now) > min(tolerance, futureBuffer) {
		return newError(ErrTimestampOutOfTolerance, "timestamp is in the future")
	}
	return nil
}

// hmacSHA256 computes HMAC-SHA256 over the concatenation of parts.
func hmacSHA256(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	return mac.Sum(nil)
}

// matchAny reports whether expected equals one of the candidates. It compares
// every candidate in constant time and never exits early, so the work does not
// depend on which entry matched.
func matchAny(expected []byte, candidates [][]byte) bool {
	matched := false
	for _, candidate := range candidates {
		if hmac.Equal(expected, candidate) {
			matched = true
		}
	}
	return matched
}

// decodeMAC decodes a SHA-256 digest that is either hex or base64 encoded. It
// returns nil for anything else.
func decodeMAC(entry string) []byte {
	if sig, err := hex.DecodeString(entry); err == nil && len(sig) == sha256.Size {
		return sig
	}
	if sig, ok := decodeCanonicalBase64(entry); ok && len(sig) == sha256.Size {
		return sig
	}
	return nil
}

// decodeCanonicalBase64 decodes standard padded base64 and rejects any input that
// does not re-encode to exactly itself, such as embedded newlines or missing padding.
func decodeCanonicalBase64(encoded string) ([]byte, bool) {
	decoded, err := base64Std.DecodeString(encoded)
	if err != nil || base64Std.EncodeToString(decoded) != encoded {
		return nil, false
	}
	return decoded, true
}

// parseUnixSeconds parses a string of ASCII digits as Unix seconds. Signs and
// whitespace are rejected.
func parseUnixSeconds(value string) (int64, bool) {
	if value == "" {
		return 0, false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil
}

func isSignatureSeparator(r rune) bool {
	return r == ',' || unicode.IsSpace(r)
}
