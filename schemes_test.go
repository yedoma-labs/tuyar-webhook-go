package webhook_test

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	webhook "github.com/yedoma-labs/tuyar-webhook-go"
)

const (
	yearSeconds = 365 * 24 * 60 * 60
	fakeSigV1   = "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

// swSecretFor returns a Standard Webhooks secret whose key is the given bytes.
func swSecretFor(key string) string {
	return "whsec_" + base64.StdEncoding.EncodeToString([]byte(key))
}

func TestStandardWebhooks(t *testing.T) {
	const id = "msg_42"
	ts := strconv.FormatInt(testUnix, 10)
	valid := swSignature(testSecretSW, id, ts, testBody)
	signedSpaced := `{"id": "evt_1", "type": "ping"}`

	tests := []struct {
		name      string
		headers   http.Header
		body      string
		now       time.Time
		tolerance time.Duration
		wantErr   error
	}{
		{name: "valid signature", headers: swHeaders(id, ts, valid), body: testBody},
		{
			name:    "wrong signature bytes",
			headers: swHeaders(id, ts, fakeSigV1),
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "signed with another secret",
			headers: swHeaders(id, ts, swSignature(swSecretFor("other-key"), id, ts, testBody)),
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "tampered body",
			headers: swHeaders(id, ts, valid),
			body:    testBody + " ",
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "re-serialized JSON body fails",
			headers: swHeaders(id, ts, swSignature(testSecretSW, id, ts, signedSpaced)),
			body:    testBody, // compact form of the same JSON, as json.Marshal would produce
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "timestamp header changed after signing",
			headers: swHeaders(id, strconv.FormatInt(testUnix+1, 10), valid),
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "id header changed after signing",
			headers: swHeaders("msg_43", ts, valid),
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "non-numeric timestamp",
			headers: swHeaders(id, "17000x0000", valid),
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "timestamp with plus sign",
			headers: swHeaders(id, "+"+ts, swSignature(testSecretSW, id, "+"+ts, testBody)),
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "non-canonical base64 signature (no padding)",
			headers: swHeaders(id, ts, strings.TrimRight(valid, "=")),
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "only a v2 entry",
			headers: swHeaders(id, ts, strings.Replace(valid, "v1,", "v2,", 1)),
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "only an undecodable v1 entry",
			headers: swHeaders(id, ts, "v1,!!!"),
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "rotation: stale entry first, valid entry second",
			headers: swHeaders(id, ts, fakeSigV1+" "+valid),
			body:    testBody,
		},
		{
			name:    "rotation: valid entry first, unknown entries after",
			headers: swHeaders(id, ts, valid+" "+fakeSigV1),
			body:    testBody,
		},
		{
			name:    "timestamp 299s old is accepted",
			headers: swHeaders(id, strconv.FormatInt(testUnix-299, 10), swSignature(testSecretSW, id, strconv.FormatInt(testUnix-299, 10), testBody)),
			body:    testBody,
		},
		{
			name:    "timestamp 301s old is rejected",
			headers: swHeaders(id, strconv.FormatInt(testUnix-301, 10), swSignature(testSecretSW, id, strconv.FormatInt(testUnix-301, 10), testBody)),
			body:    testBody,
			wantErr: webhook.ErrTimestampOutOfTolerance,
		},
		{
			name:    "timestamp 301s in the future is rejected",
			headers: swHeaders(id, strconv.FormatInt(testUnix+301, 10), swSignature(testSecretSW, id, strconv.FormatInt(testUnix+301, 10), testBody)),
			body:    testBody,
			wantErr: webhook.ErrTimestampOutOfTolerance,
		},
		{
			name:    "timestamp 30s in the future is within the buffer",
			headers: swHeaders(id, strconv.FormatInt(testUnix+30, 10), swSignature(testSecretSW, id, strconv.FormatInt(testUnix+30, 10), testBody)),
			body:    testBody,
		},
		{
			name:    "timestamp 31s in the future is rejected",
			headers: swHeaders(id, strconv.FormatInt(testUnix+31, 10), swSignature(testSecretSW, id, strconv.FormatInt(testUnix+31, 10), testBody)),
			body:    testBody,
			wantErr: webhook.ErrTimestampOutOfTolerance,
		},
		{
			name:      "custom tolerance accepts 10 minute old timestamp",
			headers:   swHeaders(id, strconv.FormatInt(testUnix-600, 10), swSignature(testSecretSW, id, strconv.FormatInt(testUnix-600, 10), testBody)),
			body:      testBody,
			tolerance: 15 * time.Minute,
		},
		{
			name:      "custom tolerance rejects 10 minute old timestamp",
			headers:   swHeaders(id, strconv.FormatInt(testUnix-600, 10), swSignature(testSecretSW, id, strconv.FormatInt(testUnix-600, 10), testBody)),
			body:      testBody,
			tolerance: time.Minute,
			wantErr:   webhook.ErrTimestampOutOfTolerance,
		},
		{
			name:    "missing webhook-id",
			headers: withoutHeader(swHeaders(id, ts, valid), "webhook-id"),
			body:    testBody,
			wantErr: webhook.ErrMissingHeader,
		},
		{
			name:    "missing webhook-timestamp",
			headers: withoutHeader(swHeaders(id, ts, valid), "webhook-timestamp"),
			body:    testBody,
			wantErr: webhook.ErrMissingHeader,
		},
		{
			name:    "missing webhook-signature",
			headers: withoutHeader(swHeaders(id, ts, valid), "webhook-signature"),
			body:    testBody,
			wantErr: webhook.ErrMissingHeader,
		},
		{
			name:    "empty webhook-id",
			headers: swHeaders("   ", ts, valid),
			body:    testBody,
			wantErr: webhook.ErrMissingHeader,
		},
		{
			name: "lowercase keys in a hand-built map",
			headers: http.Header{
				"webhook-id":        {id},
				"webhook-timestamp": {ts},
				"webhook-signature": {valid},
			},
			body: testBody,
		},
		{
			name: "uppercase keys in a hand-built map",
			headers: http.Header{
				"WEBHOOK-ID":        {id},
				"WEBHOOK-TIMESTAMP": {ts},
				"WEBHOOK-SIGNATURE": {valid},
			},
			body: testBody,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := tc.now
			if now.IsZero() {
				now = testNow
			}
			err := webhook.Verify([]byte(tc.body), tc.headers, webhook.Options{
				Scheme:    webhook.StandardWebhooks,
				Secret:    testSecretSW,
				Tolerance: tc.tolerance,
				Now:       nowAt(now),
			})
			assertErr(t, err, tc.wantErr)
		})
	}
}

func TestStandardWebhooksMalformedSecret(t *testing.T) {
	const id = "msg_42"
	ts := strconv.FormatInt(testUnix, 10)
	headers := swHeaders(id, ts, swSignature(testSecretSW, id, ts, testBody))

	tests := []struct {
		name   string
		secret string
	}{
		{"empty secret", ""},
		{"missing whsec_ prefix", "standard-key-bytes"},
		{"prefix only", "whsec_"},
		{"invalid base64 characters", "whsec_not base64!"},
		{"non-canonical base64 (no padding)", "whsec_c3RhbmRhcmQ"},
		{"trailing newline after the key", testSecretSW + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := webhook.Verify([]byte(testBody), headers, webhook.Options{
				Scheme: webhook.StandardWebhooks,
				Secret: tc.secret,
				Now:    nowAt(testNow),
			})
			assertErr(t, err, webhook.ErrMalformedSecret)
		})
	}
}

// TestStandardWebhooksSpecVector uses the example from the Standard Webhooks
// specification. Its HMAC was recomputed independently while writing these tests.
func TestStandardWebhooksSpecVector(t *testing.T) {
	err := webhook.Verify(
		[]byte(`{"test": 2432232314}`),
		swHeaders("msg_p5jXN8AQM9LWM0D4loKWxJek", "1614265330", "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="),
		webhook.Options{
			Scheme: webhook.StandardWebhooks,
			Secret: "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
			Now:    nowAt(time.Unix(1614265330, 0)),
		},
	)
	assertErr(t, err, nil)
}

func TestStripe(t *testing.T) {
	ts := strconv.FormatInt(testUnix, 10)
	valid := stripeSignature(testSecret, ts, testBody)
	validHex := strings.TrimPrefix(valid, "t="+ts+",v1=")
	zeros := strings.Repeat("0", 64)

	tests := []struct {
		name      string
		header    string
		body      string
		now       time.Time
		tolerance time.Duration
		wantErr   error
	}{
		{name: "valid signature", header: valid, body: testBody},
		{
			name:   "rotation: stale v1 first, valid v1 second",
			header: fmt.Sprintf("t=%s,v1=%s,v1=%s", ts, zeros, validHex),
			body:   testBody,
		},
		{
			name:   "spaces around parts are tolerated",
			header: fmt.Sprintf("t=%s, v1=%s", ts, validHex),
			body:   testBody,
		},
		{
			name:    "v0 entries are ignored",
			header:  fmt.Sprintf("t=%s,v0=%s", ts, validHex),
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "wrong signature",
			header:  fmt.Sprintf("t=%s,v1=%s", ts, zeros),
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "tampered body",
			header:  valid,
			body:    testBody + " ",
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "re-serialized JSON body fails",
			header:  stripeSignature(testSecret, ts, `{"id": "evt_1", "type": "ping"}`),
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "header without t",
			header:  "v1=" + validHex,
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "header without v1",
			header:  "t=" + ts,
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "non-hex v1 value",
			header:  fmt.Sprintf("t=%s,v1=zz", ts),
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "conflicting t values",
			header:  fmt.Sprintf("t=%s,t=%d,v1=%s", ts, testUnix+1, validHex),
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "timestamp 301s old is rejected",
			header:  stripeSignature(testSecret, strconv.FormatInt(testUnix-301, 10), testBody),
			body:    testBody,
			wantErr: webhook.ErrTimestampOutOfTolerance,
		},
		{
			name:    "timestamp 301s in the future is rejected",
			header:  stripeSignature(testSecret, strconv.FormatInt(testUnix+301, 10), testBody),
			body:    testBody,
			wantErr: webhook.ErrTimestampOutOfTolerance,
		},
		{
			name:      "custom tolerance accepts 10 minute old timestamp",
			header:    stripeSignature(testSecret, strconv.FormatInt(testUnix-600, 10), testBody),
			body:      testBody,
			tolerance: 15 * time.Minute,
		},
		{
			name:      "infinity accepts a timestamp ten years old",
			header:    stripeSignature(testSecret, strconv.FormatInt(testUnix-10*yearSeconds, 10), testBody),
			body:      testBody,
			tolerance: webhook.Infinity,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := tc.now
			if now.IsZero() {
				now = testNow
			}
			err := webhook.Verify([]byte(tc.body), http.Header{"Stripe-Signature": {tc.header}}, webhook.Options{
				Scheme:    webhook.Stripe,
				Secret:    testSecret,
				Tolerance: tc.tolerance,
				Now:       nowAt(now),
			})
			assertErr(t, err, tc.wantErr)
		})
	}
}

func TestStripeHeaderLookup(t *testing.T) {
	ts := strconv.FormatInt(testUnix, 10)
	headers := map[string][]string{"stripe-signature": {stripeSignature(testSecret, ts, testBody)}}
	err := webhook.Verify([]byte(testBody), headers, webhook.Options{
		Scheme: webhook.Stripe,
		Secret: testSecret,
		Now:    nowAt(testNow),
	})
	assertErr(t, err, nil)

	err = webhook.Verify([]byte(testBody), http.Header{}, webhook.Options{
		Scheme: webhook.Stripe,
		Secret: testSecret,
		Now:    nowAt(testNow),
	})
	assertErr(t, err, webhook.ErrMissingHeader)
}

func TestStripeEmptySecret(t *testing.T) {
	ts := strconv.FormatInt(testUnix, 10)
	err := webhook.Verify([]byte(testBody), http.Header{"Stripe-Signature": {stripeSignature(testSecret, ts, testBody)}}, webhook.Options{
		Scheme: webhook.Stripe,
		Now:    nowAt(testNow),
	})
	assertErr(t, err, webhook.ErrMalformedSecret)
}

func TestGitHub(t *testing.T) {
	valid := githubSignature(testSecret, testBody)

	tests := []struct {
		name    string
		headers http.Header
		body    string
		secret  string
		wantErr error
	}{
		{
			name:    "valid signature",
			headers: http.Header{"X-Hub-Signature-256": {valid}},
			body:    testBody,
		},
		{
			name:    "wrong signature",
			headers: http.Header{"X-Hub-Signature-256": {githubSignature("other-secret", testBody)}},
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "tampered body",
			headers: http.Header{"X-Hub-Signature-256": {valid}},
			body:    testBody + " ",
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "re-serialized JSON body fails",
			headers: http.Header{"X-Hub-Signature-256": {githubSignature(testSecret, `{"id": "evt_1", "type": "ping"}`)}},
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "signature without sha256= prefix",
			headers: http.Header{"X-Hub-Signature-256": {strings.TrimPrefix(valid, "sha256=")}},
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "missing header",
			headers: http.Header{},
			body:    testBody,
			wantErr: webhook.ErrMissingHeader,
		},
		{
			name:    "lowercase key in a hand-built map",
			headers: http.Header{"x-hub-signature-256": {valid}},
			body:    testBody,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := webhook.Verify([]byte(tc.body), tc.headers, webhook.Options{
				Scheme: webhook.GitHub,
				Secret: testSecret,
			})
			assertErr(t, err, tc.wantErr)
		})
	}
}

func TestGitHubEmptySecret(t *testing.T) {
	err := webhook.Verify([]byte(testBody), http.Header{"X-Hub-Signature-256": {githubSignature("", testBody)}}, webhook.Options{
		Scheme: webhook.GitHub,
	})
	assertErr(t, err, webhook.ErrMalformedSecret)
}

// TestGitHubHasNoTimestampCheck documents that GitHub signatures do not expire:
// the same signed body is accepted however far the clock has moved.
func TestGitHubHasNoTimestampCheck(t *testing.T) {
	err := webhook.Verify([]byte(testBody), http.Header{"X-Hub-Signature-256": {githubSignature(testSecret, testBody)}}, webhook.Options{
		Scheme:    webhook.GitHub,
		Secret:    testSecret,
		Tolerance: time.Second,
		Now:       nowAt(testNow.AddDate(10, 0, 0)),
	})
	assertErr(t, err, nil)
}

// TestGitHubDocumentedVector uses the example from the GitHub webhook documentation.
func TestGitHubDocumentedVector(t *testing.T) {
	err := webhook.Verify(
		[]byte("Hello, World!"),
		http.Header{"X-Hub-Signature-256": {"sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"}},
		webhook.Options{Scheme: webhook.GitHub, Secret: "It's a Secret to Everybody"},
	)
	assertErr(t, err, nil)
}

func TestHMACSHA256(t *testing.T) {
	const name = "X-Signature"
	const secret = "generic-secret"
	valid := hex.EncodeToString(mac([]byte(secret), testBody))
	validB64 := base64.StdEncoding.EncodeToString(mac([]byte(secret), testBody))
	otherHex := hex.EncodeToString(mac([]byte("other"), testBody))

	tests := []struct {
		name    string
		headers http.Header
		body    string
		wantErr error
	}{
		{name: "valid hex", headers: http.Header{name: {valid}}, body: testBody},
		{name: "valid base64", headers: http.Header{name: {validB64}}, body: testBody},
		{name: "valid uppercase hex", headers: http.Header{name: {strings.ToUpper(valid)}}, body: testBody},
		{
			name:    "rotation: comma and whitespace separated mix of hex and base64",
			headers: http.Header{name: {otherHex + ", " + validB64}},
			body:    testBody,
		},
		{
			name:    "rotation: stale hex entry first",
			headers: http.Header{name: {otherHex + " " + valid}},
			body:    testBody,
		},
		{
			name:    "wrong signature",
			headers: http.Header{name: {otherHex}},
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "tampered body",
			headers: http.Header{name: {valid}},
			body:    testBody + " ",
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "base64 of a non-digest length",
			headers: http.Header{name: {base64.StdEncoding.EncodeToString([]byte("too short"))}},
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "garbage header value",
			headers: http.Header{name: {"zzz"}},
			body:    testBody,
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "missing header",
			headers: http.Header{},
			body:    testBody,
			wantErr: webhook.ErrMissingHeader,
		},
		{
			name:    "lowercase key in a hand-built map",
			headers: http.Header{"x-signature": {valid}},
			body:    testBody,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := webhook.Verify([]byte(tc.body), tc.headers, webhook.Options{
				Scheme:     webhook.HMACSHA256,
				Secret:     secret,
				HMACHeader: name,
			})
			assertErr(t, err, tc.wantErr)
		})
	}
}

func TestHMACSHA256MalformedSecret(t *testing.T) {
	err := webhook.Verify([]byte(testBody), http.Header{"X-Signature": {"abc"}}, webhook.Options{
		Scheme:     webhook.HMACSHA256,
		HMACHeader: "X-Signature",
	})
	assertErr(t, err, webhook.ErrMalformedSecret)
}

// TestHMACSHA256RFC4231 uses RFC 4231, test case 2 (key "Jefe").
func TestHMACSHA256RFC4231(t *testing.T) {
	const want = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	digest := mac([]byte("Jefe"), "what do ya want for nothing?")
	if got := hex.EncodeToString(digest); got != want {
		t.Fatalf("test helper HMAC = %s, want %s", got, want)
	}
	err := webhook.Verify([]byte("what do ya want for nothing?"), http.Header{"X-Sig": {want}}, webhook.Options{
		Scheme:     webhook.HMACSHA256,
		Secret:     "Jefe",
		HMACHeader: "X-Sig",
	})
	assertErr(t, err, nil)
}

// withoutHeader returns a copy of h without the named header.
func withoutHeader(h http.Header, name string) http.Header {
	out := h.Clone()
	out.Del(name)
	return out
}
