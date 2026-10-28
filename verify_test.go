package webhook_test

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	webhook "github.com/yedoma-labs/tuyar-webhook-go"
)

func TestUnsupportedScheme(t *testing.T) {
	tests := []struct {
		name   string
		scheme webhook.Scheme
	}{
		{"empty scheme", ""},
		{"unknown scheme", "sha1"},
		{"case-sensitive name", "Stripe"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := webhook.Verify([]byte(testBody), http.Header{}, webhook.Options{
				Scheme: tc.scheme,
				Secret: testSecret,
			})
			assertErr(t, err, webhook.ErrUnsupportedScheme)
		})
	}
}

func TestInvalidOptionsReturnPlainErrors(t *testing.T) {
	tests := []struct {
		name string
		opts webhook.Options
	}{
		{
			name: "negative tolerance",
			opts: webhook.Options{Scheme: webhook.StandardWebhooks, Secret: testSecretSW, Tolerance: -time.Second},
		},
		{
			name: "HMACSHA256 without HMACHeader",
			opts: webhook.Options{Scheme: webhook.HMACSHA256, Secret: testSecret},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := webhook.Verify([]byte(testBody), http.Header{}, tc.opts)
			if err == nil {
				t.Fatal("expected an error")
			}
			var whErr *webhook.Error
			if errors.As(err, &whErr) {
				t.Fatalf("invalid options must not return *Error, got %v", err)
			}
		})
	}
}

// TestDefaultToleranceIsFiveMinutes checks that a zero Tolerance is not an
// "off" switch: the 5 minute default still applies.
func TestDefaultToleranceIsFiveMinutes(t *testing.T) {
	tests := []struct {
		name    string
		offset  int64
		wantErr error
	}{
		{name: "4m59s old", offset: -299},
		{name: "exactly 5m old", offset: -300},
		{name: "5m1s old", offset: -301, wantErr: webhook.ErrTimestampOutOfTolerance},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := strconv.FormatInt(testUnix+tc.offset, 10)
			headers := swHeaders("msg_default", ts, swSignature(testSecretSW, "msg_default", ts, testBody))
			err := webhook.Verify([]byte(testBody), headers, webhook.Options{
				Scheme: webhook.StandardWebhooks,
				Secret: testSecretSW,
				Now:    nowAt(testNow),
			})
			assertErr(t, err, tc.wantErr)
		})
	}
}

// TestInfinityDisablesTimestampChecks checks that only the explicit Infinity value
// removes the window, in both directions.
func TestInfinityDisablesTimestampChecks(t *testing.T) {
	for _, offset := range []int64{-10 * yearSeconds, 10 * yearSeconds} {
		ts := strconv.FormatInt(testUnix+offset, 10)
		err := webhook.Verify([]byte(testBody), swHeaders("msg_inf", ts, swSignature(testSecretSW, "msg_inf", ts, testBody)), webhook.Options{
			Scheme:    webhook.StandardWebhooks,
			Secret:    testSecretSW,
			Tolerance: webhook.Infinity,
			Now:       nowAt(testNow),
		})
		assertErr(t, err, nil)
	}
}

func TestNilNowUsesWallClock(t *testing.T) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	err := webhook.Verify([]byte(testBody), swHeaders("msg_wall", ts, swSignature(testSecretSW, "msg_wall", ts, testBody)), webhook.Options{
		Scheme: webhook.StandardWebhooks,
		Secret: testSecretSW,
	})
	assertErr(t, err, nil)
}

func TestErrorTypeMatchesKindAndSentinels(t *testing.T) {
	err := webhook.Verify([]byte(testBody), http.Header{}, webhook.Options{
		Scheme: webhook.GitHub,
		Secret: testSecret,
	})

	var whErr *webhook.Error
	if !errors.As(err, &whErr) {
		t.Fatalf("errors.As did not yield *webhook.Error: %v", err)
	}
	if whErr.Kind != webhook.ErrMissingHeader {
		t.Fatalf("Kind = %v, want ErrMissingHeader", whErr.Kind)
	}
	if !errors.Is(err, webhook.ErrMissingHeader) {
		t.Fatal("errors.Is(err, ErrMissingHeader) = false")
	}
	if errors.Is(err, webhook.ErrInvalidSignature) {
		t.Fatal("errors.Is(err, ErrInvalidSignature) = true, want false")
	}
}

// TestErrorMessagesDoNotLeakSecretOrSignature checks that neither the configured
// secret nor any signature bytes appear in error messages.
func TestErrorMessagesDoNotLeakSecretOrSignature(t *testing.T) {
	const id = "msg_leak"
	ts := strconv.FormatInt(testUnix, 10)
	expected := swSignature(testSecretSW, id, ts, testBody)
	wrong := swSignature(swSecretFor("other-key"), id, ts, testBody)

	tests := []struct {
		name      string
		headers   http.Header
		opts      webhook.Options
		forbidden []string
	}{
		{
			name:      "wrong standard webhooks signature",
			headers:   swHeaders(id, ts, wrong),
			opts:      webhook.Options{Scheme: webhook.StandardWebhooks, Secret: testSecretSW, Now: nowAt(testNow)},
			forbidden: []string{testSecretSW, strings.TrimPrefix(testSecretSW, "whsec_"), wrong, strings.TrimPrefix(wrong, "v1,"), expected, strings.TrimPrefix(expected, "v1,")},
		},
		{
			name:      "wrong stripe signature",
			headers:   http.Header{"Stripe-Signature": {stripeSignature("other-secret", ts, testBody)}},
			opts:      webhook.Options{Scheme: webhook.Stripe, Secret: testSecret, Now: nowAt(testNow)},
			forbidden: []string{testSecret, stripeSignature("other-secret", ts, testBody)},
		},
		{
			name:      "wrong github signature",
			headers:   http.Header{"X-Hub-Signature-256": {githubSignature("other-secret", testBody)}},
			opts:      webhook.Options{Scheme: webhook.GitHub, Secret: testSecret},
			forbidden: []string{testSecret, githubSignature("other-secret", testBody)},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := webhook.Verify([]byte(testBody), tc.headers, tc.opts)
			if err == nil {
				t.Fatal("expected an error")
			}
			msg := err.Error()
			for _, f := range tc.forbidden {
				if strings.Contains(msg, f) {
					t.Fatalf("error message %q leaks %q", msg, f)
				}
			}
		})
	}
}
