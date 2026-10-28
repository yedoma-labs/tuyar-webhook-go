package webhook_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	testBody   = `{"id":"evt_1","type":"ping"}`
	testSecret = "stripe-test-secret"
	testUnix   = int64(1700000000)
)

// testSecretSW is a Standard Webhooks secret whose key is "standard-key-bytes-0123456789".
var testSecretSW = "whsec_" + base64.StdEncoding.EncodeToString([]byte("standard-key-bytes-0123456789"))

var testNow = time.Unix(testUnix, 0)

func nowAt(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// mac computes HMAC-SHA256 with crypto/hmac directly. The tests never call the
// library's own signing code, so a bug in the library cannot hide in the fixtures.
func mac(key []byte, parts ...string) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		_, _ = m.Write([]byte(p))
	}
	return m.Sum(nil)
}

// swSignature returns a Standard Webhooks "v1,<base64>" entry for the given secret.
func swSignature(secret, id, ts, body string) string {
	key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	return "v1," + base64.StdEncoding.EncodeToString(mac(key, id+"."+ts+"."+body))
}

// stripeSignature returns a Stripe "t=...,v1=..." header value.
func stripeSignature(secret, ts, body string) string {
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac([]byte(secret), ts+"."+body))
}

// githubSignature returns an X-Hub-Signature-256 header value.
func githubSignature(secret, body string) string {
	return "sha256=" + hex.EncodeToString(mac([]byte(secret), body))
}

func swHeaders(id, ts, signature string) http.Header {
	h := http.Header{}
	h.Set("webhook-id", id)
	h.Set("webhook-timestamp", ts)
	h.Set("webhook-signature", signature)
	return h
}

// assertErr fails the test unless err matches want. A nil want requires err to be nil.
func assertErr(t *testing.T, err, want error) {
	t.Helper()
	if want == nil {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want errors.Is %v", err, want)
	}
}
