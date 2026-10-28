package webhook_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"

	webhook "github.com/yedoma-labs/tuyar-webhook-go"
)

func TestVerifyRequest(t *testing.T) {
	const id = "msg_req"
	ts := strconv.FormatInt(testUnix, 10)
	valid := swSignature(testSecretSW, id, ts, testBody)
	opts := webhook.Options{Scheme: webhook.StandardWebhooks, Secret: testSecretSW, Now: nowAt(testNow)}

	tests := []struct {
		name    string
		headers http.Header
		body    string
		wantErr error
	}{
		{name: "valid request", headers: swHeaders(id, ts, valid), body: testBody},
		{
			name:    "tampered body still returns the raw body",
			headers: swHeaders(id, ts, valid),
			body:    testBody + " ",
			wantErr: webhook.ErrInvalidSignature,
		},
		{
			name:    "missing header",
			headers: http.Header{},
			body:    testBody,
			wantErr: webhook.ErrMissingHeader,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(tc.body))
			req.Header = tc.headers

			body, err := webhook.VerifyRequest(req, opts)
			assertErr(t, err, tc.wantErr)
			if string(body) != tc.body {
				t.Fatalf("returned body = %q, want %q", body, tc.body)
			}

			again, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("reading restored body: %v", err)
			}
			if !bytes.Equal(again, []byte(tc.body)) {
				t.Fatalf("restored body = %q, want %q", again, tc.body)
			}

			if req.GetBody == nil {
				t.Fatal("GetBody is nil after VerifyRequest")
			}
			rc, err := req.GetBody()
			if err != nil {
				t.Fatalf("GetBody: %v", err)
			}
			fromGetBody, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("reading GetBody: %v", err)
			}
			if string(fromGetBody) != tc.body {
				t.Fatalf("GetBody = %q, want %q", fromGetBody, tc.body)
			}
		})
	}
}

func TestVerifyRequestNilBody(t *testing.T) {
	req := &http.Request{Header: http.Header{}}
	body, err := webhook.VerifyRequest(req, webhook.Options{
		Scheme: webhook.GitHub,
		Secret: testSecret,
	})
	assertErr(t, err, webhook.ErrMissingHeader)
	if len(body) != 0 {
		t.Fatalf("body = %q, want empty", body)
	}
	if req.Body == nil {
		t.Fatal("Body must be non-nil after VerifyRequest")
	}
}

func TestVerifyRequestNilRequest(t *testing.T) {
	_, err := webhook.VerifyRequest(nil, webhook.Options{Scheme: webhook.GitHub, Secret: testSecret})
	if err == nil {
		t.Fatal("expected an error for a nil request")
	}
}

func TestVerifyRequestReadError(t *testing.T) {
	boom := errors.New("connection reset")
	req := httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(testBody))
	req.Body = io.NopCloser(iotest.ErrReader(boom))

	_, err := webhook.VerifyRequest(req, webhook.Options{Scheme: webhook.GitHub, Secret: testSecret})
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want wrapped %v", err, boom)
	}
}
