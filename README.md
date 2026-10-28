# tuyar-webhook-go

Webhook signature verification for Go, using only the standard library. It supports **Standard Webhooks**, **Stripe**, **GitHub** and generic **HMAC-SHA256** signatures, checks them against the raw request body, and rejects replayed timestamps.

```sh
go get github.com/yedoma-labs/tuyar-webhook-go
```

Requires Go 1.23 or newer. There are no dependencies outside the standard library.

## The raw body trap

A webhook signature is an HMAC over the exact bytes the sender transmitted. If anything parses or re-serializes the body before the check, the check fails even though the request is genuine.

Common ways this happens:

- A JSON decoder consumes `r.Body`, and the handler then re-marshals the struct to get bytes to verify.
- A middleware reads the body for logging or JSON binding and does not restore it.
- Charset or line-ending normalization changes bytes.

```go
// WRONG: the decoder consumed the body, and re-marshalling changes whitespace and key order
var event Event
_ = json.NewDecoder(r.Body).Decode(&event)
body, _ := json.Marshal(event)
err := webhook.Verify(body, r.Header, opts) // fails for genuine requests

// RIGHT: verify the bytes that arrived, then decode them
body, err := webhook.VerifyRequest(r, opts)
if err == nil {
	_ = json.Unmarshal(body, &event)
}
```

**Always verify before anything parses the body.** `VerifyRequest` reads the body, verifies it and restores `r.Body`, so later code can still read it.

### net/http

```go
package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	webhook "github.com/yedoma-labs/tuyar-webhook-go"
)

var stripeSecret = os.Getenv("STRIPE_WEBHOOK_SECRET")

func stripeHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // bound the body size first

	body, err := webhook.VerifyRequest(r, webhook.Options{
		Scheme: webhook.Stripe,
		Secret: stripeSecret,
	})
	if err != nil {
		http.Error(w, statusText(err), statusFor(err))
		return
	}

	var event map[string]any
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, webhook.ErrMissingHeader):
		return http.StatusBadRequest
	case errors.Is(err, webhook.ErrMalformedSecret), errors.Is(err, webhook.ErrUnsupportedScheme):
		return http.StatusInternalServerError // configuration problem, not the sender's fault
	default:
		return http.StatusUnauthorized
	}
}

func statusText(err error) string {
	return http.StatusText(statusFor(err))
}

func main() {
	http.HandleFunc("POST /webhooks/stripe", stripeHandler)
	_ = http.ListenAndServe(":8080", nil)
}
```

### chi

chi does not read request bodies itself, so `VerifyRequest` works directly in the handler. Keep any JSON-binding middleware away from webhook routes, or make sure it runs after verification.

```go
package main

import (
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	webhook "github.com/yedoma-labs/tuyar-webhook-go"
)

func main() {
	r := chi.NewRouter()

	r.Post("/webhooks/github", func(w http.ResponseWriter, req *http.Request) {
		req.Body = http.MaxBytesReader(w, req.Body, 25<<20)

		body, err := webhook.VerifyRequest(req, webhook.Options{
			Scheme: webhook.GitHub,
			Secret: os.Getenv("GITHUB_WEBHOOK_SECRET"),
		})
		if err != nil {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}

		_ = body // verified bytes, safe to decode
		w.WriteHeader(http.StatusNoContent)
	})

	_ = http.ListenAndServe(":8080", r)
}
```

## Quickstart

```go
import (
	"errors"
	"net/http"

	webhook "github.com/yedoma-labs/tuyar-webhook-go"
)

body, err := webhook.VerifyRequest(r, webhook.Options{
	Scheme: webhook.StandardWebhooks,
	Secret: "whsec_...",          // from your provider's dashboard
	// Tolerance: 5 * time.Minute, // default; zero also means the default
})
if errors.Is(err, webhook.ErrTimestampOutOfTolerance) {
	// stale or future timestamp: possible replay
}
```

If you already have the body as a `[]byte` and a header map, call `Verify` directly:

```go
err := webhook.Verify(body, r.Header, webhook.Options{
	Scheme:     webhook.HMACSHA256,
	Secret:     secret,
	HMACHeader: "X-Signature-256",
})
```

## Supported schemes

| `Scheme`                    | Headers read                                       | Signed content              | Encoding      | Timestamp | Secret format                     |
| --------------------------- | -------------------------------------------------- | --------------------------- | ------------- | --------- | --------------------------------- |
| `webhook.StandardWebhooks`  | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `<id>.<timestamp>.<body>` | base64        | yes       | `whsec_<base64>`, key is decoded  |
| `webhook.Stripe`            | `Stripe-Signature` (`t=…,v1=…`)                    | `<t>.<body>`                | hex           | yes       | any non-empty string (UTF-8 bytes) |
| `webhook.GitHub`            | `X-Hub-Signature-256` (`sha256=…`)                 | `<body>`                    | hex           | no        | any non-empty string (UTF-8 bytes) |
| `webhook.HMACSHA256`        | the header named by `Options.HMACHeader`           | `<body>`                    | hex or base64 | no        | any non-empty string (UTF-8 bytes) |

- **StandardWebhooks** accepts several space-separated `v1,<base64>` entries. Entries with other versions are ignored.
- **Stripe** accepts several `v1=` entries for rotation. `v0=` entries are ignored.
- **HMACSHA256** accepts several signatures separated by commas or whitespace, and each may be hex or base64.
- Header names are matched case-insensitively, for `http.Header` values and for hand-built maps.

## Options

| Field        | Default       | Notes                                                                                              |
| ------------ | ------------- | -------------------------------------------------------------------------------------------------- |
| `Scheme`     | required      | One of the four constants above.                                                                   |
| `Secret`     | required      | Validated per scheme. Malformed values return `ErrMalformedSecret`.                               |
| `Tolerance`  | 5 minutes     | Allowed distance between the signed timestamp and `Now`, in both directions. Zero means the default. Only `webhook.Infinity` disables the window. Used by StandardWebhooks and Stripe. |
| `Now`        | `time.Now`    | Clock source, mainly for tests.                                                                    |
| `HMACHeader` | none          | Required for `HMACSHA256`.                                                                         |

Future timestamps are rejected when they are more than the smaller of `Tolerance` and 30 seconds ahead of `Now`.

## Errors

`Verify` and `VerifyRequest` return `*webhook.Error` for verification failures. Its `Kind` field holds one of the sentinel errors, and `errors.Is` matches them.

| Sentinel                     | Meaning                                                              | Suggested HTTP status |
| ---------------------------- | -------------------------------------------------------------------- | --------------------- |
| `ErrMissingHeader`           | A required signature header is absent or empty                       | 400                   |
| `ErrInvalidSignature`        | No signature matches, or the signature data is malformed             | 401                   |
| `ErrTimestampOutOfTolerance` | The signed timestamp is too old or too far in the future             | 401                   |
| `ErrMalformedSecret`         | The secret does not match the scheme's format                        | 500 (configuration)   |
| `ErrUnsupportedScheme`       | The scheme is unknown                                                | 500 (programming)     |

Invalid options, such as a negative `Tolerance` or a missing `HMACHeader`, return a plain error. Error messages never contain the secret or signature bytes.

## Replay protection

- **StandardWebhooks** and **Stripe** check the signed timestamp against `Tolerance`. The check runs after the signature check, so an unauthenticated request learns nothing about its timestamp.
- **GitHub** and **HMACSHA256** carry no timestamp. A captured request stays valid forever, and this library cannot detect the replay. Deduplicate on the delivery identifier instead, for example the `X-GitHub-Delivery` header or an event ID in the payload.

## Limits

- The library verifies that the sender holds the secret. It does not validate the payload. Check the fields you use after decoding.
- `VerifyRequest` reads the whole body into memory. Wrap `r.Body` with `http.MaxBytesReader` first.
- GitHub and HMACSHA256 have no replay protection (see above).
- The library does not manage secret rotation for you. Keep the old and new signatures in the header during a rotation, and every listed value is checked.

## Development

```sh
gofmt -l .
go vet ./...
go test -race ./...
go build ./...
```

## License

MIT, see [LICENSE](LICENSE).
