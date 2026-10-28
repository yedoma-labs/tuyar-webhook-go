# Security Policy

## Supported Versions

Security fixes are released for the latest version only. Upgrade to the newest release before reporting an issue that is already fixed there.

## Reporting a Vulnerability

Please do not open a public issue for security problems. Report them privately with GitHub Private Vulnerability Reporting:

1. Open the repository on GitHub.
2. Go to **Security** and then **Report a vulnerability**.
3. Describe the problem, the steps to reproduce it, the affected scheme or function, and the likely impact.

Reports stay private until a fix is released.

## Scope

In scope:

- Signature checks that accept a forged or altered request.
- Replay protection that is bypassed for StandardWebhooks or Stripe, for example through timestamp parsing.
- Leaks of the secret or signature bytes through errors, logs or timing.
- Crashes or unbounded resource use triggered by a crafted request.

Out of scope, because they are documented limitations:

- Replay of GitHub or HMAC-SHA256 requests. These schemes carry no timestamp, so the library cannot detect replays. See the README.
- Memory use for large bodies in `VerifyRequest`. Callers must limit the body size themselves with `http.MaxBytesReader`.
- Problems in the sender's or provider's own signing implementation.
