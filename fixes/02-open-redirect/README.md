# Fix 02: Open Redirect

| | |
|---|---|
| **Finding** | SAST-069, confirmed by DAST-001 |
| **File** | `lib/insecurity.ts`, line 136 (`isRedirectAllowed`) |
| **OWASP 2025** | A01 Broken Access Control |
| **CWE** | CWE-601 (Open Redirect) |

## The vulnerability

The `/redirect` endpoint checks the target URL against an allowlist, but the
check used `includes`:

```typescript
allowed = allowed || url.includes(allowedUrl)
```

`includes` returns true if an allowed URL appears *anywhere* in the input. An
attacker can place an allowed URL in a query parameter of their own malicious
URL and pass the check:

    /redirect?to=https://attacker.example/?x=https://github.com/juice-shop/juice-shop

The browser is then redirected to `attacker.example`. ZAP confirmed this
(DAST-001), reaching an external `owasp.org` subdomain by the same technique.

## The fix

Use `startsWith` instead of `includes`:

```typescript
allowed = allowed || url.startsWith(allowedUrl)
```

The URL must now *begin* with an allowlisted entry. Because every entry includes
the scheme and host (e.g. `https://github.com/...`), the attacker cannot place
their own domain first. Legitimate redirects are unaffected.

## How to verify

Before the fix, this redirects off-site (HTTP 302 to the attacker domain):

    curl.exe -s -i "http://localhost:3000/redirect?to=https://attacker.example/?x=https://github.com/juice-shop/juice-shop"

After the fix, the same request is rejected with HTTP 406, while a legitimate
redirect (`?to=https://github.com/juice-shop/juice-shop`) still returns 302.