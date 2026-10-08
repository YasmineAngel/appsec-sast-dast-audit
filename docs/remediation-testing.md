# Remediation Testing

This document records how the three remediated vulnerabilities were verified.
For each one, the attack was run against the live container to confirm it worked
(**before**), and the patched source in `fixes/` shows the change that prevents it
(**after**).

## Method and its limits

The "before" evidence is live: each attack was executed against the running
Juice Shop 20.2.0 container, and the full responses are saved under
`reports/remediation/`.

The "after" evidence is **source-based**. Juice Shop was not rebuilt from patched
source for this exercise, so the fixes were verified by (1) showing the exact code
change and (2) confirming that each fix uses a mechanism (parameterized queries,
prefix-based allowlisting) that makes the attack string inert. Where possible, a
companion live request shows the expected post-fix behavior (for example, a normal
search still returns products). A full rebuild would make the "after" tests live
as well; this is noted as a limitation.

The application was reset (`docker restart juice-shop`) before testing, so the data
shown is the default seed data, not residue from the earlier ZAP scan.

## Fix 01 - SQL injection in product search (SAST-070, DAST-006)

**Attack.** A UNION-based payload in the search parameter:

    qwert')) UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--

**Before.** The search returned all 24 user accounts. Each result's `name` field
held a user's email and `description` held their MD5 password hash, including the
administrator, CISO and cloud-admin accounts.
Evidence: `reports/remediation/02-search-sqli-BEFORE.txt`.

**After.** The query now binds the search term as `:criteria` via `replacements`,
so the payload is treated as a literal product name and matches nothing. A normal
search (`?q=apple`) still returns the expected products.
Evidence: `reports/remediation/02-search-sqli-AFTER.txt`, `02-search-normal.txt`.

## Fix 02 - Open redirect (SAST-069, DAST-001)

**Attack.** An attacker URL with an allowlisted URL hidden in its query string:

    /redirect?to=https://attacker.example/?x=https://github.com/juice-shop/juice-shop

**Before.** The server responded `HTTP/1.1 302 Found`, agreeing to redirect the
visitor toward the attacker-controlled domain.
Evidence: `reports/remediation/03-redirect-BEFORE.txt`.

**After.** The allowlist check was changed from `url.includes(allowedUrl)` to
`url.startsWith(allowedUrl)`. The URL must now begin with an allowlisted entry
(scheme and host included), so the attacker's domain is rejected with HTTP 406,
while legitimate redirects still return 302.
Evidence: `reports/remediation/03-redirect-AFTER.txt`.

## Fix 03 - SQL injection in login (SAST-063)

**Attack.** The email field set to `' OR 1=1--` with an arbitrary password.

**Before.** The login succeeded and returned a valid JWT. Decoding the token
showed `"email":"admin@juice-sh.op"` and `"role":"admin"`: authentication bypass
granting administrator access with no valid password.
Evidence: `reports/remediation/01-login-sqli-BEFORE.txt`, `01-login-sqli-BEFORE-decoded.txt`.

**After.** The query binds `:email` and `:password` via `replacements`, so
`' OR 1=1--` is treated as a literal email address. No user matches it and the
login fails with HTTP 401.
Evidence: `reports/remediation/01-login-sqli-AFTER.txt`.

## Summary

| Fix | Vulnerability | Before | After mechanism |
|---|---|---|---|
| 01 | SQL injection (search) | 24 accounts + hashes dumped | Parameterized query (`:criteria`) |
| 02 | Open redirect | 302 to attacker domain | Prefix allowlist (`startsWith`) |
| 03 | SQL injection (login) | Admin login bypass | Parameterized query (`:email`, `:password`) |