# Recon Report: Internal Ops-Docs URL Leak
## 37signals / Basecamp / fizzy.do

**Timestamp:** 2026-06-21 01:20 UTC
**Workspace:** /home/rez/projects/seal

---

## 1. CONFIRMED LEAK

The fizzy.do Cloudflare error page HTML source contains:

```html
<!-- UPDATING THIS PAGE AND DEPLOYING WILL *NOT* UPDATE THE LIVE CLOUDFLARE PAGE
PLEASE REFER TO THIS OPS DOCS ENTRY FOR UPDATING CUSTOM PAGES IN CLOUDFLARE :
https://ops-docs.basecamp.com/CDN/cloudflare-account-level-configs.html#cloudflare-error-pages
-->
```

This is an HTML comment leaking an internal operational documentation URL in the public-facing Cloudflare custom error page for fizzy.do. The URL explicitly documents how to update custom Cloudflare error pages.

## 2. DNS & Network Architecture

| Hostname | Records | Type | Access |
|---|---|---|---|
| `ops-docs.basecamp.com` | `104.18.15.58`, `104.18.14.58` | Cloudflare edge | PUBLIC |
| `ops-docs.37signals.com` | `10.10.5.40` | RFC1918 private IP | INTERNAL ONLY |
| `37signals.com` | `104.18.0.135`, `104.18.1.135` | Cloudflare edge | PUBLIC |
| `basecamp.com` | `104.18.14.58`, `104.18.15.58` | Cloudflare edge | PUBLIC |

**Key finding:** `ops-docs.37signals.com` resolves to `10.10.5.40` — a private RFC1918 IP reachable ONLY from within 37signals' internal network. All ports (80, 443, 8080, 8443) return "No route to host" from external IPs.

## 3. URL Redirect Chain

```
https://ops-docs.basecamp.com/CDN/cloudflare-account-level-configs.html
  → 301 Moved Permanently (Cloudflare)
  → Location: https://ops-docs.37signals.com/CDN/cloudflare-account-level-configs.html
  → FAILED: No route to host (10.10.5.40 is private IP)
```

Any URL on `ops-docs.basecamp.com` redirects to the corresponding URL on `ops-docs.37signals.com` via a catch-all Cloudflare redirect rule. The subdomain has a valid `*.basecamp.com` certificate.

## 4. Archive Status — All Negative

| Source | Result |
|---|---|
| Wayback Machine CDX API | **No snapshots** — empty for both URLs and entire domain |
| Wayback Availability API | **429 Rate Limited** |
| Google Cache | **No cached version** — returns CAPTCHA |
| archive.md (archive.today) | **No saved snapshot** |
| CachedView.nl | **404 Not Found** |

## 5. URL Variation Probes — All 301

All paths on `ops-docs.basecamp.com` return HTTP 301 redirect to `ops-docs.37signals.com`:
- `/CDN/`, `/CDN`, `/cloudflare-account-level-configs.html` (root)
- `/CDN/cloudflare-account-level-configs`, `.json`
- `/index.html`, `/`, `/.git/config`, `/robots.txt`, `/.env`, `/sitemap.xml`

All redirect targets fail at the network level (unreachable private IP).

## 6. Header Manipulation — No Bypass

| Headers sent | Result |
|---|---|
| User-Agent: `37signalsBot/1.0` + Referer: `admin.37signals.com` | 301 redirect |
| CF-Connecting-IP spoofing + X-Forwarded-For | 301 redirect |

The gate is at the **network level** (private IP resolution), not an application-level header check.

## 7. GitHub / GitLab / Source Search — No Public References

| Platform | Result |
|---|---|
| GitHub API (code search) | Requires authentication (401) |
| GitHub web (37signals org) | Org exists, redirects to login |
| GitLab search | No matches |
| Sourcegraph | No matches |

No public repositories or code snippets found containing the leaked URLs.

## 8. Certificate Transparency — No Related Certs

- `crt.sh` for `*.basecamp.com`: No ops-docs related subdomains listed
- `crt.sh` for `*.37signals.com`: No ops-docs related subdomains listed

## 9. Subdomain Discovery — All Negative

Attempted DNS lookups on all returned NXDOMAIN/no records:
- `docs.basecamp.com`, `internal.basecamp.com`
- `dev.basecamp.com`, `admin.basecamp.com`
- `cdn.basecamp.com`, `cf-docs.basecamp.com`

## 10. Cloudflare Trace — Confirmed

`ops-docs.basecamp.com`:
- Colo: DEN (Denver, CO)
- HTTP/2, HTTPS
- Behind Cloudflare proxy
- Certificate: `*.basecamp.com` via Google Trust Services

## 11. Additional Leaked Info from fizzy.do Page

- **Support email** (Cloudflare-obfuscated): `support@basecamp.com`
- **Blocked IP** displayed on error page
- The error page is custom-styled with 37signals/Basecamp branding (fonts, colors, dialog box)

## 12. Impact Assessment

### What was leaked:
- Internal ops-docs URL in a public Cloudflare error page HTML comment
- Internal hostname pattern: `ops-docs.{product}.basecamp.com` → `ops-docs.37signals.com`
- Internal DNS architecture: `10.10.5.40` (RFC1918 private IP)
- Documentation structure: `/CDN/` path prefix, `.html` pages with anchor sections (e.g., `#cloudflare-error-pages`)
- Confirms an internal documentation system exists at 37signals

### What was NOT recovered:
- The actual content of the Cloudflare configuration documentation
- Internal IPs, origin server addresses, WAF rules, or credentials
- Any other paths or pages on the internal docs server

### Risk Level: **MEDIUM**

The URL leak itself is a minor information disclosure, but it confirms:
1. Internal hostname patterns and DNS architecture
2. A Cloudflare documentation system exists internally at 37signals
3. The `fizzy.do` product uses Basecamp's Cloudflare infrastructure
4. Physical edge server location: Denver, CO

The private IP (`10.10.5.40`) is only reachable via internal network, so no direct exploitation path exists from the internet. However, if an attacker gains internal network access, they now know the server IP and hostname.

### Remediation Suggestions:
1. **Remove the HTML comment** from the fizzy.do Cloudflare error page
2. **Keep `ops-docs.37signals.com` DNS as internal-only** (already properly restricted to RFC1918)
3. **Consider removing the public redirect** from `ops-docs.basecamp.com` to `ops-docs.37signals.com` — there's no reason for this DNS record or redirect to exist publicly since no public documentation is served there
4. **Audit all Cloudflare custom error pages** for similar internal URL leaks across all customer-facing domains (basecamp.com, hey.com, .do domains, etc.)

## Files Created

- `/home/rez/projects/seal/ops-docs-leak-report.md` — This report
