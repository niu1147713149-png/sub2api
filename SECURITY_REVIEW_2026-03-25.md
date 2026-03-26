# Security Review 2026-03-25

## Scope

Static review of the current codebase, focused on:

- authentication and session handling
- admin-configurable content
- setup/bootstrap surfaces
- outbound connectivity and SSRF-like behavior
- client IP trust and abuse controls

This review did not include dynamic exploitation or full runtime verification.

## Findings

### 1. Critical: JWT leaked to third-party embedded pages via query string

Severity: Critical

Impact:

- third-party sites can directly receive user session tokens
- tokens can leak via browser history, reverse proxy logs, analytics, and referrer chains
- likely leads to full account takeover for any authenticated user opening embedded pages

Evidence:

- `frontend/src/utils/embedded-url.ts`
  - `buildEmbeddedUrl()` appends `token=<authToken>` to the target URL
- `frontend/src/views/user/CustomPageView.vue`
  - uses `buildEmbeddedUrl(...)`
  - passes result into both `:href` and `iframe :src`
- `frontend/src/views/user/PurchaseSubscriptionView.vue`
  - same pattern for purchase/subscription embedded page
- `backend/internal/handler/setting_handler.go`
  - public settings expose `purchase_subscription_url` and `custom_menu_items`
- `backend/internal/handler/admin/setting_handler.go`
  - admin can configure these URLs

Risk chain:

1. Admin configures an external URL for purchase page or custom menu item.
2. Logged-in user opens the page.
3. Frontend appends the live JWT as a query parameter.
4. Remote site receives and can store the token.

Recommendations:

- remove JWT propagation through URL query parameters entirely
- replace with short-lived, scoped, one-time embed tokens if cross-site auth is truly required
- add a strict allowlist for embeddable destinations
- consider not embedding third-party pages at all for authenticated flows

### 2. High: Stored XSS through `home_content`

Severity: High

Impact:

- arbitrary JavaScript execution in visitors' browsers
- token theft, admin action forgery, UI redress, malicious redirects
- affects all users who visit the homepage when malicious content is set

Evidence:

- `backend/internal/handler/setting_handler.go`
  - public settings include `home_content`
- `frontend/src/views/HomeView.vue`
  - renders HTML mode with `v-html="homeContent"`
  - comment explicitly acknowledges XSS risk

Why this is real:

- `home_content` is treated as trusted HTML and rendered without sanitization
- this is a classic stored XSS sink

Recommendations:

- sanitize with DOMPurify before rendering
- preferably support Markdown with a restricted HTML allowlist
- if raw HTML must exist, gate it behind an explicit unsafe mode and restrict to trusted operators only

### 3. Medium: Unauthenticated setup endpoints can probe internal services and modify Postgres state

Severity: Medium

Impact:

- anonymous attacker can use setup mode to probe DB/Redis reachability
- database test can create a database as a side effect
- increases attack surface significantly if an uninitialized instance is exposed publicly

Evidence:

- `backend/internal/setup/handler.go`
  - `/setup/test-db`
  - `/setup/test-redis`
  - only guarded by `NeedsSetup()`, no authentication
- `backend/internal/setup/setup.go`
  - `TestDatabaseConnection()` connects to arbitrary Postgres host/port provided by request
  - creates database with `CREATE DATABASE ...` when missing
- `backend/internal/setup/setup.go`
  - `TestRedisConnection()` connects to arbitrary Redis host/port provided by request

Risk chain:

1. Service starts in setup mode on a public interface.
2. Attacker calls setup test endpoints.
3. Server attempts outbound connections into attacker-chosen targets.
4. Postgres test may create a database if credentials are valid.

Recommendations:

- bind setup server to localhost by default
- require a one-time setup secret or installation token
- make test endpoints read-only, no auto-create behavior
- disable setup HTTP mode entirely in production deployments

### 4. Medium: Client IP extraction trusts spoofable forwarding headers in security-sensitive flows

Severity: Medium

Impact:

- attacker can spoof source IP in login/register/Turnstile-related flows
- weakens anti-abuse and pollutes audit trails
- may degrade effectiveness of CAPTCHA validation and operational investigations

Evidence:

- `backend/internal/pkg/ip/ip.go`
  - `GetClientIP()` trusts:
    - `CF-Connecting-IP`
    - `X-Real-IP`
    - `X-Forwarded-For`
  - before falling back to `c.ClientIP()`
- `backend/internal/handler/auth_handler.go`
  - registration uses `ip.GetClientIP(c)`
  - verify-code uses `ip.GetClientIP(c)`
  - login uses `ip.GetClientIP(c)`

Notes:

- API key IP ACLs appear to use `GetTrustedClientIP()` and are in better shape
- the issue is still meaningful for auth/risk-control and logging paths

Recommendations:

- use `c.ClientIP()` based on Gin trusted proxy configuration for all security decisions
- never directly trust raw forwarding headers unless the immediate peer is verified trusted
- separate "display/logging IP" from "security enforcement IP" if needed

## Lower-priority observations

- Admin-configured embed URLs and iframe-driven features increase overall risk even aside from token leakage.
- Custom menu SVG rendering appears sanitized in the sidebar path, but any new `v-html` sinks should be reviewed carefully.
- Dynamic SQL usage exists in reporting code, but from sampled paths it appears to interpolate only controlled column/shape values rather than raw user strings. It still deserves periodic review.

## Recommended remediation order

1. Remove JWT-in-query behavior for embedded pages.
2. Sanitize or redesign `home_content` rendering.
3. Lock down setup mode and setup test endpoints.
4. Standardize client IP extraction on trusted proxy semantics only.

## Suggested follow-up work

- add tests that assert no auth token is ever appended to external URLs
- add tests for XSS sanitization on homepage content
- add setup-mode security tests covering unauthorized network-probing attempts
- audit all remaining `v-html` usage in frontend
- audit admin-configurable URL fields and apply a shared validation policy
