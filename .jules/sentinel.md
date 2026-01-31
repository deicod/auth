## 2024-05-21 - IP Spoofing Protection
**Vulnerability:** The application was blindly trusting `X-Forwarded-For` and `X-Real-IP` headers from any source, allowing attackers to spoof their IP address. This could bypass IP-based rate limiting or audit logs.
**Learning:** While "secure by default" (deny by default) is ideal, it breaks functionality in environments like Kubernetes where the ingress IP is dynamic or unknown. A "default to allow" strategy for `TrustedProxies` (trust headers if config is empty) prioritizes usability but requires explicit configuration to secure the app.
**Prevention:** I introduced `TrustedProxies` to `AuthHandlers`. If empty, the app defaults to trusting headers (for K8s compatibility). To secure the app, admins *must* configure `TrustedProxies`, which then enforces strict validation of the upstream IP.

## 2026-01-21 - Username Enumeration via Timing Attack
**Vulnerability:** The `Login` flow returned immediately when a user was not found, but performed expensive Argon2 verification when a user existed. This timing difference allowed attackers to enumerate valid usernames.
**Learning:** Returning early on `ErrUserNotFound` is a common optimization that introduces side channels. Security-critical flows must have constant-time execution paths regardless of the outcome.
**Prevention:** Introduced a `dummyHash` generated at startup. When a user is not found, the system now performs a "fake" verification against this dummy hash, ensuring the response time is indistinguishable from a failed password attempt for a valid user.

## 2026-01-22 - DoS via Large Request Bodies
**Vulnerability:** The JSON decoder used in `AuthHandlers` read the entire request body without a size limit. This allowed an attacker to send massive payloads (e.g., infinite streams or large blobs), potentially exhausting server memory and causing a Denial of Service.
**Learning:** `json.NewDecoder(r.Body).Decode(&dst)` does NOT automatically limit input size. While some web frameworks handle this, standard Go `http.Handler`s rely on the developer to wrap `r.Body` with `http.MaxBytesReader`.
**Prevention:** I wrapped the request body in `decodeJSON` with `http.MaxBytesReader` and enforced a strict 1MB limit. This ensures the connection is closed if the payload exceeds the threshold, protecting the application resources.

## 2026-01-23 - DoS via CPU Exhaustion (Long Passwords)
**Vulnerability:** The `Register` and `Login` flows accepted passwords of arbitrary length (up to the 1MB body limit). Hashing extremely long passwords (e.g., 500KB) with Argon2 is computationally expensive, allowing an attacker to exhaust server CPU resources by sending a few requests with massive passwords.
**Learning:** Even if the request body size is limited, specific fields (like passwords processed by expensive algorithms) need tighter bounds. Standard library validations (like `mail.ParseAddress`) may not enforce strict length limits suitable for all contexts.
**Prevention:** I introduced explicit length limits for passwords (`maxPasswordLength = 1024`) and emails (`maxEmailLength = 254`) in the `AuthService`. These checks run before any expensive operations (like hashing or database lookups), allowing the server to reject malicious requests cheaply.

## 2026-01-24 - Username Enumeration via Email Timing
**Vulnerability:** The `ForgotPassword` flow sent emails synchronously. When a user existed, the server connected to the SMTP server (slow), creating a significant timing difference compared to when a user did not exist (fast).
**Learning:** Network operations (like SMTP) are inherently slow and variable. Even if DB lookups are masked, synchronous external calls leak information about the internal state (e.g., "we are sending an email, so the user exists").
**Prevention:** I moved the email sending logic in `ForgotPassword` to a background goroutine. This ensures the HTTP handler returns immediately in both cases (Found/Not Found), eliminating the network latency side channel.

## 2026-01-25 - HSTS Lockout on Localhost
**Vulnerability:** Blindly enabling Strict-Transport-Security (HSTS) with a long `max-age` (2 years) on all responses caused local development environments (accessed via `http://localhost`) to break. If a developer ran the app once, their browser would cache the HSTS policy and force HTTPS for `localhost` for 2 years, often locking them out of other local HTTP-only projects.
**Learning:** Security headers like HSTS are critical for production but harmful in non-secure development contexts. Middleware must be "environment-aware" or context-sensitive to avoid damaging the developer experience.
**Prevention:** I added a check in the `SecurityHeaders` middleware to inspect the `Host` header. If the host is `localhost`, `127.0.0.1`, or `::1`, the HSTS header is suppressed. This preserves security for production domains while keeping local development frictionless.

## 2026-01-26 - SQL Injection via UpdateFields Map Keys
**Vulnerability:** The `UpdateFields` method in `pgx` and `sqlite` repositories constructed `UPDATE` queries by directly interpolating map keys from the input `fields` map. If a caller passed user-controlled keys, an attacker could inject arbitrary SQL (e.g., commenting out the `WHERE` clause), potentially bypassing authorization or modifying unrelated data.
**Learning:** Building SQL queries dynamically from maps requires strict validation of keys. Relying on the service layer to "only pass safe keys" is fragile (defense in depth violation) because future refactors or new call sites might accidentally pass user input.
**Prevention:** I implemented an allowlist validation in `UpdateFields` to ensure only known-safe column names (`email`, `role`, etc.) are allowed, rejecting any unknown keys with an error.

## 2026-01-27 - Incomplete Async Forgot Password
**Vulnerability:** The `ForgotPassword` flow was intended to be async to prevent timing attacks, but the `issuePasswordReset` DB write was still synchronous. This allowed an attacker to distinguish valid emails by the latency of the DB insert (~10ms+) versus immediate return.
**Learning:** When making a flow asynchronous to hide side channels, *all* data-dependent operations (DB writes, external calls) must be moved to the async block. A single synchronous write before the async block defeats the protection.
**Prevention:** Moved the token generation and DB insertion into the background goroutine in `ForgotPassword`.

## 2026-01-25 - Sensitive Data Leakage via Browser Cache
**Vulnerability:** The API returned JSON responses containing sensitive data (session tokens, PII) without `Cache-Control` headers. Browsers or intermediate proxies could cache these responses, allowing an attacker with access to the same machine or network to retrieve them (e.g., via history or disk cache).
**Learning:** By default, browsers may cache GET responses (like `/auth/me`) or even some POST responses depending on heuristics. APIs serving sensitive authentication state must explicitly disable caching.
**Prevention:** I modified the `respondJSON` helper to inject `Cache-Control: no-store` and `Pragma: no-cache` on all JSON responses. This ensures that sensitive data is never stored by the client or intermediaries.

## 2026-01-28 - Weak Password Policy Configuration
**Vulnerability:** The application accepted any password that met the minimum length requirement (8 chars), allowing weak passwords like "password", "12345678", etc. There was no mechanism to enforce complexity.
**Learning:** Defaulting to "minimal friction" (only length check) is common for libraries, but security-critical applications need the *option* to enforce stronger policies. Hardcoding checks or leaving it entirely to the user (validation before calling Register) leads to inconsistent enforcement.
**Prevention:** Enhanced `config.Password` with boolean flags (`RequireUppercase`, etc.) and implemented a centralized `validatePassword` helper in the service layer. This ensures that if the policy is enabled, it is enforced consistently across all password-setting flows (Register, ResetPassword).

## 2026-01-29 - Rate Limiting without Dependencies
**Vulnerability:** The `Login` and `Register` endpoints were vulnerable to brute-force attacks and CPU exhaustion DoS because they lacked rate limiting.
**Learning:** Implementing a robust rate limiter usually requires `golang.org/x/time` or Redis. However, strict dependency constraints ("Ask first") forced a simpler solution.
**Prevention:** I implemented a "Fixed Window" rate limiter using a simple map and mutex within `AuthHandlers`. To prevent memory leaks without background goroutines, I added a "lazy cleanup" check that purges expired entries when the map grows too large. This provides sufficient protection for a single-instance service without adding dependencies.

## 2026-01-30 - Incomplete Rate Limiting Coverage
**Vulnerability:** While `Login` and `Register` were rate-limited, other sensitive endpoints like `ForgotPassword` (email trigger) and `VerifyEmail` (token verification) were not. This allowed attackers to perform email bombing or token brute-forcing.
**Learning:** Rate limiting must be applied to *all* public endpoints that trigger side effects (emails, DB writes) or consume significant resources, not just authentication entry points.
**Prevention:** Extended the existing `checkRateLimit` middleware-like check to `VerifyEmail`, `ForgotPassword`, `ResetPassword`, `InitiateEmailChange`, and `ConfirmEmailChange`.

## 2026-01-31 - Mass Assignment Risk in MongoDB UpdateFields
**Vulnerability:** The `UpdateFields` method in `mgo/repos/user.go` accepted a `bson.M` map and passed it directly to `$set` in MongoDB update. This allowed an attacker to potentially update any field in the user document (e.g. inject arbitrary fields or overwrite protected ones if not filtered upstream) by controlling the keys in the input map.
**Learning:** Applying security fixes consistently across all adapters is crucial. While `pgx` and `sqlite` adapters were secured against this (SQL injection/mass assignment), the MongoDB adapter was overlooked.
**Prevention:** I implemented an explicit allowlist validation in `mgo/repos/user.go` (similar to the SQL adapters) to ensure only known-safe fields can be updated. I also added a unit test to verify this validation logic.

## 2026-02-03 - DoS via Rate Limiter Cleanup
**Vulnerability:** The in-memory rate limiter used a "lazy cleanup" strategy that iterated the entire visitor map (`O(N)`) inside a mutex lock whenever the map size exceeded a threshold. An attacker could fill the map with active visitors, causing every subsequent request to trigger a full map scan, leading to CPU exhaustion and request blocking.
**Learning:** Naive "cleanup on write" strategies for in-memory caches can introduce DoS vectors if the cleanup complexity is linear (`O(N)`) and happens on the hot path. Bounded operations (`O(1)` or limited `N`) and hard limits are essential for stability.
**Prevention:** Refactored the cleanup logic to check only a fixed number of items (50) per request and enforced a strict hard limit (5000) with random eviction. This ensures the rate limiter remains performant and bounded in memory usage even under attack.

## 2026-02-04 - Username Enumeration via InitiateEmailChange
**Vulnerability:** The `InitiateEmailChange` service method returned `ErrUserNotFound` immediately if the user ID did not exist, but performed expensive password hashing if the user existed. This timing difference (and the specific error code `404` vs `401`) allowed attackers to enumerate valid user IDs.
**Learning:** Even if an endpoint requires a password (re-authentication), failing fast on "user not found" leaks the existence of the user. Security-critical flows must handle "user not found" and "invalid password" indistinguishably in terms of timing and error response.
**Prevention:** Modified `InitiateEmailChange` to catch `ErrUserNotFound`, execute a dummy hash verification (to normalize timing), and return `ErrInvalidCredentials`. This ensures both invalid ID and invalid password result in the same 401 response and take the same amount of time.

## 2026-02-05 - DoS via Long Inputs in Login/Forgot Password
**Vulnerability:** The `Login` and `ForgotPassword` service methods did not validate the length of the email input before processing. While the HTTP handler limits the body size to 1MB, passing a 1MB string to the database or normalization logic could cause performance degradation or DoS.
**Learning:** Security controls (like length limits) must be applied consistently across *all* entry points. Adding a limit to `Register` does not automatically protect `Login` or `ForgotPassword`.
**Prevention:** I added explicit `len(email) > maxEmailLength` checks to `Login` and `ForgotPassword` in `AuthService`, ensuring they fail fast before any expensive operations or database calls.

## 2026-02-06 - Missing Content Security Policy (CSP)
**Vulnerability:** The application lacked a `Content-Security-Policy` header. While primarily a JSON API, the absence of CSP meant that if any response was misinterpreted as HTML (e.g. via MIME confusion or future frontend integration), it would be vulnerable to XSS and framing attacks.
**Learning:** Even for pure APIs, a strict `default-src 'none'` CSP provides cheap but effective defense-in-depth against unexpected rendering contexts or future regressions where HTML might be served.
**Prevention:** Added `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` to the global security middleware.
