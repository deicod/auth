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
