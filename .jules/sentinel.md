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
