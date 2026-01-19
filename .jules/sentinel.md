## 2025-05-15 - IP Spoofing Vulnerability & Config Misalignment
**Vulnerability:** `clientIP` logic in `handlers/auth.go` blindly trusted `X-Forwarded-For` headers, allowing attackers to spoof their source IP.
**Learning:** The project's documentation/memory described a "secure by default" policy (ignoring headers unless from trusted proxy) that was **not** actually implemented in the code. This highlights the importance of verifying security claims against the actual implementation.
**Prevention:** Modified `AuthHandlers` to include `TrustedProxies` configuration. `clientIP` now only respects forwarding headers if the immediate `RemoteAddr` matches a trusted proxy. Default behavior is now secure (ignoring headers).
