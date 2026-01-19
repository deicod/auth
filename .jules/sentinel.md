## 2025-02-14 - IP Spoofing in `clientIP`

**Vulnerability:** The `clientIP` function in `handlers/auth.go` blindly trusted `X-Forwarded-For` and `X-Real-IP` headers. This allowed malicious actors to spoof their IP address by simply adding these headers to their request, bypassing potential IP-based rate limiting or corrupting audit logs.

**Learning:** Trusting client-supplied headers for security-critical data (like IP address) without validation is a common pitfall. The application was prioritizing usability (getting the real IP behind a proxy) over security (ensuring the IP is genuine).

**Prevention:** Always default to `RemoteAddr` (the direct connection IP). If support for reverse proxies is required, it MUST be explicit: require a "Trusted Proxies" configuration (list of IPs or CIDRs) and only respect `X-Forwarded-For` if the request comes from one of those trusted IPs. "Secure by default" means assuming untrusted input until proven otherwise.
