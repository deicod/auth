## 2024-05-21 - IP Spoofing Protection
**Vulnerability:** The application was blindly trusting `X-Forwarded-For` and `X-Real-IP` headers from any source, allowing attackers to spoof their IP address. This could bypass IP-based rate limiting or audit logs.
**Learning:** Defaulting to trusting headers is dangerous because it assumes the application is always behind a trusted proxy. Security should be "secure by default" (deny by default).
**Prevention:** Only process forwarded headers if the request comes from a configured Trusted Proxy. I introduced `TrustedProxies` configuration to `AuthHandlers` and updated `clientIP` logic to enforce this check.
