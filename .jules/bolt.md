## 2025-05-23 - Redundant IP Parsing in Handlers
**Learning:** The `clientIP` method in `handlers/auth.go` performs expensive operations (header parsing and `net.ParseCIDR` loops) when `TrustedProxies` is configured. This method was being called multiple times per request (for rate limiting, logging, and command struct population).
**Action:** Always cache the result of expensive request-scoped calculations (like IP resolution) in a local variable at the start of the handler if it is used multiple times. This simple refactoring yielded a ~39% improvement in handler execution time in a benchmark scenario with trusted proxies.

## 2025-06-03 - Zero-Allocation IP Parsing
**Learning:** `strings.Split` in hot paths like `clientIP` allocates unnecessary slices (O(N) allocations). Iterating manually from right to left over the header string eliminates allocations entirely and avoids redundant IP parsing.
**Action:** Prefer manual string slicing (using `strings.LastIndexByte`) over `strings.Split` for comma-separated headers in high-throughput middleware, especially when processing items in reverse order.

## 2025-06-04 - Amortized Rate Limit Cleanup
**Learning:** The simple map cleanup strategy in `checkRateLimit` (checking 50 items on *every* request once the map is full) creates a high constant-time overhead under load, even when no items are expiring. This degraded throughput significantly (~4x slower in benchmarks).
**Action:** Use a counter or random sampler to run expensive cleanup operations only occasionally (e.g., every 64th request). Amortizing the cost maintains memory safety while eliminating the latency penalty for the majority of requests.
