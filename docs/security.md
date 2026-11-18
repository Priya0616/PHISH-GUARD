# PhishGuard Defensive Security Architecture

1. **Password Security**: Passwords hashed with `bcryptjs` (salt rounds = 10); plaintext passwords are never stored or logged.
2. **Authentication**: Stateless `HS256` JWTs with 12-hour expiration (`Authorization: Bearer <token>`).
3. **SSRF & DNS Rebinding Protection**:
   - Rejects non-HTTP(S) schemes (`javascript:`, `file:`, `gopher:`, `data:`).
   - Blocks loopback (`127.0.0.0/8`, `::1`), RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`), and `.local` / `.internal` hostnames.
   - Re-validates all DNS-resolved IPv4/IPv6 addresses before opening any TLS socket.
4. **Parameterized SQLite**: All queries use prepared statements (`db.prepare(...).run/get/all(...)`) to prevent SQL injection.
5. **Rate Limiting & Payload Caps**: Sliding-window per-IP rate limiting (`429` + `Retry-After`) and 256KB JSON body limit.
6. **Secret Hygiene**: Third-party threat intelligence keys and `GEMINI_API_KEY` remain exclusively on the backend.
