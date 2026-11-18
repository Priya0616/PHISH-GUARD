# PhishGuard Testing & Quality Assurance

Run the full automated unit & API integration suite:

```bash
npm test
```

## Covered Test Vectors
1. Legitimate HTTPS URLs
2. Subdomain spoofing & brand impersonation URLs
3. IP-address-based URLs and non-standard ports
4. URL shortening services (`bit.ly`, etc.)
5. Punycode (`xn--`) and mixed-script Unicode homograph domains
6. Malformed URLs, empty strings, dangerous schemes, and >2048-char inputs
7. SSRF blocking (`127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`, `::1`)
8. Missing & malformed email headers (confirming SPF/DKIM/DMARC remain `unavailable`)
9. Phishing & BEC email content with reply-to mismatch and embedded URLs
10. DNS NXDOMAIN failure & unavailable external API handling
11. Unauthenticated (`401`) and invalid credential rejections
12. Rate limiting (`429` + `Retry-After`)
