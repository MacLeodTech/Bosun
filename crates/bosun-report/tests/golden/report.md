# Bosun issues report

3 issue(s).

| Severity | Count |
| --- | --- |
| critical | 0 |
| high | 0 |
| medium | 1 |
| low | 1 |
| info | 1 |

## No Content-Security-Policy

- Severity: medium
- Confidence: firm
- Status: new
- Type: missing-csp
- Request: GET https://app.example/
- CWE: CWE-693

**Remediation:** Send a Content-Security-Policy header.

## Session cookie without HttpOnly

- Severity: low
- Confidence: certain
- Status: confirmed
- Type: cookie-no-httponly
- Request: GET https://app.example/login?next=/home&amp;token=\[redacted\]
- CWE: CWE-1004
- OWASP: A05:2021

The session cookie can be read by script.

**Remediation:** Set the HttpOnly attribute.

Evidence (response):

```
HTTP/1.1 200 OK
Set-Cookie: [redacted]
Content-Type: text/html
```

## Server version disclosed

- Severity: info
- Confidence: tentative
- Status: false_positive
- Type: server-banner
- Request: GET https://app.example/status
- CWE: CWE-200
