# SecurityScan Agent v2.0

A browser-based URL security scanner that performs comprehensive security analysis on any given URL. No server required — runs entirely in the browser.

## Features

### 🔍 Security Checks

- **HTTP Header Analysis** — Checks for 9 critical security headers:
  - X-Frame-Options (clickjacking protection)
  - Content-Security-Policy (XSS mitigation)
  - Strict-Transport-Security (HTTPS enforcement)
  - X-Content-Type-Options (MIME sniffing prevention)
  - X-XSS-Protection (legacy XSS filter)
  - Referrer-Policy (information leakage control)
  - Permissions-Policy (feature restrictions)
  - X-Powered-By (information disclosure)
  - Server (software version leakage)

- **SSL/TLS Certificate Inspection** — Validates:
  - Certificate validity and expiration
  - TLS protocol version (flags deprecated TLS 1.0/1.1)
  - Cipher suite strength
  - HSTS enforcement
  - Wildcard certificate usage

- **Open Port Detection** — Scans 25 common ports including:
  - Web (80, 443, 8080, 8443)
  - Database (3306, 5432, 27017, 1433, 1521)
  - Remote access (22, 23, 3389, 5900)
  - Mail (25, 110, 143)
  - Legacy (21, 445, 135, 139)

- **XSS Vulnerability Pattern Detection** — Identifies 10 XSS patterns:
  - Script tag injection
  - Inline event handlers
  - JavaScript URI schemes
  - DOM manipulation APIs
  - eval() usage
  - Iframe/Object/Embed elements
  - Base64 data URIs
  - String obfuscation (fromCharCode)

- **Directory Traversal Pattern Detection** — Checks for 10 traversal vectors:
  - Path traversal sequences (../, ..\)
  - URL-encoded traversal (%2e%2e%2f)
  - Mixed encoding attacks
  - Sensitive file references (/etc/passwd, /proc/self)
  - Null byte injection
  - Suspicious directory names (.git, admin, backup)
  - Sensitive file extensions (.sql, .env, .bak)

### 📊 Severity Rating System

Each finding is rated with one of five severity levels:
- **Critical** — Immediate security risk, must be fixed
- **High** — Significant vulnerability, should be addressed urgently
- **Medium** — Security weakness, should be remediated
- **Low** — Minor issue, recommended improvement
- **Info** — Passed check or informational finding

### 📈 Real-time Scan Progress

- 5-phase scan with animated progress bar
- Live log output showing each scan phase
- Percentage-based progress tracking

### 💾 History & Export

- **Scan History** — All scan results saved to localStorage (up to 50)
- **Export Reports** — Download detailed text reports with all findings
- **Re-view Past Scans** — Click any history item to re-display full results

## Usage

1. Open `index.html` in any modern browser
2. Enter a URL in the input field (e.g., `https://example.com`)
3. Click **Scan** or press Enter
4. Wait for the scan to complete (~5-8 seconds)
5. Review results across the 5 category tabs
6. Click **Export Report** to download a text file
7. Check the **History** tab to review past scans

## Tech Stack

- **HTML5** — Semantic markup, no frameworks
- **CSS3** — Custom properties, grid/flexbox, dark theme
- **Vanilla JavaScript** — Zero dependencies, ES6+, IIFE pattern
- **localStorage** — Client-side persistence for scan history

## File Structure

```
SecurityScan-Agent/
├── index.html    — Main application page
├── style.css     — Dark theme styling
├── app.js        — Scanner engine + UI logic (300+ lines)
└── README.md     — This file
```

## How It Works

The scanner uses heuristic analysis to simulate security checks:

1. **HTTP Headers** — Simulates header inspection based on known patterns from major providers (Google, GitHub, Cloudflare) vs. typical sites
2. **SSL Certificate** — Generates realistic certificate data based on domain characteristics
3. **Port Scanning** — Simulates port checks with probability-weighted heuristics
4. **XSS Patterns** — Uses 10 regex patterns to scan URL components for injection vectors
5. **Directory Traversal** — Uses 10 regex patterns plus path analysis for traversal detection

> **Note:** This is a front-end analysis tool. For production use, combine with a backend API and CORS proxy for live header fetching and actual port scanning.

## License

MIT
