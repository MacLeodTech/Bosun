# Competitive analysis and gaps

Written 2026-11-25. This compares Bosun's roadmap with the tools a web security tester reaches for, and lists what
the roadmap does not yet cover. Sources for the first four tools were read online on that date; for Wireshark, Nmap,
sqlmap and Nessus the notes come from general knowledge of those tools, not from a fresh look.

How to read it: **Covered** means a work package in `roadmap.md` delivers it. **Gap** means no work package does.
The gaps became work packages WP-75 to WP-86 in `roadmap.md` (index, phase plan, details and milestone checklists).

## Proxies: Burp, Caido, mitmproxy, Proxyman

| Capability | Seen in | Bosun |
|---|---|---|
| Intercept, history, scope, site map, match-and-replace | all | Done (M1) |
| Repeater with tabs, history, HTTP/2, race (single-packet) | Burp, Caido (Replay, with parallel and sequenced send) | Mostly done (WP-41); WebSocket sends and saved tabs open |
| Intruder-style fuzzing | Burp, Caido (Automate, custom extractors and columns) | Covered (WP-47) |
| Decoder, Comparer, Organizer, Logger | Burp | Covered (WP-42, WP-43) |
| Collaborator (OAST) | Burp | Covered (WP-58, WP-59) |
| Passive and active scanner, custom checks | Burp (BChecks), Caido, ZAP | Covered (WP-49 to WP-55, WP-50 check language) |
| Plugins | Burp BApps, Caido JS and backend plugins | Covered (WP-61, WP-62, WASM) |
| WebSocket capture | all | Done |
| HTTP/3 | Burp, mitmproxy | Covered (WP-74) |
| **Query language for history** (typed filters over headers, body, status, tags, saved presets) | Caido HTTPQL, Burp Bambdas | **Gap**: WP-43 mentions columns and sorting only |
| **Workflows**: visual or scripted pipelines that convert, tag, or react to traffic without writing a full plugin | Caido Workflows | **Gap**: plugins cover it in theory, but a no-code layer is missing |
| **Map Local and Map Remote** (answer a request from a file, or redirect it to another host) | Proxyman, Fiddler | **Gap**: match-and-replace edits messages but cannot serve a file or reroute |
| **Throttle and latency simulation** | Proxyman, Burp (resource pools only for Intruder) | **Gap** |
| **Mobile and device capture**: guided setup for iOS and Android, per-app capture | Proxyman, mitmproxy (WireGuard and local capture modes) | **Gap**: no WireGuard, local-capture or device-setup work |
| **Reverse-proxy mode** (sit in front of one upstream) | mitmproxy | **Gap** (the roadmap only mentions it in passing) |
| **gRPC and Protobuf** decode and edit | Proxyman, Burp (extension) | **Gap** |
| **GraphQL-aware** matching and editing (by operation name) | Proxyman, Burp | Partly: imports only (WP-60) |
| **Export**: HAR, curl, copy as code | all | Partly: HAR import is planned; export of single messages as curl or HAR is not |
| **TLS key log export** (`SSLKEYLOGFILE`) so Wireshark can decrypt captures | mitmproxy | **Gap** |
| Python or JS scripting of traffic | mitmproxy addons, Proxyman scripting | Covered by WASM plugins, but with a higher barrier |
| AI assistance (explain a response, suggest tests, agent mode) | Burp AI and Burp AT, Caido's Shift plugin | **Gap**; a local-model, off-by-default design would fit the threat model |
| Shared projects and collaboration | Burp Collections, Caido Cloud | Covered (WP-64) |

## Network and exploitation tools

Bosun is a web tool, so most of these are out of scope on purpose. The useful question is which web-facing parts to
borrow.

| Tool | What it does | Bosun |
|---|---|---|
| **Wireshark** | Packet capture and dissection | Out of scope as a packet tool. Worth borrowing: TLS key log export (above), and an HTTP/2 frame view in the message viewer, which `bosun-http` already parses. |
| **Nmap** | Port scanning, service detection, NSE scripts | Out of scope as a network scanner. Worth borrowing: a light technology and service **fingerprint** of in-scope web hosts (server banner, framework, version), which feeds the vulnerable-component check below. |
| **sqlmap** | Detects and exploits SQL injection (database fingerprinting, data extraction, tamper scripts) | Detection is covered (WP-55). **Gap**: an opt-in exploitation helper (confirm injection type, identify the database, tamper transforms for WAF bypass). Needs the destructive-check gating and an explicit user confirmation per target. |
| **Nessus** | Network vulnerability scanning against a CVE database | Out of scope as a host scanner. **Gap** worth closing at web level: detect known-vulnerable components from versions seen in responses and match them against an offline advisory feed (CVE, OSV). |

## DAST tools: ZAP, Nuclei, ffuf and others

| Capability | Seen in | Bosun |
|---|---|---|
| Spider, AJAX spider, active scan, policies, CI mode | ZAP | Covered (WP-52 to WP-57) |
| Nuclei templates | Nuclei | Covered (subset, WP-50) |
| Authenticated scanning, login macros, session handling | ZAP, Burp | Covered (WP-56) |
| OpenAPI, GraphQL, Postman imports and API scanning | ZAP, Burp | Covered (WP-60) |
| Reports: HTML, JSON, SARIF, JUnit | ZAP, Burp | Covered (WP-51) |
| Access-control and IDOR matrix | Burp (Autorize), ZAP | Covered (WP-56) |
| **Content discovery** (forced browsing of paths, files and parameters from wordlists) | ffuf, feroxbuster, ZAP Forced Browse, Burp Discover Content | **Gap**: Intruder with wordlists can do it by hand, but there is no dedicated recursive tool with soft-404 detection |
| **Parameter discovery** | Param Miner, Arjun | **Gap** |
| **Subdomain and asset discovery** | amass, subfinder | Deliberately out of scope until the scope gate can cover discovered hosts; note as a later option |
| **WAF detection and evasion hints** | wafw00f, sqlmap | **Gap** (small) |
| **JWT and OAuth tooling** (decode, alg=none, key confusion, replay) | Burp JWT Editor, ZAP | Partly: decoder handles JWT; attacks fall under WP-63 for OAuth only |
| **DOM XSS taint tracking** | Burp DOM Invader | Covered only as "DOM XSS through browser instrumentation" (WP-63); no testing browser extension or helper UI |
| **Scheduled and recurring scans, scan diffing over time** | ZAP automation framework, Burp DAST | **Gap**: `bosun scan` exists for CI, but no scheduler or comparison of two runs |
| **Vulnerable-component detection (SCA-lite)** | Nessus, Retire.js | **Gap** (see above) |
| **Issue tracker export** (Jira, GitHub, Linear) | Burp, ZAP add-ons | **Gap** (SARIF covers GitHub code scanning only) |
| API security checks for common API Top 10 issues (BOLA, mass assignment, rate limiting) | ZAP, 42Crunch, Burp | Partly: authorisation matrix covers BOLA; mass assignment and rate-limit checks are not listed |

## UI: lessons from Burp and Caido

These come from published comparisons and release notes, not hands-on use of either product. Check them against the
tools before committing to a design.

- **A command palette** (Burp has a quick launcher; Caido leans on a keyboard-first flow). Bosun has none, and the
  roadmap does not list one. It is cheap with a Svelte UI and helps keyboard users and accessibility (WP-73).
- **A query bar over history** with autocomplete, saved filters and history of past queries. This is the single UI
  feature Caido users praise most (the HTTPQL gap above).
- **Tabs and layout**: Burp lets users rearrange tabs and split panes; Repeater tabs can be grouped. Bosun's Repeater
  has tabs but no grouping, drag to reorder, or split view.
- **One place for history, Replay and findings** with the same message viewer everywhere (Caido). Bosun's message
  viewer exists for History; WP-44 covers a shared editor. Make sure every tool uses the same one.
- **Collections of requests** (Burp Collections and Organizer notes, Caido Replay collections): saved, named groups of
  requests with notes. Planned only as the Organizer (WP-43); tabs are not saved in the project yet.
- **Themes**: Bosun has light and dark; WP-73 covers the audit. Burp and Caido both offer themes and font size.
- **Onboarding**: Caido and Proxyman set up a browser or device in a few clicks. WP-21 covers browser provisioning;
  mobile has no plan.
- **Keep Bosun's own strengths**: safer defaults (scope gate on every send, target content never rendered in the UI's
  origin, an out-of-scope policy that resets) are the main reason to choose it over the others. New features should
  keep them.

## New work packages

All are in `roadmap.md` (the details are under "WP-75 to WP-86"; the phases there are the plan). Sizes are rough. All need the threat model checked before they land.

| WP | Title | Size | Notes |
|---|---|---|---|
| WP-75 | History query language and saved filters | M | Parser with a fuzz target; also drives Logger and Intruder results |
| WP-76 | Map Local, Map Remote, throttling | M | Extends the rules engine; map-remote must pass the scope gate |
| WP-77 | Export: copy as curl, HAR export, code snippets | S | Quick win; redact secrets by default |
| WP-78 | Proxy modes: reverse proxy, WireGuard or local capture, TLS key log file | L | Mobile capture guides on top; biggest effort is the network stack |
| WP-79 | gRPC and Protobuf, GraphQL-aware views and rules | M | New decoders: fuzz targets needed |
| WP-80 | Command palette and shared message viewer | M | Fits with WP-44 and WP-73 |
| WP-81 | Content and parameter discovery | M | Reuses Intruder and the crawler; soft-404 detection; rate limited by the scope gate |
| WP-82 | Technology fingerprint and known-vulnerable components | M | Offline advisory feed (OSV), signed updates like check feeds |
| WP-83 | SQL injection exploitation helper (opt-in) | L | Destructive-class; per-target confirmation and audit entry |
| WP-84 | Scheduled scans and scan diff | M | Builds on `bosun scan` |
| WP-85 | Issue tracker export | S | Outbound calls go through an allow list the user sets |
| WP-86 | Optional AI assistance | L | Off by default; a local or user-supplied endpoint only; nothing leaves the machine unless configured. Treat model output as untrusted input |

Suggested order: WP-77 and WP-75 first (small, daily value), then WP-76, WP-80 and WP-81. WP-78 and WP-86 are the
largest, and their value depends on who the users turn out to be.
