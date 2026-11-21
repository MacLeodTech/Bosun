# Security policy

Bosun sits between a browser and the internet, holds a certificate authority that can impersonate any site to
a browser that trusts it, and reads attacker-controlled content all day. Security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting: on the repository page choose
**Security -> Report a vulnerability**. Include what you found, the version (`bosun --version`), and the steps
to reproduce it. This is a small project, so please allow a few days for an answer.

Once a fix is released the report can be made public, and you will be credited if you wish.

## What is in scope

- Getting around sign-in, roles, sessions, CSRF, Host or Origin checks on the UI/API.
- A web page or response viewed or proxied through Bosun that can run script in the UI's origin, read the
  API, open the event stream, or otherwise act as the signed-in user.
- Using the proxy as an open proxy, or reaching the UI/API through the proxy.
- Reading the CA private key, the data key, password hashes, session or API tokens without the access the threat
  model says is needed.
- An active tool, scanner or plugin sending traffic to a target outside the configured scope.
- Memory corruption, crashes or unbounded resource use triggered by traffic (malformed HTTP, TLS, WebSocket
  frames, compressed bodies) or by a project file.

## Not in scope

- Anything that needs the attacker to already control the machine, the data directory or the data key.
- Installing the CA in a system trust store and then being impersonated by whoever holds the key
  (`bosun doctor` warns about this; the launched browser pins the CA without installing it).
- Running the UI on a network without TLS, or the proxy on a public address with authentication you chose to
  disable after reading the warnings.
- Findings that a scan reports about a target. Those are the product working.

## Supported versions

Only the latest release gets fixes.
