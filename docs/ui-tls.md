# HTTPS for the web UI

The UI and API listen on loopback over plain HTTP by default, which is fine on a single machine. Anywhere else
(a server, a container, a shared lab network) put TLS in front of them.

**Never trust Bosun's interception CA in your everyday browser to make the UI's warning go away.** Whoever holds
that CA's key can impersonate any site to a browser that trusts it. The UI never uses the CA's certificates.

## Recommended: a reverse proxy

Run Bosun's UI on loopback (or a private container network) and let a reverse proxy terminate TLS with a real
certificate:

```
# Caddy
bosun.lab.example {
    reverse_proxy 127.0.0.1:8090
}
```

```
# nginx
server {
    listen 443 ssl;
    server_name bosun.lab.example;
    ssl_certificate     /etc/ssl/bosun.crt;
    ssl_certificate_key /etc/ssl/bosun.key;
    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;       # the live event stream is a WebSocket
        proxy_set_header Connection "upgrade";
    }
}
```

Then tell Bosun about it in `bosun.toml`:

```toml
[api]
hosts = ["bosun.lab.example"]                 # the Host header it will see
origins = ["https://bosun.lab.example"]       # the Origin header it will see
secure_cookies = true
trusted_proxies = ["127.0.0.1/32"]            # believe X-Forwarded-For / -Proto only from the proxy
```

Without `trusted_proxies` every client looks like the proxy's address (sign-in limits then apply to everyone
together) and the forwarded headers are ignored.

## Bosun terminates TLS itself

```toml
[api]
tls = true
tls_cert = "/etc/bosun/ui.crt"   # PEM chain, leaf first
tls_key  = "/etc/bosun/ui.key"
```

The files are re-read when they change (checked every ten seconds) and on `SIGHUP`, so a renewal needs no restart.
If a new file fails to load, the old certificate stays in service and a warning is logged.

With `tls = true` and no files, Bosun makes a **self-signed certificate for the UI only** (in `<data>/ui-tls/`, its
key sealed with the data key, valid for a year and renewed automatically, remade if `api.hosts` changes). It is not a
CA, so trusting it lets nobody impersonate anything but this UI. Your browser will warn once; compare the
fingerprint printed at start-up before accepting.

`bosun doctor` warns when the UI is reachable from the network without TLS and checks that certificate files exist.
