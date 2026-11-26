# Scanning from CI with `bosun scan`

`bosun scan URL` crawls a site, runs the active checks over what it found, prints the findings, can write a SARIF
file, and sets the exit code from a severity threshold. It needs no UI and no account.

```sh
bosun scan https://staging.example.com --fail-on high --sarif bosun.sarif
```

## How it runs

- With no `--server`, it starts an engine inside the process: a throwaway data directory, listeners on loopback
  only, no web UI used. The engine is stopped when the scan ends. Give the global `--data-dir` to keep the
  project (flows and issues) instead.
- With `--server URL` (or `$BOSUN_SERVER` and `$BOSUN_TOKEN`, or `--profile`) it drives an engine you already run,
  through the API. The token needs the tester role. The target's host is added to that engine's scope; its other
  scope rules stay.
- The scope is the target URL's host and port (`--also-scope HOST` adds more). Every request goes through the
  scope gate, so nothing outside it is contacted. Requests of an import that are outside it are listed and
  skipped. A target on `localhost` or a private address also needs `--allow-private`.

## What is scanned

- A URL: it is crawled (`--max-depth`, `--max-pages`), and the pages, `GET` forms and (only with `--post-forms`)
  `POST` forms found become the targets. `--no-crawl` scans just the URL.
- `--import FILE --import-format openapi|har|postman|burp|graphql|urls` scans the requests of an API definition or
  a recording instead; give `--base-url` when the file has no server. Imports are parsed by the same code as
  `bosun import`.
- `-H 'Authorization: Bearer ...'` adds a header to every request. Put secrets in CI secrets and pass them
  through the environment, not on the command line of a shared runner.
- `--strength low|medium|high`, `--check ID` (repeatable), `--max-requests N`, `--concurrency N` and
  `--timeout SECONDS` bound the work.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No finding at or above `--fail-on` (default `high`; `none` never fails on findings) |
| 1 | Error (bad arguments, no engine, unreadable file) |
| 2 | A finding at or above `--fail-on` |
| 4 | The scan did not finish (failed, stopped or timed out) and nothing reached the threshold |

The exit code looks at the findings of this scan. The SARIF file holds every issue of the project, so with
`--server` it can also hold older issues and the passive scanner's findings on the scan traffic.

Progress lines go to stderr (`--quiet` turns them off) and findings to stdout. `--json FILE` writes the scan
result. The engine also sends `scan_started`, `scan_progress` (at most four a second) and `scan_done` events on
`/events`, which is what a UI watches.

## GitHub Actions

```yaml
name: dast
on:
  pull_request:
  schedule: [{ cron: "0 3 * * *" }]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - name: Start the app under test
        run: docker compose up -d --wait   # your own service, on http://localhost:8080
      - name: Scan
        run: |
          docker run --rm --network host -v "$PWD:/out" -w /out \
            bosun:latest scan http://localhost:8080 --allow-private \
            --fail-on high --sarif /out/bosun.sarif
      - name: Upload to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bosun.sarif
```

The container runs as a non-root user (65532): make the mounted directory writable for it, or write the SARIF
file under `/tmp` and copy it out another way. To scan with a binary instead of the image, download or build
`bosun` and run the same `bosun scan` line. Only scan systems you own or are allowed to test.

## GitLab CI

```yaml
dast:
  stage: test
  image:
    name: bosun:latest          # your registry's path for the image
    entrypoint: [""]
  services:
    - name: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
      alias: app
  script:
    - /usr/local/bin/bosun scan http://app:8080 --allow-private --fail-on high --sarif gl-bosun.sarif
  artifacts:
    when: always
    paths: [gl-bosun.sarif]
```

The distroless image has no shell, so each CI step has to call `bosun` directly (`entrypoint: [""]` and a single
command, as above). Where a service in the same job is reached by a private address, `--allow-private` is needed.

## Container use

```sh
docker run --rm bosun:latest scan https://staging.example.com --fail-on medium
docker run --rm -v "$PWD:/work" bosun:latest scan --import /work/openapi.yaml \
  --base-url https://staging.example.com
```

The image's entrypoint is `bosun`, so the arguments are the arguments of `bosun scan`. The scan engine needs no
volume: its data lives in `/tmp` for the length of the run.
