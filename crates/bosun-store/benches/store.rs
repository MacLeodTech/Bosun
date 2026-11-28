//! Storage at scale: write rate, history queries, delete, and bytes per flow.
//!
//! `cargo bench -p bosun-store` fills a project with 1,000,000 flows (a few minutes). `BOSUN_BENCH_FLOWS=50000`
//! is the CI-sized mode. The budgeted figures are also written to `$BOSUN_BENCH_OUT` (default `target/store-bench.txt`) as
//! `name=value` lines for `scripts/footprint.py check`; the others (raw size, the first layout's size) are only
//! printed.
//!
//! The traffic is made to look like browsing: 200 hosts, many paths, a few hundred distinct response bodies, and
//! request and response headers that differ on every flow (`Date`, cookies), so only the bodies can be shared.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::fmt::Write as _;
use std::time::Instant;

use bosun_model::{FlowSource, Scheme};
use bosun_store::{FlowFilter, NewFlow, Project};
use criterion::{Criterion, criterion_group, criterion_main};

fn total() -> usize {
    std::env::var("BOSUN_BENCH_FLOWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000)
}

fn bodies() -> Vec<String> {
    (0..400)
        .map(|i| {
            let mut s = format!("<html><head><title>page {i}</title></head><body>");
            for j in 0..40 {
                let _ = write!(
                    s,
                    "<div class=\"row r{}\"><a href=\"/item/{i}/{j}\">item {i}-{j}</a></div>",
                    j % 7
                );
            }
            s.push_str("</body></html>");
            s
        })
        .collect()
}

fn flow(p: &Project, n: usize, bodies: &[String]) -> NewFlow {
    let host = format!("app{}.example{}.test", n % 200, n % 7);
    let ext = ["html", "js", "css", "png", "json"][n % 5];
    let path = format!("/p{}/f{}.{ext}", n % 5000, n % 31);
    let body = &bodies[(n * 31) % bodies.len()];
    NewFlow {
        id: p.next_flow_id(),
        source: FlowSource::Proxy,
        started_ms: 1_700_000_000_000 + n as i64,
        duration_ms: Some(12),
        ttfb_ms: Some(4),
        scheme: Scheme::Https,
        host: host.clone(),
        port: 443,
        method: if n.is_multiple_of(9) { "POST" } else { "GET" }.into(),
        path: path.clone(),
        http_version: "HTTP/1.1".into(),
        status: Some([200, 200, 200, 301, 404][n % 5]),
        in_scope: !n.is_multiple_of(3),
        edited: false,
        error: None,
        request: format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0\r\n\
             Accept: */*\r\nCookie: sid={n:016x}; theme=dark\r\n\r\n"
        )
        .into_bytes(),
        original_request: None,
        response: Some(
            format!(
                "HTTP/1.1 200 OK\r\nDate: Tue, 01 Jan 2030 00:{:02}:{:02} GMT\r\nContent-Type: text/html; charset=utf-8\r\n\
                 Set-Cookie: sid={n:016x}; HttpOnly; Secure\r\nContent-Length: {}\r\n\r\n{body}",
                (n / 60) % 60,
                n % 60,
                body.len()
            )
            .into_bytes(),
        ),
        original_response: None,
        response_truncated: false,
    }
}

fn bench(c: &mut Criterion) {
    let n = total();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench.bosun");
    let p = Project::open(&path).unwrap();
    let bodies = bodies();
    let mut out = String::new();
    let mut info = String::new();

    // Write rate, in batches as the proxy's recorder does.
    let t = Instant::now();
    let mut batch = Vec::with_capacity(500);
    let mut raw = 0usize;
    let mut v1 = 0usize;
    for i in 0..n {
        let f = flow(&p, i, &bodies);
        raw += f.request.len() + f.response.as_ref().map_or(0, Vec::len);
        // What the first layout stored for this flow: each whole message compressed, none of it shared.
        v1 += zstd::bulk::compress(&f.request, 3).unwrap().len()
            + f.response
                .as_ref()
                .map_or(0, |r| zstd::bulk::compress(r, 3).unwrap().len());
        batch.push(f);
        if batch.len() == 500 {
            p.write_batch(&batch, &[]).unwrap();
            batch.clear();
        }
    }
    p.write_batch(&batch, &[]).unwrap();
    let secs = t.elapsed().as_secs_f64();
    let _ = writeln!(out, "store_insert_flows_per_s={:.0}", n as f64 / secs);

    // Bytes on disk per flow, against the raw message bytes.
    let wal = path.with_extension("bosun-wal");
    let size =
        (std::fs::metadata(&path).unwrap().len() + std::fs::metadata(&wal).map_or(0, |m| m.len())) as f64;
    let _ = writeln!(out, "store_bytes_per_flow={:.0}", size / n as f64);
    let _ = writeln!(info, "store_raw_bytes_per_flow={:.0}", raw as f64 / n as f64);

    // Message bytes as stored now (heads on the rows plus the shared bodies), without the full-text index.
    let _ = writeln!(
        info,
        "store_v1_message_bytes_per_flow={:.0}",
        v1 as f64 / n as f64
    );
    let conn =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let heads: i64 = conn
        .query_row(
            "SELECT coalesce(sum(coalesce(length(req_head),0)+coalesce(length(resp_head),0)),0) FROM flows",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let blobs: i64 = conn
        .query_row("SELECT coalesce(sum(length(data)),0) FROM blobs", [], |r| {
            r.get(0)
        })
        .unwrap();
    let _ = writeln!(
        out,
        "store_message_bytes_per_flow={:.0}",
        (heads + blobs) as f64 / n as f64
    );
    drop(conn);

    let mut g = c.benchmark_group(format!("store/{n}_flows"));
    g.sample_size(10);
    let mut time = |name: &str, f: &dyn Fn()| {
        let t = Instant::now();
        let k = 20;
        for _ in 0..k {
            f();
        }
        let ms = t.elapsed().as_secs_f64() * 1000.0 / f64::from(k);
        let _ = writeln!(out, "{name}={ms:.2}");
    };
    let pr = &p;
    let list = |f: FlowFilter| {
        move || {
            pr.list_flows(&f).unwrap();
        }
    };
    let latest = FlowFilter {
        limit: Some(100),
        ..Default::default()
    };
    g.bench_function("list_latest_100", |b| b.iter(list(latest.clone())));
    time("store_list_latest_ms", &list(latest));
    let ext = FlowFilter {
        limit: Some(100),
        hide_extensions: Some(vec!["png".into(), "css".into()]),
        ..Default::default()
    };
    g.bench_function("list_hide_extensions", |b| b.iter(list(ext.clone())));
    time("store_list_ext_ms", &list(ext));
    let scoped = FlowFilter {
        limit: Some(100),
        in_scope_only: true,
        status_min: Some(400),
        ..Default::default()
    };
    g.bench_function("list_scope_status", |b| b.iter(list(scoped.clone())));
    time("store_list_scope_status_ms", &list(scoped));
    g.bench_function("flow_count", |b| b.iter(|| pr.flow_count().unwrap()));
    g.bench_function("get_flow", |b| b.iter(|| pr.get_flow((n / 2) as i64).unwrap()));
    time("store_get_flow_ms", &|| {
        pr.get_flow((n / 2) as i64).unwrap();
    });
    g.finish();

    // Deleting a thousand flows must not depend on the table's size.
    let ids: Vec<i64> = (1..=1000)
        .map(|i| (i * (n as i64 / 1000).max(1)).min(n as i64))
        .collect();
    let t = Instant::now();
    p.delete_flows(&ids).unwrap();
    let _ = writeln!(
        out,
        "store_delete_1000_ms={:.1}",
        t.elapsed().as_secs_f64() * 1000.0
    );

    print!("{info}{out}");
    let dest = std::env::var("BOSUN_BENCH_OUT").unwrap_or_else(|_| "target/store-bench.txt".into());
    let _ = std::fs::write(dest, out);
}

criterion_group!(benches, bench);
criterion_main!(benches);
