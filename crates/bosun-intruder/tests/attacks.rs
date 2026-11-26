#![allow(clippy::unwrap_used)]
//! Attacks against a local server: each attack type, grep, the delay, retries, the gate's rate limit and the
//! stop switch.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bosun_http::{Engine, Exchange};
use bosun_intruder::{
    Attack, AttackType, Finish, GrepExtract, GrepMatch, Greps, Options, PayloadSet, PayloadSource, Plan,
    Processing, Progress, Row, Sink, Stop, Summary, Template, run,
};
use bosun_model::{Scheme, Target};
use bosun_proxy::budget::MemoryBudget;
use bosun_scope::{Gate, RuleSpec, Scope, ScopeSpec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Answers `200` with `you asked for <target>` (and `404` when the target holds `missing`), after `delay`.
struct Server {
    addr: SocketAddr,
    /// Each request's target and when it arrived.
    seen: Arc<Mutex<Vec<(String, Instant)>>>,
}

async fn server(delay: Duration) -> Server {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let log = log.clone();
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&got);
                let target = line.split(' ').nth(1).unwrap_or("").to_string();
                log.lock().unwrap().push((target.clone(), Instant::now()));
                tokio::time::sleep(delay).await;
                let (status, body) = if target.contains("missing") {
                    ("404 Not Found", format!("nothing at {target}"))
                } else {
                    (
                        "200 OK",
                        format!("you asked for {target} token=T{}", target.len()),
                    )
                };
                let reply = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(reply.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    Server { addr, seen }
}

#[derive(Default)]
struct Collect {
    rows: Mutex<Vec<Row>>,
    next: AtomicI64,
}

impl Sink for Collect {
    fn record(&self, _ex: &Exchange) -> Option<i64> {
        Some(self.next.fetch_add(1, Ordering::SeqCst) + 1)
    }
    fn row(&self, row: Row) {
        self.rows.lock().unwrap().push(row);
    }
}

fn gate() -> Gate {
    let scope = Scope::compile(ScopeSpec {
        include: vec![RuleSpec {
            host: "127.0.0.1".into(),
            allow_private: true,
            ..Default::default()
        }],
        exclude: vec![],
    })
    .unwrap();
    Gate::new(scope)
}

fn list(items: &[&str]) -> PayloadSet {
    PayloadSet {
        source: PayloadSource::List {
            items: items.iter().map(|s| (*s).to_string()).collect(),
        },
        processing: vec![],
    }
}

fn attack(
    gate: Gate,
    addr: SocketAddr,
    kind: AttackType,
    req: &str,
    sets: &[PayloadSet],
    options: Options,
) -> Attack {
    let plan = Plan::new(Template::parse(req.as_bytes()).unwrap(), kind, sets).unwrap();
    Attack {
        engine: Engine::new(gate, MemoryBudget::new(64 << 20)),
        target: Target::new(Scheme::Http, addr.ip().to_string(), addr.port()),
        plan: Arc::new(plan),
        options,
        greps: Greps::default(),
    }
}

async fn go(a: Attack) -> (Summary, Vec<Row>) {
    let sink = Arc::new(Collect::default());
    let s = run(a, sink.clone(), Arc::new(Progress::default()), Stop::new())
        .await
        .unwrap();
    let mut rows = sink.rows.lock().unwrap().clone();
    rows.sort_by_key(|r| r.index);
    (s, rows)
}

fn paths(srv: &Server) -> Vec<String> {
    let mut v: Vec<String> = srv.seen.lock().unwrap().iter().map(|(t, _)| t.clone()).collect();
    v.sort();
    v
}

const REQ2: &str = "GET /§a§/§b§ HTTP/1.1\r\nHost: x\r\n\r\n";

#[tokio::test]
async fn sniper_attacks_each_position_in_turn() {
    let srv = server(Duration::ZERO).await;
    let a = attack(
        gate(),
        srv.addr,
        AttackType::Sniper,
        REQ2,
        &[list(&["1", "2"])],
        Options::default(),
    );
    let (s, rows) = go(a).await;
    assert_eq!(s.finish, Finish::Completed);
    assert_eq!(s.done, 4);
    assert_eq!(paths(&srv), ["/1/b", "/2/b", "/a/1", "/a/2"]);
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[2].position, Some(1));
    assert!(rows.iter().all(|r| r.status == Some(200) && r.flow_id.is_some()));
}

#[tokio::test]
async fn battering_ram_puts_one_payload_in_every_position() {
    let srv = server(Duration::ZERO).await;
    let a = attack(
        gate(),
        srv.addr,
        AttackType::BatteringRam,
        REQ2,
        &[list(&["x", "y"])],
        Options::default(),
    );
    let (_, rows) = go(a).await;
    assert_eq!(paths(&srv), ["/x/x", "/y/y"]);
    assert_eq!(rows[0].payloads, ["x"]);
}

#[tokio::test]
async fn pitchfork_pairs_payloads_by_position() {
    let srv = server(Duration::ZERO).await;
    let a = attack(
        gate(),
        srv.addr,
        AttackType::Pitchfork,
        REQ2,
        &[list(&["1", "2", "3"]), list(&["a", "b"])],
        Options::default(),
    );
    let (s, rows) = go(a).await;
    assert_eq!(s.done, 2);
    assert_eq!(paths(&srv), ["/1/a", "/2/b"]);
    assert_eq!(rows[1].payloads, ["2", "b"]);
}

#[tokio::test]
async fn cluster_bomb_sends_every_combination() {
    let srv = server(Duration::ZERO).await;
    let a = attack(
        gate(),
        srv.addr,
        AttackType::ClusterBomb,
        REQ2,
        &[list(&["1", "2"]), list(&["a", "b", "c"])],
        Options {
            concurrency: 6,
            ..Options::default()
        },
    );
    let (s, _) = go(a).await;
    assert_eq!(s.done, 6);
    assert_eq!(paths(&srv), ["/1/a", "/1/b", "/1/c", "/2/a", "/2/b", "/2/c"]);
}

#[tokio::test]
async fn processing_numbers_and_grep_show_in_the_rows() {
    let srv = server(Duration::ZERO).await;
    let mut set = PayloadSet {
        source: PayloadSource::Numbers {
            from: 1,
            to: 3,
            step: 1,
            base: bosun_intruder::NumberBase::Decimal,
            min_digits: 0,
        },
        processing: vec![Processing::Prefix { value: "id".into() }],
    };
    set.processing.push(Processing::Suffix {
        value: "_missing".into(),
    });
    set.processing.push(Processing::SkipIfMatches {
        pattern: "id2".into(),
    });
    let mut a = attack(
        gate(),
        srv.addr,
        AttackType::Sniper,
        "GET /§a§ HTTP/1.1\r\n\r\n",
        &[set],
        Options::default(),
    );
    a.greps = Greps {
        matches: vec![
            GrepMatch {
                pattern: "NOTHING AT".into(),
                regex: false,
                case_insensitive: true,
            },
            GrepMatch {
                pattern: "token=".into(),
                regex: false,
                case_insensitive: false,
            },
        ],
        extracts: vec![GrepExtract {
            pattern: r"nothing at /(\w+)".into(),
        }],
    };
    let (s, rows) = go(a).await;
    assert_eq!((s.done, s.skipped), (2, 1));
    assert_eq!(rows[0].status, Some(404));
    assert_eq!(rows[0].matches, [true, false]);
    assert_eq!(rows[0].extracts, [Some("id1_missing".to_string())]);
    assert_eq!(rows[1].payloads, ["id3_missing"]);
    assert!(rows[0].length > 0);
}

#[tokio::test]
async fn null_payloads_repeat_the_request() {
    let srv = server(Duration::ZERO).await;
    let set = PayloadSet {
        source: PayloadSource::Null { count: 5 },
        processing: vec![],
    };
    let a = attack(
        gate(),
        srv.addr,
        AttackType::BatteringRam,
        "GET /§x§ HTTP/1.1\r\n\r\n",
        &[set],
        Options::default(),
    );
    let (s, _) = go(a).await;
    assert_eq!(s.done, 5);
    assert!(paths(&srv).iter().all(|p| p == "/"));
}

#[tokio::test]
async fn the_gates_rate_limit_holds_and_nothing_is_dropped() {
    let srv = server(Duration::ZERO).await;
    let g = gate();
    g.set_rate_limit(5);
    let items: Vec<String> = (0..12).map(|i| i.to_string()).collect();
    let set = PayloadSet {
        source: PayloadSource::List { items },
        processing: vec![],
    };
    let a = attack(
        g,
        srv.addr,
        AttackType::Sniper,
        "GET /§a§ HTTP/1.1\r\n\r\n",
        &[set],
        Options {
            concurrency: 8,
            ..Options::default()
        },
    );
    let (s, rows) = go(a).await;
    assert_eq!((s.finish, s.done), (Finish::Completed, 12));
    assert!(rows.iter().all(|r| r.status == Some(200)), "{rows:?}");
    // No stretch of 900 ms (the gate counts at its check, a little before arrival) saw more than 5 requests.
    let times: Vec<Instant> = srv.seen.lock().unwrap().iter().map(|(_, t)| *t).collect();
    for t in &times {
        let n = times
            .iter()
            .filter(|u| **u >= *t && u.duration_since(*t) < Duration::from_millis(900))
            .count();
        assert!(n <= 5, "{n} requests in 900 ms");
    }
}

#[tokio::test]
async fn the_delay_spaces_request_starts() {
    let srv = server(Duration::ZERO).await;
    let set = PayloadSet {
        source: PayloadSource::Null { count: 5 },
        processing: vec![],
    };
    let a = attack(
        gate(),
        srv.addr,
        AttackType::BatteringRam,
        "GET /§x§ HTTP/1.1\r\n\r\n",
        &[set],
        Options {
            concurrency: 5,
            delay_ms: 100,
            ..Options::default()
        },
    );
    let t = Instant::now();
    let (s, _) = go(a).await;
    assert_eq!(s.done, 5);
    assert!(t.elapsed() >= Duration::from_millis(400), "{:?}", t.elapsed());
}

#[tokio::test]
async fn failed_requests_are_retried_and_reported() {
    // Nothing listens here.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let a = attack(
        gate(),
        addr,
        AttackType::Sniper,
        "GET /§a§ HTTP/1.1\r\n\r\n",
        &[list(&["1"])],
        Options {
            retries: 1,
            ..Options::default()
        },
    );
    let (s, rows) = go(a).await;
    assert_eq!((s.done, s.errors), (1, 1));
    assert_eq!(rows[0].attempts, 2);
    assert!(rows[0].error.is_some() && rows[0].status.is_none());
}

#[tokio::test]
async fn a_target_out_of_scope_fails_the_attack_and_sends_nothing() {
    let srv = server(Duration::ZERO).await;
    let a = attack(
        Gate::new(Scope::default()),
        srv.addr,
        AttackType::Sniper,
        "GET /§a§ HTTP/1.1\r\n\r\n",
        &[list(&["1", "2"])],
        Options::default(),
    );
    let (s, rows) = go(a).await;
    assert!(
        matches!(s.finish, Finish::Failed(ref m) if m.contains("out of scope")),
        "{:?}",
        s.finish
    );
    assert!(rows.is_empty());
    assert!(paths(&srv).is_empty());
}

#[tokio::test]
async fn the_stop_switch_halts_at_once() {
    // Each answer takes two seconds, so most of the 100 requests are waiting or in flight when it is thrown.
    let srv = server(Duration::from_secs(2)).await;
    let set = PayloadSet {
        source: PayloadSource::Null { count: 100 },
        processing: vec![],
    };
    let a = attack(
        gate(),
        srv.addr,
        AttackType::BatteringRam,
        "GET /§x§ HTTP/1.1\r\n\r\n",
        &[set],
        Options {
            concurrency: 3,
            ..Options::default()
        },
    );
    let sink = Arc::new(Collect::default());
    let stop = Stop::new();
    let task = tokio::spawn(run(a, sink.clone(), Arc::new(Progress::default()), stop.clone()));
    tokio::time::sleep(Duration::from_millis(400)).await;
    let t = Instant::now();
    stop.stop();
    let s = task.await.unwrap().unwrap();
    assert!(t.elapsed() < Duration::from_millis(500), "{:?}", t.elapsed());
    assert_eq!(s.finish, Finish::Stopped);
    assert!(
        sink.rows.lock().unwrap().is_empty(),
        "in-flight requests are dropped"
    );
    let n = srv.seen.lock().unwrap().len();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        srv.seen.lock().unwrap().len(),
        n,
        "nothing is sent after the stop"
    );
    assert!(n <= 3);
}

#[tokio::test]
async fn the_gates_kill_switch_stops_the_attack() {
    let srv = server(Duration::ZERO).await;
    let g = gate();
    g.set_stopped(true);
    let a = attack(
        g,
        srv.addr,
        AttackType::Sniper,
        "GET /§a§ HTTP/1.1\r\n\r\n",
        &[list(&["1", "2"])],
        Options::default(),
    );
    let (s, _) = go(a).await;
    assert_eq!(s.finish, Finish::Stopped);
    assert!(paths(&srv).is_empty());
}

#[tokio::test]
async fn bad_options_are_refused() {
    let srv = server(Duration::ZERO).await;
    let a = attack(
        gate(),
        srv.addr,
        AttackType::Sniper,
        "GET /§a§ HTTP/1.1\r\n\r\n",
        &[list(&["1"])],
        Options {
            concurrency: 0,
            ..Options::default()
        },
    );
    let r = run(
        a,
        Arc::new(Collect::default()),
        Arc::new(Progress::default()),
        Stop::new(),
    )
    .await;
    assert!(r.is_err());
}
