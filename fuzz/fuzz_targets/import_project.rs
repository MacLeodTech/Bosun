//! A project file from outside (the import path): whatever the bytes, importing must not panic, and anything it
//! accepts must open as a project afterwards.
#![no_main]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;

static N: AtomicU64 = AtomicU64::new(0);

fn scratch() -> PathBuf {
    // Memory-backed where there is one, so the fuzzer does not wear a disk.
    let base = if std::path::Path::new("/dev/shm").is_dir() { PathBuf::from("/dev/shm") } else { std::env::temp_dir() };
    let d = base.join(format!("bosun-fuzz-import-{}", std::process::id()));
    std::fs::create_dir_all(&d).ok();
    d
}

/// A real, valid project file, made once: raw random bytes almost never get past the first check, so the input
/// is applied to this as patches (offset, byte) instead, which reaches the schema checks and the page parser.
fn base() -> &'static [u8] {
    static BASE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BASE.get_or_init(|| {
        let dir = scratch();
        let p = dir.join("base.bosun");
        let _ = std::fs::remove_file(&p);
        let project = bosun_store::Project::open_in_memory().expect("in-memory project");
        project.set_setting("scope", &"x").expect("setting");
        project.backup_to(&p).expect("backup");
        std::fs::read(&p).expect("read the base")
    })
}

fuzz_target!(|data: &[u8]| {
    let mut bytes;
    let data = if data.first() == Some(&0) {
        // Patch mode: the rest is (offset: u16, value: u8) triples over a valid file.
        bytes = base().to_vec();
        for t in data[1..].chunks_exact(3) {
            let at = usize::from(u16::from_le_bytes([t[0], t[1]])) % bytes.len();
            bytes[at] = t[2];
        }
        &bytes[..]
    } else {
        data
    };
    let dir = scratch();
    let n = N.fetch_add(1, Ordering::Relaxed);
    let (src, dst) = (dir.join(format!("{n}.in")), dir.join(format!("{n}.out.bosun")));
    if std::fs::write(&src, data).is_err() {
        return;
    }
    if bosun_store::import_foreign(&src, &dst).is_ok() {
        let p = bosun_store::Project::open(&dst).expect("an accepted import opens as a project");
        drop(p);
    }
    for suffix in ["", "-wal", "-shm", "-journal", ".lock"] {
        let mut a = src.as_os_str().to_owned();
        a.push(suffix);
        let _ = std::fs::remove_file(a);
        let mut b = dst.as_os_str().to_owned();
        b.push(suffix);
        let _ = std::fs::remove_file(b);
    }
});
