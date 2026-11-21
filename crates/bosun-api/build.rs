//! Point the embedded-assets macro at the built web UI (`web/dist`), or at a placeholder page when the UI has
//! not been built, so `cargo build` works without Node.

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let dist = manifest.join("../../web/dist");
    println!("cargo:rerun-if-changed={}", dist.display());
    println!("cargo:rerun-if-env-changed=BOSUN_WEB_DIST");
    let dir = if let Ok(d) = std::env::var("BOSUN_WEB_DIST") {
        PathBuf::from(d)
    } else if dist.join("index.html").exists() {
        dist.canonicalize().expect("canonical web/dist")
    } else {
        let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("web-placeholder");
        std::fs::create_dir_all(&out).expect("placeholder dir");
        std::fs::write(
            out.join("index.html"),
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Bosun</title></head>\
             <body><h1>Bosun</h1><p>The web UI was not built into this binary. Run <code>npm ci &amp;&amp; \
             npm run build</code> in <code>web/</code> and rebuild. The API is available under \
             <code>/api/v1</code>.</p></body></html>",
        )
        .expect("placeholder index");
        out
    };
    println!("cargo:rustc-env=BOSUN_WEB_DIST={}", dir.display());
}
