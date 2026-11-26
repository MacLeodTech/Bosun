//! `bosun-testbed [ADDR]`: run the planted-vulnerability server (default `127.0.0.1:8099`).

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let bind = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8099".into());
    let t = bosun_testbed::start(&bind, None).await?;
    eprintln!("testbed on http://{}", t.addr);
    std::future::pending::<()>().await;
    Ok(())
}
