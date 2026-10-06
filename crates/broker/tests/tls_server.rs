//! TLS termination: the broker serves its certificate, and picks up a renewed
//! one from disk without a restart (cert-manager rotates in place).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use recognito_broker::server::{serve_tls, tls_config_with_reload};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn der(name: &str) -> CertificateDer<'static> {
    CertificateDer::from_pem_file(fixture(name)).unwrap()
}

/// Connect, return the certificate the server presented and the HTTP reply.
async fn fetch(addr: std::net::SocketAddr) -> (CertificateDer<'static>, String) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der("tls-a.crt")).unwrap();
    roots.add(der("tls-b.crt")).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let presented = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
    tls.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut reply = String::new();
    tls.read_to_string(&mut reply).await.unwrap();
    (presented.into_owned(), reply)
}

#[tokio::test]
async fn serves_over_tls_and_reloads_a_renewed_certificate() {
    let dir = std::env::temp_dir().join(format!("recognito-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("tls.crt"), dir.join("tls.key"));
    std::fs::copy(fixture("tls-a.crt"), &cert).unwrap();
    std::fs::copy(fixture("tls-a.key"), &key).unwrap();

    let tls = tls_config_with_reload(cert.clone(), key.clone(), Duration::from_millis(50)).unwrap();
    let app = Router::new().route("/healthz", get(|| async { "ok" }));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_tls(
        addr,
        app,
        tls,
        async {
            let _ = stop_rx.await;
        },
        Duration::from_secs(1),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (presented, reply) = fetch(addr).await;
    assert_eq!(presented, der("tls-a.crt"));
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert!(reply.ends_with("ok"));

    // Renewal: new files land in place (mtime must move).
    tokio::time::sleep(Duration::from_millis(1100)).await;
    std::fs::copy(fixture("tls-b.crt"), &cert).unwrap();
    std::fs::copy(fixture("tls-b.key"), &key).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let _ = fetch(addr).await; // first handshake after the interval triggers the check
    let (presented, _) = fetch(addr).await;
    assert_eq!(
        presented,
        der("tls-b.crt"),
        "renewed certificate not picked up"
    );

    // A broken replacement keeps the last good certificate.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    std::fs::write(&cert, "not a certificate").unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = fetch(addr).await;
    let (presented, _) = fetch(addr).await;
    assert_eq!(presented, der("tls-b.crt"));

    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_mismatched_certificate_and_key_refuse_to_load() {
    assert!(
        tls_config_with_reload(
            fixture("tls-a.crt"),
            fixture("tls-b.key"),
            Duration::from_secs(30)
        )
        .is_err()
    );
}
