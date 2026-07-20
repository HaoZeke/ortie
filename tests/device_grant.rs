//! Device grant e2e via the real binary and a local mock AS.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use serde_json::Value;
use tempfile::TempDir;

fn start_mock() -> (SocketAddr, Arc<AtomicUsize>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let polls = Arc::new(AtomicUsize::new(0));
    let polls_t = Arc::clone(&polls);
    let handle = thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 8192];
            let Ok(n) = stream.read(&mut buf) else {
                continue;
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/");
            let (status, body): (u16, String) = if path.starts_with("/devicecode") {
                (
                    200,
                    format!(
                        r#"{{"device_code":"dc-test","user_code":"USER","verification_uri":"http://{addr}/d","expires_in":60,"interval":1}}"#
                    ),
                )
            } else if path.starts_with("/token") {
                if polls_t.fetch_add(1, Ordering::SeqCst) == 0 {
                    (400, r#"{"error":"authorization_pending"}"#.into())
                } else {
                    (
                        200,
                        r#"{"access_token":"at-test","token_type":"Bearer","expires_in":3600}"#
                            .into(),
                    )
                }
            } else {
                (404, r#"{"error":"not_found"}"#.into())
            };
            let resp = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    thread::sleep(Duration::from_millis(20));
    (addr, polls, handle)
}

#[test]
fn auth_get_json_then_resume_stores_token() {
    let (addr, polls, _h) = start_mock();
    let dir = TempDir::new().unwrap();
    let token = dir.path().join("token.json");
    std::fs::write(&token, b"").unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[accounts.device]
default = true
client-id = "c"
grant = "device"
endpoints.device-authorization = "http://{addr}/devicecode"
endpoints.token = "http://{addr}/token"
storage.read.command = ["cat", "{t}"]
storage.write.command = ["tee", "{t}"]
"#,
            t = token.display()
        ),
    )
    .unwrap();
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_ortie"));

    let get = Command::new(&bin)
        .args(["-c", config.to_str().unwrap(), "--json", "auth", "get"])
        .output()
        .unwrap();
    assert!(get.status.success(), "{get:?}");
    let v: Value = serde_json::from_slice(&get.stdout).unwrap();
    assert_eq!(v["device_code"], "dc-test");
    assert_eq!(v["user_code"], "USER");
    // Entra-shaped mock omits verification_uri_complete; JSON must not invent one.
    assert!(
        v["verification_uri_complete"].is_null(),
        "complete URI must be null when omitted: {v}"
    );
    assert!(
        v["verification_uri"]
            .as_str()
            .unwrap_or("")
            .contains(&addr.to_string()),
        "verification_uri missing: {v}"
    );
    assert_eq!(polls.load(Ordering::SeqCst), 0);

    let resume = Command::new(&bin)
        .args(["-c", config.to_str().unwrap(), "auth", "resume", "dc-test"])
        .output()
        .unwrap();
    assert!(resume.status.success(), "{resume:?}");
    assert!(polls.load(Ordering::SeqCst) >= 2);
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&token).unwrap()).unwrap();
    assert_eq!(stored["access_token"], "at-test");
}

/// Device and token endpoints may use different hosts/ports. Connect must
/// open each URL separately (device request vs token poll).
#[test]
fn separate_device_and_token_hosts() {
    let (device_addr, device_polls, _dh) = start_mock();
    let (token_addr, token_polls, _th) = start_mock();
    assert_ne!(device_addr, token_addr);

    let dir = TempDir::new().unwrap();
    let token = dir.path().join("token.json");
    std::fs::write(&token, b"").unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[accounts.device]
default = true
client-id = "c"
grant = "device"
endpoints.device-authorization = "http://{device_addr}/devicecode"
endpoints.token = "http://{token_addr}/token"
storage.read.command = ["cat", "{t}"]
storage.write.command = ["tee", "{t}"]
"#,
            t = token.display()
        ),
    )
    .unwrap();
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_ortie"));

    let get = Command::new(&bin)
        .args(["-c", config.to_str().unwrap(), "--json", "auth", "get"])
        .output()
        .unwrap();
    assert!(get.status.success(), "{get:?}");
    assert_eq!(
        token_polls.load(Ordering::SeqCst),
        0,
        "token host must not be contacted on auth get --json"
    );
    assert_eq!(
        device_polls.load(Ordering::SeqCst),
        0,
        "device host /devicecode is not a token poll"
    );

    let resume = Command::new(&bin)
        .args(["-c", config.to_str().unwrap(), "auth", "resume", "dc-test"])
        .output()
        .unwrap();
    assert!(resume.status.success(), "{resume:?}");
    assert!(
        token_polls.load(Ordering::SeqCst) >= 1,
        "token polls must hit the token host"
    );
    assert_eq!(
        device_polls.load(Ordering::SeqCst),
        0,
        "device host must not receive token polls"
    );
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&token).unwrap()).unwrap();
    assert_eq!(stored["access_token"], "at-test");
}

#[test]
fn auth_resume_authorization_code_input_still_exchanges_code() {
    // After device-grant String input, authorization-code accounts still
    // treat the positional as the redirected URI (trimmed).
    let (addr, polls, _h) = start_mock();
    let dir = TempDir::new().unwrap();
    let token = dir.path().join("token.json");
    std::fs::write(&token, b"").unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[accounts.ac]
default = true
client-id = "c"
grant = "authorization-code"
pkce = false
endpoints.authorization = "http://{addr}/authorize"
endpoints.token = "http://{addr}/token"
endpoints.redirection = "http://127.0.0.1/cb"
storage.read.command = ["cat", "{t}"]
storage.write.command = ["tee", "{t}"]
"#,
            t = token.display()
        ),
    )
    .unwrap();
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_ortie"));

    // Force first token poll to succeed: authorization-code is one POST.
    polls.store(1, Ordering::SeqCst);

    let redirected = "  http://127.0.0.1/cb?code=auth-code-xyz&state=mystate  ";
    let resume = Command::new(&bin)
        .args([
            "-c",
            config.to_str().unwrap(),
            "auth",
            "resume",
            "--state",
            "mystate",
            redirected,
        ])
        .output()
        .unwrap();
    assert!(
        resume.status.success(),
        "auth resume (authorization-code) failed: {:?}",
        resume
    );
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&token).unwrap()).unwrap();
    assert_eq!(stored["access_token"], "at-test");
}

#[test]
fn auth_resume_authorization_code_state_mismatch_fails() {
    let (addr, polls, _h) = start_mock();
    let dir = TempDir::new().unwrap();
    let token = dir.path().join("token.json");
    std::fs::write(&token, b"").unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[accounts.ac]
default = true
client-id = "c"
grant = "authorization-code"
pkce = false
endpoints.authorization = "http://{addr}/authorize"
endpoints.token = "http://{addr}/token"
endpoints.redirection = "http://127.0.0.1/cb"
storage.read.command = ["cat", "{t}"]
storage.write.command = ["tee", "{t}"]
"#,
            t = token.display()
        ),
    )
    .unwrap();
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_ortie"));

    let resume = Command::new(&bin)
        .args([
            "-c",
            config.to_str().unwrap(),
            "auth",
            "resume",
            "--state",
            "from-client",
            "http://127.0.0.1/cb?code=x&state=from-server",
        ])
        .output()
        .unwrap();
    assert!(!resume.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&resume.stdout),
        String::from_utf8_lossy(&resume.stderr)
    );
    assert!(
        combined.contains("do not match") || combined.contains("state"),
        "{combined}"
    );
    assert!(
        !combined.contains("from-server") && !combined.contains("from-client"),
        "state values must not appear in error output: {combined}"
    );
    assert_eq!(polls.load(Ordering::SeqCst), 0);
}

#[test]
fn auth_get_json_authorization_code_emits_uri_state_and_extras() {
    let (addr, polls, _h) = start_mock();
    let dir = TempDir::new().unwrap();
    let token = dir.path().join("token.json");
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[accounts.ac]
default = true
client-id = "c"
grant = "authorization-code"
pkce = false
endpoints.authorization = "http://{addr}/authorize"
endpoints.token = "http://{addr}/token"
endpoints.redirection = "http://127.0.0.1/cb"
extras.access_type = "offline"
extras.prompt = "consent"
storage.read.command = ["cat", "{t}"]
storage.write.command = ["tee", "{t}"]
"#,
            t = token.display()
        ),
    )
    .unwrap();
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_ortie"));

    let get = Command::new(&bin)
        .args(["-c", config.to_str().unwrap(), "--json", "auth", "get"])
        .output()
        .unwrap();
    assert!(get.status.success(), "{get:?}");
    let v: Value = serde_json::from_slice(&get.stdout).unwrap();
    let auth_uri = v["authorization_uri"].as_str().unwrap();
    assert!(auth_uri.contains("/authorize"), "{auth_uri}");
    assert!(
        auth_uri.contains("access_type=offline") && auth_uri.contains("prompt=consent"),
        "extras missing from authorization URI: {auth_uri}"
    );
    assert!(
        v["state"].as_str().is_some_and(|s| !s.is_empty()),
        "state missing: {v}"
    );
    assert!(v["pkce_code_verifier"].is_null(), "{v}");
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert!(!token.exists());
}

#[test]
fn auth_resume_authorization_code_with_pkce_sends_verifier() {
    // Smoke: --pkce is accepted on authorization-code resume and the
    // token exchange runs (mock does not validate the verifier).
    let (addr, polls, _h) = start_mock();
    let dir = TempDir::new().unwrap();
    let token = dir.path().join("token.json");
    std::fs::write(&token, b"").unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[accounts.ac]
default = true
client-id = "c"
grant = "authorization-code"
pkce = true
endpoints.authorization = "http://{addr}/authorize"
endpoints.token = "http://{addr}/token"
endpoints.redirection = "http://127.0.0.1/cb"
storage.read.command = ["cat", "{t}"]
storage.write.command = ["tee", "{t}"]
"#,
            t = token.display()
        ),
    )
    .unwrap();
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_ortie"));
    polls.store(1, Ordering::SeqCst);

    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP01234";
    let resume = Command::new(&bin)
        .args([
            "-c",
            config.to_str().unwrap(),
            "auth",
            "resume",
            "--state",
            "s1",
            "--pkce",
            verifier,
            "http://127.0.0.1/cb?code=pkce-code&state=s1",
        ])
        .output()
        .unwrap();
    assert!(resume.status.success(), "{resume:?}");
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&token).unwrap()).unwrap();
    assert_eq!(stored["access_token"], "at-test");
}

#[test]
fn auth_resume_invalid_pkce_error_omits_verifier_secret() {
    let dir = TempDir::new().unwrap();
    let config = dir.path().join("c.toml");
    let token = dir.path().join("t.json");
    std::fs::write(
        &config,
        format!(
            r#"
[accounts.t]
client-id = "c"
grant = "authorization-code"
endpoints.authorization = "http://127.0.0.1/a"
endpoints.token = "http://127.0.0.1/t"
endpoints.redirection = "http://127.0.0.1/cb"
storage.read.command = ["cat", "{t}"]
storage.write.command = ["tee", "{t}"]
"#,
            t = token.display()
        ),
    )
    .unwrap();
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_ortie"));
    let secret = "pkce-verifier-with space-secret";
    let out = Command::new(&bin)
        .args([
            "-c",
            config.to_str().unwrap(),
            "auth",
            "resume",
            "--pkce",
            secret,
            "http://127.0.0.1/cb?code=x&state=y",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!combined.contains(secret), "{combined}");
}

#[test]
fn auth_resume_invalid_redirect_error_omits_authorization_code() {
    let dir = TempDir::new().unwrap();
    let config = dir.path().join("c.toml");
    let token = dir.path().join("t.json");
    std::fs::write(
        &config,
        format!(
            r#"
[accounts.t]
client-id = "c"
grant = "authorization-code"
endpoints.authorization = "http://127.0.0.1/a"
endpoints.token = "http://127.0.0.1/t"
endpoints.redirection = "http://127.0.0.1/cb"
storage.read.command = ["cat", "{t}"]
storage.write.command = ["tee", "{t}"]
"#,
            t = token.display()
        ),
    )
    .unwrap();
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_ortie"));
    let bad = "not a url?code=auth-code-must-not-leak&state=s";
    let out = Command::new(&bin)
        .args(["-c", config.to_str().unwrap(), "auth", "resume", bad])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!combined.contains("auth-code-must-not-leak"), "{combined}");
}
