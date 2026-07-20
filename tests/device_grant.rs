//! Device grant e2e via the real binary and a local mock AS.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use serde_json::Value;
use tempfile::TempDir;

#[derive(Clone, Debug)]
enum TokenBehavior {
    PendingThenSuccess { pending_before_success: usize },
    AlwaysAccessDenied,
    AlwaysInvalidGrant,
    AlwaysExpiredToken,
}

struct MockState {
    polls: AtomicUsize,
    behavior: Mutex<TokenBehavior>,
}

impl MockState {
    fn new() -> Self {
        Self {
            polls: AtomicUsize::new(0),
            behavior: Mutex::new(TokenBehavior::PendingThenSuccess {
                pending_before_success: 1,
            }),
        }
    }

    fn set_behavior(&self, b: TokenBehavior) {
        *self.behavior.lock().unwrap() = b;
    }
}

fn start_mock() -> (SocketAddr, Arc<MockState>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(MockState::new());
    let state_t = Arc::clone(&state);
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
                let n = state_t.polls.fetch_add(1, Ordering::SeqCst);
                match state_t.behavior.lock().unwrap().clone() {
                    TokenBehavior::PendingThenSuccess {
                        pending_before_success,
                    } => {
                        if n < pending_before_success {
                            (400, r#"{"error":"authorization_pending"}"#.into())
                        } else {
                            (
                                200,
                                r#"{"access_token":"at-test","token_type":"Bearer","expires_in":3600}"#
                                    .into(),
                            )
                        }
                    }
                    TokenBehavior::AlwaysAccessDenied => (
                        400,
                        r#"{"error":"access_denied","error_description":"user denied the request"}"#
                            .into(),
                    ),
                    TokenBehavior::AlwaysInvalidGrant => (
                        400,
                        r#"{"error":"invalid_grant","error_description":"device code unknown"}"#
                            .into(),
                    ),
                    TokenBehavior::AlwaysExpiredToken => (
                        400,
                        r#"{"error":"expired_token","error_description":"the device code has expired"}"#
                            .into(),
                    ),
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
    (addr, state, handle)
}

fn shell_quote(path: &Path) -> String {
    let s = path.display().to_string();
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn write_config(
    dir: &TempDir,
    addr: SocketAddr,
    token: &Path,
    success_hook: Option<&Path>,
    error_hook: Option<&Path>,
) -> PathBuf {
    let config = dir.path().join("config.toml");
    let mut hooks = String::new();
    if let Some(p) = success_hook {
        let sh = format!(
            "printf '%s\\n' \"$ACCESS_TOKEN\" >> {}",
            shell_quote(p)
        );
        hooks.push_str(&format!(
            "hooks.on-issue.success.command = [\"sh\", \"-c\", {:?}]\n",
            sh
        ));
    }
    if let Some(p) = error_hook {
        let sh = format!(
            "printf '%s\\n' \"$ERROR\" \"$ERROR_DESCRIPTION\" >> {}",
            shell_quote(p)
        );
        hooks.push_str(&format!(
            "hooks.on-issue.error.command = [\"sh\", \"-c\", {:?}]\n",
            sh
        ));
    }
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
{hooks}"#,
            t = token.display(),
            hooks = hooks,
        ),
    )
    .unwrap();
    config
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ortie"))
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(bin()).args(args).output().unwrap()
}

#[test]
fn auth_get_json_then_resume_stores_token() {
    let (addr, state, _h) = start_mock();
    let dir = TempDir::new().unwrap();
    let token = dir.path().join("token.json");
    std::fs::write(&token, b"").unwrap();
    let config = write_config(&dir, addr, &token, None, None);

    let get = run(&["-c", config.to_str().unwrap(), "--json", "auth", "get"]);
    assert!(get.status.success(), "{get:?}");
    let v: Value = serde_json::from_slice(&get.stdout).unwrap();
    assert_eq!(v["device_code"], "dc-test");
    assert_eq!(state.polls.load(Ordering::SeqCst), 0);

    let resume = run(&["-c", config.to_str().unwrap(), "auth", "resume", "dc-test"]);
    assert!(resume.status.success(), "{resume:?}");
    assert!(state.polls.load(Ordering::SeqCst) >= 2);
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&token).unwrap()).unwrap();
    assert_eq!(stored["access_token"], "at-test");
}

#[test]
fn auth_resume_success_fires_on_issue_success_hook() {
    let (addr, state, _h) = start_mock();
    state.set_behavior(TokenBehavior::PendingThenSuccess {
        pending_before_success: 0,
    });
    let dir = TempDir::new().unwrap();
    let token = dir.path().join("token.json");
    let success = dir.path().join("success-hook.txt");
    let error = dir.path().join("error-hook.txt");
    let config = write_config(&dir, addr, &token, Some(&success), Some(&error));

    let out = run(&["-c", config.to_str().unwrap(), "auth", "resume", "dc-test"]);
    assert!(out.status.success(), "{out:?}");
    let body = std::fs::read_to_string(&success).expect("success hook");
    assert!(body.contains("at-test"), "{body:?}");
    assert!(!error.exists() || std::fs::read_to_string(&error).unwrap().is_empty());
}

#[test]
fn auth_resume_access_denied_fires_on_issue_error_hook() {
    let (addr, state, _h) = start_mock();
    state.set_behavior(TokenBehavior::AlwaysAccessDenied);
    let dir = TempDir::new().unwrap();
    let token = dir.path().join("token.json");
    let success = dir.path().join("success-hook.txt");
    let error = dir.path().join("error-hook.txt");
    let config = write_config(&dir, addr, &token, Some(&success), Some(&error));

    let out = run(&["-c", config.to_str().unwrap(), "auth", "resume", "dc-test"]);
    assert!(!out.status.success(), "expected access_denied failure");
    let body = std::fs::read_to_string(&error).expect("error hook");
    assert!(
        body.contains("AccessDenied") || body.contains("access_denied"),
        "{body:?}"
    );
    assert!(body.contains("denied") || body.contains("user denied"), "{body:?}");
    assert!(!success.exists() || std::fs::read_to_string(&success).unwrap().is_empty());
}

#[test]
fn auth_resume_invalid_grant_fires_on_issue_error_hook() {
    let (addr, state, _h) = start_mock();
    state.set_behavior(TokenBehavior::AlwaysInvalidGrant);
    let dir = TempDir::new().unwrap();
    let token = dir.path().join("token.json");
    let success = dir.path().join("success-hook.txt");
    let error = dir.path().join("error-hook.txt");
    let config = write_config(&dir, addr, &token, Some(&success), Some(&error));

    let out = run(&["-c", config.to_str().unwrap(), "auth", "resume", "dc-test"]);
    assert!(!out.status.success());
    let body = std::fs::read_to_string(&error).expect("error hook");
    assert!(
        body.contains("InvalidGrant") || body.contains("invalid_grant"),
        "{body:?}"
    );
}

#[test]
fn auth_resume_server_expired_token_fires_on_issue_error_hook() {
    let (addr, state, _h) = start_mock();
    state.set_behavior(TokenBehavior::AlwaysExpiredToken);
    let dir = TempDir::new().unwrap();
    let token = dir.path().join("token.json");
    let success = dir.path().join("success-hook.txt");
    let error = dir.path().join("error-hook.txt");
    let config = write_config(&dir, addr, &token, Some(&success), Some(&error));

    let out = run(&["-c", config.to_str().unwrap(), "auth", "resume", "dc-test"]);
    assert!(!out.status.success());
    let body = std::fs::read_to_string(&error).expect("error hook");
    assert!(
        body.contains("ExpiredToken") || body.contains("expired_token"),
        "{body:?}"
    );
}

#[test]
fn auth_resume_network_error_does_not_fire_on_issue_error_hook() {
    let dir = TempDir::new().unwrap();
    let token = dir.path().join("token.json");
    let success = dir.path().join("success-hook.txt");
    let error = dir.path().join("error-hook.txt");
    let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let config = write_config(&dir, dead, &token, Some(&success), Some(&error));

    let out = run(&["-c", config.to_str().unwrap(), "auth", "resume", "dc-test"]);
    assert!(!out.status.success());
    assert!(!error.exists() || std::fs::read_to_string(&error).unwrap().is_empty());
    assert!(!success.exists() || std::fs::read_to_string(&success).unwrap().is_empty());
}
