#![cfg(not(target_family = "wasm"))]

use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use sub_hub_conversion::prepare_direct_subscription_v1;

const SING_BOX_BINARY_ENV: &str = "SUB_HUB_SING_BOX_BIN";
const REQUIRE_SING_BOX_ENV: &str = "SUB_HUB_REQUIRE_SING_BOX";
const SING_BOX_VERSION: &str = "1.13.14";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const VALID_DIRECT: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
const VALID_TROJAN: &str = "trojan://password@example.com:443#Alpha";

static NEXT_SANDBOX_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn configured_official_sing_box_accepts_builtin_document() {
    let Some(binary) = configured_sing_box_binary() else {
        return;
    };
    let sandbox = TestSandbox::create()
        .unwrap_or_else(|_| panic!("failed to create the isolated sing-box test sandbox"));

    verify_sing_box_version(&binary, &sandbox);
    let rendered = prepare_direct_subscription_v1(&[VALID_DIRECT])
        .expect("fixed subscription must be valid")
        .render_builtin_singbox_v1()
        .expect("builtin sing-box render must succeed")
        .into_bytes();
    fs::write(&sandbox.config_file, rendered)
        .unwrap_or_else(|_| panic!("failed to prepare the sing-box acceptance fixture"));
    verify_sing_box_config(&binary, &sandbox, "builtin document");
}

#[test]
fn configured_official_sing_box_accepts_builtin_trojan() {
    let Some(binary) = configured_sing_box_binary() else {
        return;
    };
    let sandbox = TestSandbox::create()
        .unwrap_or_else(|_| panic!("failed to create the isolated sing-box test sandbox"));

    verify_sing_box_version(&binary, &sandbox);
    let rendered = prepare_direct_subscription_v1(&[VALID_TROJAN])
        .expect("fixed Trojan subscription must be valid")
        .render_builtin_singbox_v1()
        .expect("builtin Trojan sing-box render must succeed")
        .into_bytes();
    fs::write(&sandbox.config_file, rendered)
        .unwrap_or_else(|_| panic!("failed to prepare the Trojan sing-box acceptance fixture"));
    verify_sing_box_config(&binary, &sandbox, "builtin Trojan");
}

fn configured_sing_box_binary() -> Option<PathBuf> {
    let required = sing_box_is_required();
    let configured = env::var_os(SING_BOX_BINARY_ENV).filter(|value| !value.as_os_str().is_empty());

    let Some(configured) = configured else {
        assert!(
            !required,
            "SUB_HUB_SING_BOX_BIN must be set when SUB_HUB_REQUIRE_SING_BOX=1"
        );
        eprintln!("official sing-box acceptance skipped: SUB_HUB_SING_BOX_BIN is not set");
        return None;
    };

    match fs::canonicalize(PathBuf::from(configured)) {
        Ok(path) if path.is_file() => Some(path),
        Ok(_) | Err(_) => panic!("SUB_HUB_SING_BOX_BIN must identify an executable file"),
    }
}

fn sing_box_is_required() -> bool {
    match env::var(REQUIRE_SING_BOX_ENV) {
        Ok(value) if value == "1" => true,
        Ok(value) if value == "0" => false,
        Err(env::VarError::NotPresent) => false,
        Ok(_) | Err(env::VarError::NotUnicode(_)) => {
            panic!("SUB_HUB_REQUIRE_SING_BOX must be unset, 0, or 1")
        }
    }
}

fn verify_sing_box_version(binary: &Path, sandbox: &TestSandbox) {
    let mut command = isolated_command(binary, sandbox);
    command
        .arg("version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command
        .spawn()
        .unwrap_or_else(|_| panic!("failed to execute the configured sing-box binary"));
    let Some(output) = wait_for_output(child)
        .unwrap_or_else(|_| panic!("sing-box version check failed; process output withheld"))
    else {
        panic!("sing-box version check timed out; process output withheld")
    };

    let version_matches =
        reports_expected_version(&output.stdout) || reports_expected_version(&output.stderr);
    assert!(
        output.status.success() && version_matches,
        "configured sing-box binary does not match the approved version; process output withheld"
    );
}

fn reports_expected_version(output: &[u8]) -> bool {
    let Ok(output) = std::str::from_utf8(output) else {
        return false;
    };

    output.lines().any(|line| {
        let mut fields = line.split_ascii_whitespace();
        fields.next() == Some("sing-box")
            && fields.next() == Some("version")
            && fields.next() == Some(SING_BOX_VERSION)
    })
}

fn verify_sing_box_config(binary: &Path, sandbox: &TestSandbox, fixture: &str) {
    let mut command = isolated_command(binary, sandbox);
    command
        .arg("check")
        .arg("-c")
        .arg(&sandbox.config_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = command
        .spawn()
        .unwrap_or_else(|_| panic!("failed to execute the configured sing-box binary"));

    match wait_for_status(child)
        .unwrap_or_else(|_| panic!("sing-box configuration check failed; output withheld"))
    {
        Some(status) if status.success() => {}
        Some(_) => panic!("sing-box rejected {fixture}; process output withheld"),
        None => panic!("sing-box configuration check timed out for {fixture}; output withheld"),
    }
}

fn isolated_command(binary: &Path, sandbox: &TestSandbox) -> Command {
    let mut command = Command::new(binary);
    command
        .current_dir(&sandbox.root)
        .env("HOME", &sandbox.os_home)
        .env("USERPROFILE", &sandbox.os_home)
        .env("TEMP", &sandbox.process_temp)
        .env("TMP", &sandbox.process_temp)
        .stdin(Stdio::null());
    command
}

fn wait_for_output(mut child: Child) -> io::Result<Option<Output>> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().map(Some),
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        if started.elapsed() >= PROCESS_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait_with_output();
            return Ok(None);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn wait_for_status(mut child: Child) -> io::Result<Option<ExitStatus>> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        if started.elapsed() >= PROCESS_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

struct TestSandbox {
    root: PathBuf,
    os_home: PathBuf,
    process_temp: PathBuf,
    config_file: PathBuf,
}

impl TestSandbox {
    fn create() -> io::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let sequence = NEXT_SANDBOX_ID.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!(
            "sub-hub-singbox-validation-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root)?;

        let sandbox = Self {
            os_home: root.join("os-home"),
            process_temp: root.join("process-temp"),
            config_file: root.join("config.json"),
            root,
        };
        for directory in [&sandbox.os_home, &sandbox.process_temp] {
            if let Err(error) = fs::create_dir(directory) {
                let _ = fs::remove_dir_all(&sandbox.root);
                return Err(error);
            }
        }

        Ok(sandbox)
    }
}

impl Drop for TestSandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
