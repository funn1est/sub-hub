#![cfg(not(target_family = "wasm"))]

use std::{
    env,
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MIHOMO_BINARY_ENV: &str = "SUB_HUB_MIHOMO_BIN";
const REQUIRE_MIHOMO_ENV: &str = "SUB_HUB_REQUIRE_MIHOMO";
const EXPECTED_MIHOMO_VERSION: &str = "v1.19.27";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const BUILTIN_MIHOMO_GOLDEN: &[u8] = include_bytes!("golden/builtin_mihomo_v1.yaml");

static NEXT_SANDBOX_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn official_mihomo_v1_19_27_accepts_builtin_golden() {
    let Some(binary) = configured_mihomo_binary() else {
        return;
    };
    let sandbox = TestSandbox::create()
        .unwrap_or_else(|_| panic!("failed to create the isolated Mihomo test sandbox"));

    verify_mihomo_version(&binary, &sandbox);
    fs::write(&sandbox.config_file, BUILTIN_MIHOMO_GOLDEN)
        .unwrap_or_else(|_| panic!("failed to prepare the Mihomo acceptance fixture"));
    verify_mihomo_config(&binary, &sandbox);
}

fn configured_mihomo_binary() -> Option<PathBuf> {
    let required = mihomo_is_required();
    let configured = env::var_os(MIHOMO_BINARY_ENV).filter(|value| !value.as_os_str().is_empty());

    let Some(configured) = configured else {
        assert!(
            !required,
            "SUB_HUB_MIHOMO_BIN must be set when SUB_HUB_REQUIRE_MIHOMO=1"
        );
        eprintln!("official Mihomo acceptance skipped: SUB_HUB_MIHOMO_BIN is not set");
        return None;
    };

    match fs::canonicalize(PathBuf::from(configured)) {
        Ok(path) if path.is_file() => Some(path),
        Ok(_) | Err(_) => panic!("SUB_HUB_MIHOMO_BIN must identify an executable file"),
    }
}

fn mihomo_is_required() -> bool {
    match env::var(REQUIRE_MIHOMO_ENV) {
        Ok(value) if value == "1" => true,
        Ok(value) if value == "0" => false,
        Err(env::VarError::NotPresent) => false,
        Ok(_) | Err(env::VarError::NotUnicode(_)) => {
            panic!("SUB_HUB_REQUIRE_MIHOMO must be unset, 0, or 1")
        }
    }
}

fn verify_mihomo_version(binary: &Path, sandbox: &TestSandbox) {
    let mut command = isolated_command(binary, sandbox);
    command
        .arg("-v")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command
        .spawn()
        .unwrap_or_else(|_| panic!("failed to execute the configured Mihomo binary"));
    let Some(output) = wait_for_output(child)
        .unwrap_or_else(|_| panic!("Mihomo version check failed; process output withheld"))
    else {
        panic!("Mihomo version check timed out; process output withheld")
    };

    let version_matches =
        reports_expected_version(&output.stdout) || reports_expected_version(&output.stderr);
    assert!(
        output.status.success() && version_matches,
        "configured Mihomo binary is not v1.19.27; process output withheld"
    );
}

fn reports_expected_version(output: &[u8]) -> bool {
    let Ok(output) = std::str::from_utf8(output) else {
        return false;
    };

    output.lines().any(|line| {
        let mut fields = line.split_ascii_whitespace();
        fields.next() == Some("Mihomo")
            && fields.next() == Some("Meta")
            && fields.next() == Some(EXPECTED_MIHOMO_VERSION)
    })
}

fn verify_mihomo_config(binary: &Path, sandbox: &TestSandbox) {
    let mut command = isolated_command(binary, sandbox);
    command
        .arg("-d")
        .arg(&sandbox.mihomo_home)
        .arg("-t")
        .arg("-f")
        .arg(&sandbox.config_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = command
        .spawn()
        .unwrap_or_else(|_| panic!("failed to execute the configured Mihomo binary"));

    match wait_for_status(child)
        .unwrap_or_else(|_| panic!("Mihomo configuration check failed; output withheld"))
    {
        Some(status) if status.success() => {}
        Some(_) => panic!("Mihomo rejected the generated configuration; output withheld"),
        None => panic!("Mihomo configuration check timed out; output withheld"),
    }
}

fn isolated_command(binary: &Path, sandbox: &TestSandbox) -> Command {
    let mut command = Command::new(binary);
    for (name, _) in env::vars_os() {
        if is_clash_environment_variable(&name) {
            command.env_remove(name);
        }
    }
    command
        .current_dir(&sandbox.root)
        .env("HOME", &sandbox.os_home)
        .env("USERPROFILE", &sandbox.os_home)
        .env("APPDATA", &sandbox.app_data)
        .env("LOCALAPPDATA", &sandbox.local_app_data)
        .env("XDG_CONFIG_HOME", &sandbox.xdg_config)
        .env("XDG_CACHE_HOME", &sandbox.xdg_cache)
        .env("XDG_DATA_HOME", &sandbox.xdg_data)
        .env("TEMP", &sandbox.process_temp)
        .env("TMP", &sandbox.process_temp)
        .stdin(Stdio::null());
    command
}

fn is_clash_environment_variable(name: &OsStr) -> bool {
    name.to_string_lossy()
        .to_ascii_uppercase()
        .starts_with("CLASH_")
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
    mihomo_home: PathBuf,
    os_home: PathBuf,
    app_data: PathBuf,
    local_app_data: PathBuf,
    xdg_config: PathBuf,
    xdg_cache: PathBuf,
    xdg_data: PathBuf,
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
            "sub-hub-mihomo-validation-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root)?;

        let sandbox = Self {
            mihomo_home: root.join("mihomo-home"),
            os_home: root.join("os-home"),
            app_data: root.join("app-data"),
            local_app_data: root.join("local-app-data"),
            xdg_config: root.join("xdg-config"),
            xdg_cache: root.join("xdg-cache"),
            xdg_data: root.join("xdg-data"),
            process_temp: root.join("process-temp"),
            config_file: root.join("config.yaml"),
            root,
        };
        for directory in [
            &sandbox.mihomo_home,
            &sandbox.os_home,
            &sandbox.app_data,
            &sandbox.local_app_data,
            &sandbox.xdg_config,
            &sandbox.xdg_cache,
            &sandbox.xdg_data,
            &sandbox.process_temp,
        ] {
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
