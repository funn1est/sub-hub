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

use sub_hub_conversion::{
    OutputTarget, SubscriptionPreparationError, SubscriptionSourceV1, prepare_subscription_v1,
};

fn prepare_direct(
    uris: &[&str],
) -> Result<sub_hub_conversion::PreparedSubscriptionV1, SubscriptionPreparationError> {
    let sources: Vec<_> = uris
        .iter()
        .copied()
        .map(SubscriptionSourceV1::Direct)
        .collect();
    prepare_subscription_v1(&sources)
}

const MIHOMO_BINARY_ENV: &str = "SUB_HUB_MIHOMO_BIN";
const REQUIRE_MIHOMO_ENV: &str = "SUB_HUB_REQUIRE_MIHOMO";
const MIHOMO_VERSION_ENV: &str = "SUB_HUB_MIHOMO_VERSION";
const ACL4SSR_CORPUS_DIR_ENV: &str = "SUB_HUB_ACL4SSR_CORPUS_DIR";
const REQUIRE_ACL4SSR_CORPUS_ENV: &str = "SUB_HUB_REQUIRE_ACL4SSR_CORPUS";
const MIHOMO_V1_19_27: &str = "v1.19.27";
const MIHOMO_V1_19_29: &str = "v1.19.29";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const BUILTIN_MIHOMO_GOLDEN: &[u8] = include_bytes!("golden/builtin_mihomo_v1.yaml");
const ACL4SSR_REMOTE_PREFIX: &str = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/";
const VALID_DIRECT: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
const VALID_TROJAN: &str = "trojan://password@example.com:443#Alpha";
const VALID_VMESS: &str = "vmess://eyJ2IjoyLCJwcyI6IkFscGhhIiwiYWRkIjoiRVhBTVBMRS5DT00iLCJwb3J0Ijo0NDMsImlkIjoiMDEyMzQ1NjctODlhYi1jZGVmLTAxMjMtNDU2Nzg5YWJjZGVmIiwic2N5IjoiYWVzLTEyOC1nY20ifQ==";
const VALID_HYSTERIA2: &str = "hysteria2://password@example.com:443#Alpha";
const VALID_TUIC: &str =
    "tuic://01234567-89ab-cdef-0123-456789abcdef:password@example.com:443#Alpha";

static NEXT_SANDBOX_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn configured_official_mihomo_accepts_builtin_golden() {
    let expected_version = configured_mihomo_version();
    let Some(binary) = configured_mihomo_binary() else {
        return;
    };
    let sandbox = TestSandbox::create()
        .unwrap_or_else(|_| panic!("failed to create the isolated Mihomo test sandbox"));

    verify_mihomo_version(&binary, &sandbox, expected_version);
    fs::write(&sandbox.config_file, BUILTIN_MIHOMO_GOLDEN)
        .unwrap_or_else(|_| panic!("failed to prepare the Mihomo acceptance fixture"));
    verify_mihomo_config(&binary, &sandbox, "builtin golden");
}

#[test]
fn configured_official_mihomo_accepts_builtin_trojan() {
    let expected_version = configured_mihomo_version();
    let Some(binary) = configured_mihomo_binary() else {
        return;
    };
    let sandbox = TestSandbox::create()
        .unwrap_or_else(|_| panic!("failed to create the isolated Mihomo test sandbox"));

    verify_mihomo_version(&binary, &sandbox, expected_version);
    let rendered = prepare_direct(&[VALID_TROJAN])
        .expect("fixed Trojan subscription must be valid")
        .render_builtin_v1(OutputTarget::Mihomo)
        .expect("builtin Trojan Mihomo render must succeed");
    fs::write(&sandbox.config_file, rendered.as_bytes())
        .unwrap_or_else(|_| panic!("failed to prepare the Trojan Mihomo acceptance fixture"));
    verify_mihomo_config(&binary, &sandbox, "builtin Trojan");
}

#[test]
fn configured_official_mihomo_accepts_builtin_vmess() {
    let expected_version = configured_mihomo_version();
    let Some(binary) = configured_mihomo_binary() else {
        return;
    };
    let sandbox = TestSandbox::create()
        .unwrap_or_else(|_| panic!("failed to create the isolated Mihomo test sandbox"));

    verify_mihomo_version(&binary, &sandbox, expected_version);
    let rendered = prepare_direct(&[VALID_VMESS])
        .expect("fixed VMess subscription must be valid")
        .render_builtin_v1(OutputTarget::Mihomo)
        .expect("builtin VMess Mihomo render must succeed");
    fs::write(&sandbox.config_file, rendered.as_bytes())
        .unwrap_or_else(|_| panic!("failed to prepare the VMess Mihomo acceptance fixture"));
    verify_mihomo_config(&binary, &sandbox, "builtin VMess");
}

#[test]
fn configured_official_mihomo_accepts_builtin_hysteria2() {
    let expected_version = configured_mihomo_version();
    let Some(binary) = configured_mihomo_binary() else {
        return;
    };
    let sandbox = TestSandbox::create()
        .unwrap_or_else(|_| panic!("failed to create the isolated Mihomo test sandbox"));

    verify_mihomo_version(&binary, &sandbox, expected_version);
    let rendered = prepare_direct(&[VALID_HYSTERIA2])
        .expect("fixed Hysteria2 subscription must be valid")
        .render_builtin_v1(OutputTarget::Mihomo)
        .expect("builtin Hysteria2 Mihomo render must succeed");
    fs::write(&sandbox.config_file, rendered.as_bytes())
        .unwrap_or_else(|_| panic!("failed to prepare the Hysteria2 Mihomo acceptance fixture"));
    verify_mihomo_config(&binary, &sandbox, "builtin Hysteria2");
}

#[test]
fn configured_official_mihomo_accepts_builtin_tuic() {
    let expected_version = configured_mihomo_version();
    let Some(binary) = configured_mihomo_binary() else {
        return;
    };
    let sandbox = TestSandbox::create()
        .unwrap_or_else(|_| panic!("failed to create the isolated Mihomo test sandbox"));

    verify_mihomo_version(&binary, &sandbox, expected_version);
    let rendered = prepare_direct(&[VALID_TUIC])
        .expect("fixed TUIC subscription must be valid")
        .render_builtin_v1(OutputTarget::Mihomo)
        .expect("builtin TUIC Mihomo render must succeed");
    fs::write(&sandbox.config_file, rendered.as_bytes())
        .unwrap_or_else(|_| panic!("failed to prepare the TUIC Mihomo acceptance fixture"));
    verify_mihomo_config(&binary, &sandbox, "builtin TUIC");
}

#[test]
fn configured_mihomo_accepts_generated_online_and_full_acl4ssr_profiles() {
    let expected_version = configured_mihomo_version();
    let corpus_required = acl4ssr_corpus_is_required();
    let Some(corpus_root) = configured_acl4ssr_corpus_root(corpus_required) else {
        return;
    };
    let Some(binary) = configured_mihomo_binary() else {
        assert!(
            !corpus_required,
            "SUB_HUB_MIHOMO_BIN must be set when SUB_HUB_REQUIRE_ACL4SSR_CORPUS=1"
        );
        return;
    };
    let version_sandbox = TestSandbox::create()
        .unwrap_or_else(|_| panic!("failed to create the isolated Mihomo test sandbox"));
    verify_mihomo_version(&binary, &version_sandbox, expected_version);

    for profile in [
        "Clash/config/ACL4SSR_Online.ini",
        "Clash/config/ACL4SSR_Online_Full_MultiMode.ini",
    ] {
        let rendered = render_acl4ssr_profile(&corpus_root, profile);
        let sandbox = TestSandbox::create()
            .unwrap_or_else(|_| panic!("failed to create the isolated Mihomo test sandbox"));
        fs::write(&sandbox.config_file, rendered)
            .unwrap_or_else(|_| panic!("failed to prepare the generated ACL4SSR profile"));
        verify_mihomo_config(&binary, &sandbox, profile);
    }
}

#[test]
fn mihomo_version_selection_is_closed_to_the_validation_matrix() {
    assert_eq!(
        parse_mihomo_version(Err(env::VarError::NotPresent)),
        MIHOMO_V1_19_27
    );
    assert_eq!(
        parse_mihomo_version(Ok(MIHOMO_V1_19_27.to_owned())),
        MIHOMO_V1_19_27
    );
    assert_eq!(
        parse_mihomo_version(Ok(MIHOMO_V1_19_29.to_owned())),
        MIHOMO_V1_19_29
    );

    for rejected in [
        Ok(String::new()),
        Ok("1.19.27".to_owned()),
        Ok("v1.19.30".to_owned()),
        Err(env::VarError::NotUnicode("withheld".into())),
    ] {
        assert!(
            std::panic::catch_unwind(|| parse_mihomo_version(rejected)).is_err(),
            "unapproved Mihomo version selection must panic"
        );
    }
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

fn configured_mihomo_version() -> &'static str {
    parse_mihomo_version(env::var(MIHOMO_VERSION_ENV))
}

fn parse_mihomo_version(value: Result<String, env::VarError>) -> &'static str {
    match value {
        Err(env::VarError::NotPresent) => MIHOMO_V1_19_27,
        Ok(value) if value == MIHOMO_V1_19_27 => MIHOMO_V1_19_27,
        Ok(value) if value == MIHOMO_V1_19_29 => MIHOMO_V1_19_29,
        Ok(_) | Err(env::VarError::NotUnicode(_)) => {
            panic!("SUB_HUB_MIHOMO_VERSION must be unset, v1.19.27, or v1.19.29")
        }
    }
}

fn acl4ssr_corpus_is_required() -> bool {
    match env::var(REQUIRE_ACL4SSR_CORPUS_ENV) {
        Ok(value) if value == "1" => true,
        Ok(value) if value == "0" => false,
        Err(env::VarError::NotPresent) => false,
        Ok(_) | Err(env::VarError::NotUnicode(_)) => {
            panic!("SUB_HUB_REQUIRE_ACL4SSR_CORPUS must be unset, 0, or 1")
        }
    }
}

fn configured_acl4ssr_corpus_root(required: bool) -> Option<PathBuf> {
    let configured =
        env::var_os(ACL4SSR_CORPUS_DIR_ENV).filter(|value| !value.as_os_str().is_empty());
    let Some(configured) = configured else {
        assert!(
            !required,
            "SUB_HUB_ACL4SSR_CORPUS_DIR must be set when SUB_HUB_REQUIRE_ACL4SSR_CORPUS=1"
        );
        eprintln!("generated ACL4SSR Mihomo acceptance skipped: corpus directory is not set");
        return None;
    };

    match fs::canonicalize(configured) {
        Ok(path) if path.is_dir() => Some(path),
        Ok(_) | Err(_) => panic!("SUB_HUB_ACL4SSR_CORPUS_DIR must identify a directory"),
    }
}

fn render_acl4ssr_profile(root: &Path, config_path: &str) -> Vec<u8> {
    let config = read_acl4ssr_corpus_file(root, config_path);
    let prepared = prepare_direct(&[VALID_DIRECT])
        .expect("fixed corpus subscription must be valid")
        .prepare_acl4ssr_config_v1(&config)
        .expect("fixed corpus config must match its compile-time policy");
    let bodies = prepared
        .rule_set_requests()
        .iter()
        .map(|request| {
            let relative = request
                .url()
                .strip_prefix(ACL4SSR_REMOTE_PREFIX)
                .expect("fixed corpus Rule Set URL must use the approved prefix");
            read_acl4ssr_corpus_file(root, relative)
        })
        .collect::<Vec<_>>();
    let body_refs = bodies.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let urls: Vec<String> = (0..prepared.rule_set_requests().len())
        .map(|index| format!("https://rules.example/flight/{index}"))
        .collect();
    prepared
        .bind_canonical_urls_v1(&urls)
        .expect("fixed corpus flight plan is bounded and dense")
        .render_v1(OutputTarget::Mihomo, &body_refs)
        .expect("fixed corpus must render through the strict conversion seam")
        .into_bytes()
}

fn read_acl4ssr_corpus_file(root: &Path, relative: &str) -> Vec<u8> {
    assert!(
        !relative
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | "..")),
        "fixed corpus path must be canonical"
    );
    fs::read(root.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR)))
        .unwrap_or_else(|_| panic!("required fixed corpus file is unavailable"))
}

fn verify_mihomo_version(binary: &Path, sandbox: &TestSandbox, expected: &str) {
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

    let version_matches = reports_expected_version(&output.stdout, expected)
        || reports_expected_version(&output.stderr, expected);
    assert!(
        output.status.success() && version_matches,
        "configured Mihomo binary does not match the approved version; process output withheld"
    );
}

fn reports_expected_version(output: &[u8], expected: &str) -> bool {
    let Ok(output) = std::str::from_utf8(output) else {
        return false;
    };

    output.lines().any(|line| {
        let mut fields = line.split_ascii_whitespace();
        fields.next() == Some("Mihomo")
            && fields.next() == Some("Meta")
            && fields.next() == Some(expected)
    })
}

fn verify_mihomo_config(binary: &Path, sandbox: &TestSandbox, fixture: &str) {
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
        Some(_) => panic!("Mihomo rejected {fixture}; process output withheld"),
        None => panic!("Mihomo configuration check timed out for {fixture}; output withheld"),
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
