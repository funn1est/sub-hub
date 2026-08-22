#![cfg(not(target_family = "wasm"))]

use std::{
    collections::{BTreeMap, HashMap},
    env, fs,
    path::{Path, PathBuf},
};

use sub_hub_conversion::OutputTarget;

mod common;

const CORPUS_DIR_ENV: &str = "SUB_HUB_ACL4SSR_CORPUS_DIR";
const REQUIRE_CORPUS_ENV: &str = "SUB_HUB_REQUIRE_ACL4SSR_CORPUS";
const REMOTE_PREFIX: &str = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/";
const VALID_DIRECT: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";

struct ExpectedOutputStructure {
    group_count: usize,
    group_types: &'static [(&'static str, usize)],
    rule_count: usize,
    rule_types: &'static [(&'static str, usize)],
}

const ONLINE_OUTPUT: ExpectedOutputStructure = ExpectedOutputStructure {
    group_count: 11,
    group_types: &[("select", 10), ("url-test", 1)],
    rule_count: 3_528,
    rule_types: &[
        ("DOMAIN", 159),
        ("DOMAIN-KEYWORD", 94),
        ("DOMAIN-SUFFIX", 2_876),
        ("GEOIP", 1),
        ("IP-CIDR", 380),
        ("IP-CIDR6", 14),
        ("MATCH", 1),
        ("PROCESS-NAME", 3),
    ],
};

const FULL_OUTPUT: ExpectedOutputStructure = ExpectedOutputStructure {
    group_count: 31,
    group_types: &[
        ("fallback", 1),
        ("load-balance", 1),
        ("select", 28),
        ("url-test", 1),
    ],
    rule_count: 10_410,
    rule_types: &[
        ("DOMAIN", 199),
        ("DOMAIN-KEYWORD", 106),
        ("DOMAIN-SUFFIX", 9_622),
        ("GEOIP", 1),
        ("IP-CIDR", 449),
        ("IP-CIDR6", 14),
        ("MATCH", 1),
        ("PROCESS-NAME", 18),
    ],
};

#[test]
fn pinned_online_and_full_corpus_cross_the_opaque_conversion_seam() {
    let Some(root) = configured_corpus_root() else {
        return;
    };
    verify_profile(
        &root,
        "Clash/config/ACL4SSR_Online.ini",
        14,
        1,
        0,
        0,
        &ONLINE_OUTPUT,
    );
    verify_profile(
        &root,
        "Clash/config/ACL4SSR_Online_Full_MultiMode.ini",
        31,
        9,
        2,
        7,
        &FULL_OUTPUT,
    );
    a_semantic_full_config_change_is_still_accepted(&root);
}

fn verify_profile(
    root: &Path,
    config_path: &str,
    expected_remote_count: usize,
    expected_omitted_count: u8,
    _expected_legacy_hint_count: u8,
    expected_empty_count: u8,
    expected_output: &ExpectedOutputStructure,
) {
    let config = read_corpus_file(root, config_path);
    let mut collected = HashMap::new();
    let outcome = render_corpus(root, &config, &mut collected)
        .expect("fixed corpus must render through Unique-flight fill");
    assert_eq!(outcome.outbound_count, expected_remote_count);
    let output = outcome.document;
    assert_eq!(output.omitted_url_regex(), expected_omitted_count);
    let text = std::str::from_utf8(output.as_bytes()).expect("utf-8");
    if expected_empty_count == 0 {
        assert!(!text.contains("empty proxy groups"));
    } else {
        assert!(text.contains(&format!(
            "empty proxy groups downgraded to select + REJECT; count={expected_empty_count}"
        )));
    }
    assert!(
        output.as_bytes().starts_with(
            b"# subconverter: lossy conversion; unsupported URL-REGEX rules omitted\n"
        )
    );
    assert_output_structure(output.as_bytes(), expected_output);

    let mut changed = collected;
    let (body_key, pattern_index) = changed
        .iter()
        .find_map(|(url, body)| {
            body.windows(b"URL-REGEX,".len())
                .position(|window| window == b"URL-REGEX,")
                .map(|index| (url.clone(), index + b"URL-REGEX,".len()))
        })
        .expect("fixed compatibility corpus must contain URL-REGEX evidence");
    let byte = changed.get_mut(&body_key).expect("collected body");
    byte[pattern_index] = match byte[pattern_index] {
        b'x' => b'y',
        _ => b'x',
    };
    let mutated = common::drive_session(
        common::start_direct_config(VALID_DIRECT, OutputTarget::Mihomo),
        |url| {
            if url == common::CONFIG_URL {
                return config.clone();
            }
            changed
                .get(url)
                .cloned()
                .unwrap_or_else(|| panic!("missing unique Rule Set body for {url}"))
        },
    )
    .expect("URL-REGEX pattern bytes are not a render gate");
    assert_eq!(mutated.document.omitted_url_regex(), expected_omitted_count);
}

fn render_corpus(
    root: &Path,
    config: &[u8],
    collected: &mut HashMap<String, Vec<u8>>,
) -> Result<common::DriveStats, sub_hub_conversion::UniqueFlightFillFailure> {
    common::drive_session(
        common::start_direct_config(VALID_DIRECT, OutputTarget::Mihomo),
        |url| {
            if url == common::CONFIG_URL {
                return config.to_vec();
            }
            collected
                .entry(url.to_owned())
                .or_insert_with(|| {
                    let relative = url
                        .strip_prefix(REMOTE_PREFIX)
                        .expect("fixed corpus Rule Set URL must use the approved prefix");
                    read_corpus_file(root, relative)
                })
                .clone()
        },
    )
}

fn assert_output_structure(output: &[u8], expected: &ExpectedOutputStructure) {
    let output = std::str::from_utf8(output).expect("fixed corpus output must be UTF-8");
    let (_, after_group_header) = output
        .split_once("proxy-groups:\n")
        .expect("fixed corpus output must contain proxy-groups");
    let (groups, rules) = after_group_header
        .split_once("rules:\n")
        .expect("fixed corpus output must contain rules after proxy-groups");

    let group_names = groups
        .lines()
        .filter(|line| line.starts_with("- name: "))
        .count();
    assert_eq!(group_names, expected.group_count);
    let actual_group_types = count_values(
        groups
            .lines()
            .filter_map(|line| line.strip_prefix("  type: ")),
    );
    assert_eq!(
        actual_group_types,
        expected.group_types.iter().copied().collect()
    );

    let rule_lines = rules
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    assert!(
        rule_lines.iter().all(|line| line.starts_with("- ")),
        "the rules section must contain only Mihomo rule entries"
    );
    assert_eq!(rule_lines.len(), expected.rule_count);
    let actual_rule_types = count_values(rule_lines.iter().map(|line| {
        line.strip_prefix("- ")
            .and_then(|rule| rule.split_once(','))
            .map(|(rule_type, _)| rule_type)
            .expect("fixed corpus output rule must contain a type and payload")
    }));
    assert_eq!(
        actual_rule_types,
        expected.rule_types.iter().copied().collect()
    );
    assert!(
        rule_lines
            .last()
            .is_some_and(|line| line.starts_with("- MATCH,")),
        "the final rendered rule must be MATCH"
    );
}

fn count_values<'a>(values: impl IntoIterator<Item = &'a str>) -> BTreeMap<&'a str, usize> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value).or_default() += 1;
    }
    counts
}

fn a_semantic_full_config_change_is_still_accepted(root: &Path) {
    let config = read_corpus_file(root, "Clash/config/ACL4SSR_Online_Full_MultiMode.ini");
    let config = String::from_utf8(config).expect("fixed config must be UTF-8");
    let changed = config.replacen(
        "https://raw.githubusercontent.com/",
        "https://RAW.githubusercontent.com/",
        1,
    );
    assert_ne!(changed, config);
    assert_eq!(
        common::count_rule_set_outbounds(VALID_DIRECT, changed.as_bytes())
            .expect("a declared-URL case change is not a Unique-flight fill gate"),
        31
    );
}

fn read_corpus_file(root: &Path, relative: &str) -> Vec<u8> {
    assert!(
        !relative
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | "..")),
        "fixed corpus path must be canonical"
    );
    fs::read(root.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR)))
        .unwrap_or_else(|_| panic!("required fixed corpus file is unavailable"))
}

fn configured_corpus_root() -> Option<PathBuf> {
    let required = match env::var(REQUIRE_CORPUS_ENV) {
        Ok(value) if value == "1" => true,
        Ok(value) if value == "0" => false,
        Err(env::VarError::NotPresent) => false,
        Ok(_) | Err(env::VarError::NotUnicode(_)) => {
            panic!("SUB_HUB_REQUIRE_ACL4SSR_CORPUS must be unset, 0, or 1")
        }
    };
    let configured = env::var_os(CORPUS_DIR_ENV).filter(|value| !value.is_empty());
    let Some(configured) = configured else {
        assert!(
            !required,
            "SUB_HUB_ACL4SSR_CORPUS_DIR must be set when SUB_HUB_REQUIRE_ACL4SSR_CORPUS=1"
        );
        eprintln!("fixed ACL4SSR corpus test skipped: corpus directory is not set");
        return None;
    };
    match fs::canonicalize(configured) {
        Ok(path) if path.is_dir() => Some(path),
        Ok(_) | Err(_) => panic!("SUB_HUB_ACL4SSR_CORPUS_DIR must identify a directory"),
    }
}
