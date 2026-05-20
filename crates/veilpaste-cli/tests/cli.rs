use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::io::Write;
use std::process::Command as StdCommand;
use tempfile::NamedTempFile;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn default_stdin_scrubs_to_stdout() {
    let mut cmd = Command::cargo_bin("veilpaste").expect("binary exists");

    cmd.write_stdin("Authorization: Bearer sk-live-abc1234567890")
        .assert()
        .success()
        .stdout(predicate::str::contains("[BEARER_TOKEN_1]"))
        .stdout(predicate::str::contains("sk-live-abc1234567890").not());
}

#[test]
fn preview_lists_redactions_without_scrubbed_body() {
    let mut input = NamedTempFile::new().expect("temp file");
    writeln!(input, "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz").unwrap();

    let mut cmd = Command::cargo_bin("veilpaste").expect("binary exists");
    cmd.args(["scrub", input.path().to_str().unwrap(), "--preview"])
        .assert()
        .success()
        .stdout(predicate::str::contains("WOULD_REDACT"))
        .stdout(predicate::str::contains("[OPENAI_KEY_1]"))
        .stdout(predicate::str::contains("sk-proj-abcdefghijklmnopqrstuvwxyz").not());
}

#[test]
fn check_exits_one_when_secret_is_found() {
    let mut input = NamedTempFile::new().expect("temp file");
    writeln!(input, "Authorization: Bearer sk-live-abc1234567890").unwrap();

    let mut cmd = Command::cargo_bin("veilpaste").expect("binary exists");
    cmd.args(["check", input.path().to_str().unwrap()])
        .assert()
        .code(1);
}

#[test]
fn scrub_writes_mapping_and_restore_uses_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let input_path = dir.path().join("input.env");
    let output_path = dir.path().join("ai-output.env");
    let map_path = dir.path().join("session.json");

    fs::write(
        &input_path,
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz",
    )
    .unwrap();

    let mut scrub = Command::cargo_bin("veilpaste").expect("binary exists");
    let scrubbed = scrub
        .args([
            "scrub",
            input_path.to_str().unwrap(),
            "--map",
            map_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    fs::write(
        &output_path,
        String::from_utf8(scrubbed)
            .unwrap()
            .replace("OPENAI_API_KEY", "FIXED_OPENAI_API_KEY"),
    )
    .unwrap();

    let mut restore = Command::cargo_bin("veilpaste").expect("binary exists");
    restore
        .args([
            "restore",
            output_path.to_str().unwrap(),
            "--map",
            map_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "FIXED_OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz",
        ));
}

#[test]
fn scrub_writes_mapping_metadata_and_restrictive_permissions() {
    let dir = tempfile::tempdir().expect("temp dir");
    let input_path = dir.path().join("input.env");
    let map_path = dir.path().join(".veilpaste/session.json");
    fs::write(
        &input_path,
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("veilpaste").expect("binary exists");
    cmd.args([
        "scrub",
        input_path.to_str().unwrap(),
        "--map",
        map_path.to_str().unwrap(),
    ])
    .assert()
    .success();

    let map_text = fs::read_to_string(&map_path).expect("mapping should exist");
    let map_json: serde_json::Value = serde_json::from_str(&map_text).expect("mapping json");
    assert_eq!(map_json["version"], 1);
    assert!(map_json["session_id"]
        .as_str()
        .is_some_and(|v| !v.is_empty()));
    assert!(map_json["created_at"]
        .as_str()
        .is_some_and(|v| !v.is_empty()));

    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&map_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn map_inspect_hides_original_secret_values() {
    let dir = tempfile::tempdir().expect("temp dir");
    let input_path = dir.path().join("input.env");
    let map_path = dir.path().join("session.json");
    fs::write(
        &input_path,
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz",
    )
    .unwrap();

    let mut scrub = Command::cargo_bin("veilpaste").expect("binary exists");
    scrub
        .args([
            "scrub",
            input_path.to_str().unwrap(),
            "--map",
            map_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut inspect = Command::cargo_bin("veilpaste").expect("binary exists");
    inspect
        .args(["map", "inspect", "--map", map_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("[OPENAI_KEY_1]"))
        .stdout(predicate::str::contains("OpenAiKey"))
        .stdout(predicate::str::contains("sk-proj-abcdefghijklmnopqrstuvwxyz").not());
}

#[test]
fn quiet_flag_is_accepted_for_pipeline_use() {
    let mut cmd = Command::cargo_bin("veilpaste").expect("binary exists");

    cmd.args(["--quiet"])
        .write_stdin("Authorization: Bearer sk-live-abc1234567890")
        .assert()
        .success()
        .stdout(predicate::str::contains("[BEARER_TOKEN_1]"));
}

#[test]
fn warns_when_mapping_file_is_inside_git_repo_without_ignore_rule() {
    let dir = tempfile::tempdir().expect("temp dir");
    StdCommand::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .expect("git init should run");
    let input_path = dir.path().join("input.env");
    let map_path = dir.path().join(".veilpaste/session.json");
    fs::write(
        &input_path,
        "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("veilpaste").expect("binary exists");
    cmd.current_dir(dir.path())
        .args([
            "scrub",
            input_path.to_str().unwrap(),
            "--map",
            map_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "mapping file contains live secrets",
        ))
        .stderr(predicate::str::contains(".veilpaste/"));
}

#[test]
fn version_flag_prints_crate_version() {
    let mut cmd = Command::cargo_bin("veilpaste").expect("binary exists");

    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn check_prints_summary_for_found_secrets() {
    let mut input = NamedTempFile::new().expect("temp file");
    writeln!(input, "Authorization: Bearer sk-live-abc1234567890").unwrap();

    let mut cmd = Command::cargo_bin("veilpaste").expect("binary exists");
    cmd.args(["check", input.path().to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("1 high-confidence secret"))
        .stdout(predicate::str::contains("BearerToken"));
}

#[test]
fn check_prints_clean_summary_when_no_secret_is_found() {
    let mut input = NamedTempFile::new().expect("temp file");
    writeln!(input, "word=sketch").unwrap();

    let mut cmd = Command::cargo_bin("veilpaste").expect("binary exists");
    cmd.args(["check", input.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("No high-confidence secrets found"));
}
