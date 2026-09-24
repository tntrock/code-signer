//! CLI 端對端：實際執行 code-signer.exe，檢查 exit code、文字與 JSON 輸出。

use std::path::Path;
use std::process::{Command, Output};

const PW_VAR: &str = "CODE_SIGNER_TEST_PW";
const PW: &str = "cli-test-password";

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_code-signer"))
        .args(args)
        .env(PW_VAR, PW)
        .env_remove("CODE_SIGNER_LANG")
        .output()
        .expect("run code-signer")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|e| panic!("invalid JSON ({e}): {}", stdout(o)))
}

fn new_cert(dir: &Path) -> String {
    let pfx = dir.join("cli.pfx");
    let o = run(&[
        "new-cert",
        "--cn",
        "CLI Test",
        "--out",
        pfx.to_str().unwrap(),
        "--key-size",
        "2048",
        "--years",
        "1",
        "--password-env",
        PW_VAR,
        "--json",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
    let v = json(&o);
    assert_eq!(v["command"], "new-cert");
    assert_eq!(v["results"][0]["status"], "created");
    assert_eq!(v["results"][0]["signer"]["subject_cn"], "CLI Test");
    pfx.to_str().unwrap().to_string()
}

fn sample(dir: &Path, name: &str) -> String {
    let p = dir.join(name);
    std::fs::copy(env!("CARGO_BIN_EXE_code-signer"), &p).unwrap();
    p.to_str().unwrap().to_string()
}

#[test]
fn help_is_localized_and_exits_zero() {
    let zh = run(&["--lang", "zh-TW", "--help"]);
    assert_eq!(zh.status.code(), Some(0));
    assert!(stdout(&zh).contains("程式碼簽章"));
    let en = run(&["--lang", "en", "--help"]);
    assert!(stdout(&en).contains("code signing"));
}

#[test]
fn bad_arguments_exit_two() {
    assert_eq!(run(&["sign", "a.exe"]).status.code(), Some(2)); // 缺憑證來源
    assert_eq!(run(&["frobnicate"]).status.code(), Some(2));
}

#[test]
fn sign_then_verify_json_flow() {
    let dir = tempfile::tempdir().unwrap();
    let pfx = new_cert(dir.path());
    let exe = sample(dir.path(), "app.exe");

    let o = run(&[
        "sign",
        &exe,
        "--pfx",
        &pfx,
        "--password-env",
        PW_VAR,
        "--json",
        "--lang",
        "en",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
    let v = json(&o);
    assert_eq!(v["results"][0]["status"], "signed");
    assert_eq!(v["summary"]["succeeded"], 1);

    // 自簽根憑證不受信任 → 驗證不算成功，exit code 1
    let o = run(&["verify", &exe, "--json", "--lang", "zh-TW"]);
    assert_eq!(o.status.code(), Some(1));
    let v = json(&o);
    assert_eq!(v["results"][0]["status"], "untrusted_root");
    assert_eq!(v["results"][0]["message"], "根憑證不受信任 — CLI Test");
}

#[test]
fn wrong_password_is_setup_error() {
    let dir = tempfile::tempdir().unwrap();
    let pfx = new_cert(dir.path());
    let exe = sample(dir.path(), "app.exe");
    let o = Command::new(env!("CARGO_BIN_EXE_code-signer"))
        .args([
            "sign",
            &exe,
            "--pfx",
            &pfx,
            "--password-env",
            "WRONG_PW",
            "--json",
        ])
        .env("WRONG_PW", "nope-nope-nope")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(json(&o)["error"]["status"], "pfx_wrong_password");
}

#[test]
fn mixed_batch_exits_one_and_reports_each_file() {
    let dir = tempfile::tempdir().unwrap();
    let pfx = new_cert(dir.path());
    let exe = sample(dir.path(), "ok.exe");
    let missing = dir.path().join("missing.exe");
    let o = run(&[
        "sign",
        &exe,
        missing.to_str().unwrap(),
        "--pfx",
        &pfx,
        "--password-env",
        PW_VAR,
        "--json",
    ]);
    assert_eq!(o.status.code(), Some(1));
    let v = json(&o);
    assert_eq!(v["summary"]["total"], 2);
    assert_eq!(v["results"][1]["status"], "file_not_found");
}

#[test]
fn new_cert_refuses_to_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let pfx = new_cert(dir.path());
    let args = [
        "new-cert",
        "--cn",
        "X",
        "--out",
        &pfx,
        "--key-size",
        "2048",
        "--password-env",
        PW_VAR,
        "--json",
    ];
    let o = run(&args);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(json(&o)["error"]["status"], "output_exists");
    let mut forced = args.to_vec();
    forced.push("--force");
    assert_eq!(run(&forced).status.code(), Some(0));
}

#[test]
fn text_output_has_marks_and_summary() {
    let dir = tempfile::tempdir().unwrap();
    let exe = sample(dir.path(), "plain.exe");
    let o = run(&["verify", &exe, "--lang", "en"]);
    assert_eq!(o.status.code(), Some(1));
    let out = stdout(&o);
    assert!(out.contains("✘"), "{out}");
    assert!(out.contains("Not signed"), "{out}");
    assert!(out.contains("1 file(s): 0 succeeded, 1 failed"), "{out}");
}
