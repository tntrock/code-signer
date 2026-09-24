//! 命令列介面：sign / verify / new-cert。
//!
//! 用 clap builder（而非 derive），才能讓 `--help` 文字跟著語言切換。
//! Exit code：0 全部成功；1 至少一個檔案失敗；2 參數、憑證或其他前置錯誤。

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use serde::Serialize;

use crate::core::batch::{expand_paths, run_batch};
use crate::core::cert::{
    create_self_signed, install_trust, load_cert, CertSource, CertSummary, NewCertParams, RsaBits,
    Secret, StoreLocation,
};
use crate::core::signer::{sign_file, SignOptions, DEFAULT_TIMESTAMP_URL};
use crate::core::verify::{verify_file, VerifyStatus};
use crate::core::CoreError;
use crate::i18n::{format_time, Lang, Strings};

pub const EXIT_OK: i32 = 0;
pub const EXIT_FILE_FAILED: i32 = 1;
pub const EXIT_SETUP_FAILED: i32 = 2;

/// 在 clap 解析前決定語言：`--lang` > `CODE_SIGNER_LANG` > 系統語言。
pub fn resolve_lang(args: &[OsString]) -> Lang {
    let mut iter = args.iter().filter_map(|a| a.to_str());
    while let Some(a) = iter.next() {
        if let Some(v) = a.strip_prefix("--lang=") {
            if let Some(l) = Lang::parse(v) {
                return l;
            }
        } else if a == "--lang" {
            if let Some(l) = iter.next().and_then(Lang::parse) {
                return l;
            }
        }
    }
    std::env::var("CODE_SIGNER_LANG")
        .ok()
        .and_then(|v| Lang::parse(&v))
        .unwrap_or_else(Lang::detect)
}

pub fn build_command(t: &'static Strings) -> Command {
    let paths = Arg::new("paths")
        .help(t.h_paths)
        .value_name("PATH")
        .num_args(1..)
        .required(true)
        .value_parser(value_parser!(PathBuf));
    let recursive = Arg::new("recursive")
        .short('r')
        .long("recursive")
        .help(t.h_recursive)
        .action(ArgAction::SetTrue);
    let password_env = Arg::new("password-env")
        .long("password-env")
        .value_name("VAR")
        .help(t.h_password_env);

    Command::new("code-signer")
        .version(env!("CARGO_PKG_VERSION"))
        .about(t.cli_about)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("json")
                .long("json")
                .global(true)
                .help(t.h_json)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("lang")
                .long("lang")
                .global(true)
                .value_name("LANG")
                .help(t.h_lang),
        )
        .subcommand(
            Command::new("sign")
                .about(t.cli_sign_about)
                .arg(paths.clone())
                .arg(
                    Arg::new("pfx")
                        .long("pfx")
                        .value_name("FILE")
                        .help(t.h_pfx)
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    Arg::new("thumbprint")
                        .long("thumbprint")
                        .value_name("HEX")
                        .help(t.h_thumbprint),
                )
                .group(
                    clap::ArgGroup::new("cert")
                        .args(["pfx", "thumbprint"])
                        .required(true),
                )
                .arg(
                    Arg::new("store")
                        .long("store")
                        .value_name("user|machine")
                        .help(t.h_store)
                        .value_parser(["user", "machine"])
                        .default_value("user")
                        .requires("thumbprint"),
                )
                .arg(password_env.clone())
                .arg(
                    Arg::new("timestamp")
                        .long("timestamp")
                        .value_name("URL")
                        .help(t.h_timestamp)
                        .num_args(0..=1)
                        // 值必須用 `--timestamp=URL` 這種等號形式給，否則
                        // `sign --timestamp a.exe --pfx x` 會把下一個路徑
                        // 貪婪地吃成時間戳記 URL。
                        .require_equals(true)
                        .default_missing_value(DEFAULT_TIMESTAMP_URL),
                )
                .arg(recursive.clone()),
        )
        .subcommand(
            Command::new("verify")
                .about(t.cli_verify_about)
                .arg(paths)
                .arg(recursive),
        )
        .subcommand(
            Command::new("new-cert")
                .about(t.cli_new_cert_about)
                .arg(
                    Arg::new("cn")
                        .long("cn")
                        .value_name("NAME")
                        .help(t.h_cn)
                        .required(true),
                )
                .arg(Arg::new("org").long("org").value_name("ORG").help(t.h_org))
                .arg(
                    Arg::new("years")
                        .long("years")
                        .value_name("1-10")
                        .help(t.h_years)
                        .value_parser(value_parser!(u32).range(1..=10))
                        .default_value("3"),
                )
                .arg(
                    Arg::new("key-size")
                        .long("key-size")
                        .help(t.h_key_size)
                        .value_parser(["2048", "3072", "4096"])
                        .default_value("3072"),
                )
                .arg(
                    Arg::new("out")
                        .long("out")
                        .value_name("FILE.pfx")
                        .help(t.h_out)
                        .required(true)
                        .value_parser(value_parser!(PathBuf)),
                )
                .arg(password_env)
                .arg(
                    Arg::new("install-trust")
                        .long("install-trust")
                        .help(t.h_install_trust)
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("force")
                        .long("force")
                        .help(t.h_force)
                        .action(ArgAction::SetTrue),
                ),
        )
}

// ---------------------------------------------------------------------------
// 輸出
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct JsonResult {
    path: String,
    ok: bool,
    status: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer: Option<CertSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
}

#[derive(Serialize)]
struct JsonSummary {
    total: usize,
    succeeded: usize,
    failed: usize,
}

#[derive(Serialize)]
struct JsonOutput {
    command: &'static str,
    results: Vec<JsonResult>,
    summary: JsonSummary,
}

struct Output {
    json: bool,
    t: &'static Strings,
    command: &'static str,
    results: Vec<JsonResult>,
}

impl Output {
    fn push(&mut self, r: JsonResult) {
        if !self.json {
            let mark = if r.ok { "✔" } else { "✘" };
            println!("{mark} {}  {}", r.path, r.message);
        }
        self.results.push(r);
    }

    /// 印出摘要（或整份 JSON），回傳 exit code。
    fn finish(self) -> i32 {
        let failed = self.results.iter().filter(|r| !r.ok).count();
        let total = self.results.len();
        if self.json {
            let out = JsonOutput {
                command: self.command,
                summary: JsonSummary {
                    total,
                    succeeded: total - failed,
                    failed,
                },
                results: self.results,
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&out).expect("serializable")
            );
        } else {
            println!("{}", self.t.summary(total, total - failed, failed));
        }
        if failed == 0 {
            EXIT_OK
        } else {
            EXIT_FILE_FAILED
        }
    }

    /// 前置錯誤：印出並回傳 exit code 2。
    fn setup_error(self, message: String, code: &str) -> i32 {
        if self.json {
            let v = serde_json::json!({ "command": self.command, "error": { "status": code, "message": message } });
            println!(
                "{}",
                serde_json::to_string_pretty(&v).expect("serializable")
            );
        } else {
            eprintln!("✘ {message}");
        }
        EXIT_SETUP_FAILED
    }
}

fn error_result(path: String, t: &Strings, e: &CoreError) -> JsonResult {
    JsonResult {
        path,
        ok: false,
        status: e.code().into(),
        message: t.error(e),
        signer: None,
        timestamp: None,
    }
}

// ---------------------------------------------------------------------------
// 指令
// ---------------------------------------------------------------------------

/// CLI 進入點；回傳 exit code。
pub fn run(args: Vec<OsString>) -> i32 {
    let lang = resolve_lang(&args);
    let t = lang.strings();
    let matches = match build_command(t).try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() {
                EXIT_SETUP_FAILED
            } else {
                EXIT_OK
            };
        }
    };
    let json = matches.get_flag("json");
    match matches.subcommand() {
        Some(("sign", m)) => cmd_sign(m, t, json),
        Some(("verify", m)) => cmd_verify(m, t, json),
        Some(("new-cert", m)) => cmd_new_cert(m, t, json),
        _ => EXIT_SETUP_FAILED,
    }
}

/// 取得密碼：`--password-env` 指定的環境變數，否則在終端機提示輸入。
///
/// 提示文字用 `eprint!` 印到 stderr（Rust 對 stderr 使用 WriteConsoleW，在主控台上
/// 正確顯示中文），再呼叫 `rpassword::read_password()`；不能用
/// `rpassword::prompt_password`，它是用 WriteFile 寫原始 UTF-8 位元組到
/// CONOUT$，在預設 CP950 主控台上繁體中文提示會變成亂碼。stdout 維持乾淨，
/// 不受影響（`--json` 仍可正常解析）。
fn read_password(m: &ArgMatches, t: &Strings, prompt: &str) -> Result<Secret, String> {
    if let Some(var) = m.get_one::<String>("password-env") {
        return std::env::var(var)
            .map(Secret::new)
            .map_err(|_| format!("{}: {var}", t.err_env_missing));
    }
    use std::io::Write as _;
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    rpassword::read_password()
        .map(Secret::new)
        .map_err(|e| e.to_string())
}

fn paths_of(m: &ArgMatches) -> Vec<PathBuf> {
    let inputs: Vec<PathBuf> = m
        .get_many::<PathBuf>("paths")
        .map(|v| v.cloned().collect())
        .unwrap_or_default();
    expand_paths(&inputs, m.get_flag("recursive"))
}

fn cmd_sign(m: &ArgMatches, t: &'static Strings, json: bool) -> i32 {
    let out = Output {
        json,
        t,
        command: "sign",
        results: Vec::new(),
    };
    let files = paths_of(m);
    if files.is_empty() {
        return out.setup_error(t.err_no_files.into(), "no_files");
    }
    let source = if let Some(pfx) = m.get_one::<PathBuf>("pfx") {
        let password = match read_password(m, t, t.prompt_password) {
            Ok(p) => p,
            Err(msg) => return out.setup_error(msg, "password_unavailable"),
        };
        CertSource::Pfx {
            path: pfx.clone(),
            password,
        }
    } else {
        let location = match m.get_one::<String>("store").map(String::as_str) {
            Some("machine") => StoreLocation::LocalMachine,
            _ => StoreLocation::CurrentUser,
        };
        CertSource::Store {
            thumbprint: m
                .get_one::<String>("thumbprint")
                .cloned()
                .unwrap_or_default(),
            location,
        }
    };
    let cert = match load_cert(&source) {
        Ok(c) => c,
        Err(e) => return out.setup_error(t.error(&e), e.code()),
    };
    let opts = SignOptions {
        timestamp_url: m.get_one::<String>("timestamp").cloned(),
    };
    let cancel = AtomicBool::new(false);
    let mut out = out;
    run_batch(
        &files,
        &cancel,
        |p| sign_file(p, &cert, &opts),
        |_, r| {
            let path = r.path.display().to_string();
            out.push(match &r.result {
                Ok(()) => JsonResult {
                    path,
                    ok: true,
                    status: "signed".into(),
                    message: t.st_signed.into(),
                    signer: Some(cert.summary.clone()),
                    timestamp: None,
                },
                Err(e) => error_result(path, t, e),
            });
        },
    );
    out.finish()
}

fn cmd_verify(m: &ArgMatches, t: &'static Strings, json: bool) -> i32 {
    let mut out = Output {
        json,
        t,
        command: "verify",
        results: Vec::new(),
    };
    let files = paths_of(m);
    if files.is_empty() {
        return out.setup_error(t.err_no_files.into(), "no_files");
    }
    let cancel = AtomicBool::new(false);
    run_batch(&files, &cancel, verify_file, |_, r| {
        let path = r.path.display().to_string();
        out.push(match &r.result {
            Ok(rep) => {
                let mut message = t.status(&rep.status);
                if let Some(s) = &rep.signer {
                    message.push_str(&format!(" — {}", s.subject_cn));
                }
                JsonResult {
                    path,
                    ok: rep.status == VerifyStatus::Valid,
                    status: rep.status.code().into(),
                    message,
                    signer: rep.signer.clone(),
                    timestamp: rep.timestamp.map(format_time),
                }
            }
            Err(e) => error_result(path, t, e),
        });
    });
    out.finish()
}

fn cmd_new_cert(m: &ArgMatches, t: &'static Strings, json: bool) -> i32 {
    let mut out = Output {
        json,
        t,
        command: "new-cert",
        results: Vec::new(),
    };
    let password = if m.contains_id("password-env") && m.get_one::<String>("password-env").is_some()
    {
        match read_password(m, t, t.prompt_new_password) {
            Ok(p) => p,
            Err(msg) => return out.setup_error(msg, "password_unavailable"),
        }
    } else {
        let first = match read_password(m, t, t.prompt_new_password) {
            Ok(p) => p,
            Err(msg) => return out.setup_error(msg, "password_unavailable"),
        };
        let second = match read_password(m, t, t.prompt_confirm_password) {
            Ok(p) => p,
            Err(msg) => return out.setup_error(msg, "password_unavailable"),
        };
        if *first != *second {
            return out.setup_error(t.password_mismatch.into(), "password_mismatch");
        }
        first
    };
    let key_bits = m
        .get_one::<String>("key-size")
        .and_then(|s| s.parse().ok())
        .and_then(RsaBits::from_bits)
        .unwrap_or(RsaBits::B3072);
    let out_path = m.get_one::<PathBuf>("out").cloned().unwrap_or_default();
    let params = NewCertParams {
        common_name: m.get_one::<String>("cn").cloned().unwrap_or_default(),
        organization: m.get_one::<String>("org").cloned(),
        validity_years: *m.get_one::<u32>("years").unwrap_or(&3),
        key_bits,
        out_path: out_path.clone(),
        password,
        overwrite: m.get_flag("force"),
    };
    let created = match create_self_signed(&params) {
        Ok(c) => c,
        Err(e) => return out.setup_error(t.error(&e), e.code()),
    };
    let mut message = format!("{} — {}", t.cert_created, created.summary.subject_cn);
    if m.get_flag("install-trust") {
        if !json {
            println!("{}", t.cli_trust_prompt_note);
        }
        if let Err(e) = install_trust(&created.der) {
            out.push(JsonResult {
                path: out_path.display().to_string(),
                ok: false,
                status: e.code().into(),
                message: format!("{}: {}", t.trust_failed, t.error(&e)),
                signer: Some(created.summary),
                timestamp: None,
            });
            return out.finish();
        }
        message.push_str(&format!("; {}", t.trust_installed));
    }
    out.push(JsonResult {
        path: out_path.display().to_string(),
        ok: true,
        status: "created".into(),
        message,
        signer: Some(created.summary),
        timestamp: None,
    });
    out.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn lang_flag_wins() {
        assert_eq!(
            resolve_lang(&os(&["code-signer", "--lang", "en", "verify", "a.exe"])),
            Lang::En
        );
        assert_eq!(
            resolve_lang(&os(&["code-signer", "verify", "--lang=zh-TW", "a.exe"])),
            Lang::ZhTw
        );
    }

    #[test]
    fn command_definition_is_valid_in_both_languages() {
        for l in Lang::ALL {
            build_command(l.strings()).debug_assert();
        }
    }

    #[test]
    fn sign_requires_exactly_one_cert_source() {
        let cmd = || build_command(Lang::En.strings());
        assert!(cmd().try_get_matches_from(["cs", "sign", "a.exe"]).is_err());
        assert!(cmd()
            .try_get_matches_from([
                "cs",
                "sign",
                "a.exe",
                "--pfx",
                "a.pfx",
                "--thumbprint",
                "AB"
            ])
            .is_err());
        let m = cmd()
            .try_get_matches_from(["cs", "sign", "a.exe", "--pfx", "a.pfx", "--timestamp"])
            .unwrap();
        let (_, sm) = m.subcommand().unwrap();
        assert_eq!(
            sm.get_one::<String>("timestamp").map(String::as_str),
            Some(DEFAULT_TIMESTAMP_URL)
        );
    }

    #[test]
    fn bare_timestamp_does_not_swallow_the_next_path() {
        let cmd = || build_command(Lang::En.strings());
        let m = cmd()
            .try_get_matches_from(["cs", "sign", "--timestamp", "a.exe", "--pfx", "p.pfx"])
            .unwrap();
        let (_, sm) = m.subcommand().unwrap();
        let paths: Vec<String> = sm
            .get_many::<PathBuf>("paths")
            .unwrap()
            .map(|p| p.display().to_string())
            .collect();
        assert!(paths.contains(&"a.exe".to_string()), "{paths:?}");
        assert_eq!(
            sm.get_one::<String>("timestamp").map(String::as_str),
            Some(DEFAULT_TIMESTAMP_URL)
        );

        let m = cmd()
            .try_get_matches_from([
                "cs",
                "sign",
                "a.exe",
                "--pfx",
                "p.pfx",
                "--timestamp=http://x",
            ])
            .unwrap();
        let (_, sm) = m.subcommand().unwrap();
        assert_eq!(
            sm.get_one::<String>("timestamp").map(String::as_str),
            Some("http://x")
        );
    }
}
