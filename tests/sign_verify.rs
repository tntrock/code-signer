//! 端對端：產生自簽憑證 → 簽章 → 驗證 → 竄改偵測。只在 Windows 上執行，且不修改系統信任清單。

use std::path::{Path, PathBuf};

use code_signer::core::cert::{
    create_self_signed, load_cert, CertSource, NewCertParams, RsaBits, Secret,
};
use code_signer::core::signer::{sign_file, SignOptions};
use code_signer::core::verify::{verify_file, VerifyStatus};
use code_signer::core::CoreError;

const PASSWORD: &str = "integration-test-pw";

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    pfx: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let pfx = root.join("test.pfx");
    create_self_signed(&NewCertParams {
        common_name: "Integration Test Signing".into(),
        organization: None,
        validity_years: 1,
        key_bits: RsaBits::B2048,
        out_path: pfx.clone(),
        password: Secret::new(PASSWORD.into()),
        overwrite: false,
    })
    .unwrap();
    Fixture {
        _dir: dir,
        root,
        pfx,
    }
}

/// 以測試執行檔本身作為未簽章的 PE 樣本。
fn sample_exe(root: &Path, name: &str) -> PathBuf {
    let p = root.join(name);
    std::fs::copy(std::env::current_exe().unwrap(), &p).unwrap();
    p
}

fn source(f: &Fixture) -> CertSource {
    CertSource::Pfx {
        path: f.pfx.clone(),
        password: Secret::new(PASSWORD.into()),
    }
}

fn leftover_temp_files(root: &Path) -> Vec<String> {
    std::fs::read_dir(root)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".code-signer-tmp."))
        .collect()
}

#[test]
fn unsigned_file_reports_unsigned() {
    let f = fixture();
    let exe = sample_exe(&f.root, "plain.exe");
    let r = verify_file(&exe).unwrap();
    assert_eq!(r.status, VerifyStatus::Unsigned);
    assert!(r.signer.is_none());
}

#[test]
fn signed_file_verifies_as_untrusted_root_with_signer() {
    let f = fixture();
    let exe = sample_exe(&f.root, "app.exe");
    let cert = load_cert(&source(&f)).unwrap();
    sign_file(&exe, &cert, &SignOptions::default()).unwrap();

    let r = verify_file(&exe).unwrap();
    // 自簽根憑證不在信任清單中
    assert_eq!(r.status, VerifyStatus::UntrustedRoot);
    let signer = r.signer.unwrap();
    assert_eq!(signer.subject_cn, "Integration Test Signing");
    assert_eq!(signer.sha1, cert.summary.sha1);
    assert!(r.timestamp.is_none());
    assert!(leftover_temp_files(&f.root).is_empty());
}

#[test]
fn tampered_file_is_detected() {
    let f = fixture();
    let exe = sample_exe(&f.root, "app.exe");
    let cert = load_cert(&source(&f)).unwrap();
    sign_file(&exe, &cert, &SignOptions::default()).unwrap();

    let mut bytes = std::fs::read(&exe).unwrap();
    bytes[0x200] ^= 0xFF;
    std::fs::write(&exe, bytes).unwrap();
    assert_eq!(verify_file(&exe).unwrap().status, VerifyStatus::Tampered);
}

#[test]
fn powershell_script_can_be_signed() {
    let f = fixture();
    let ps1 = f.root.join("tool.ps1");
    std::fs::write(&ps1, "Write-Host 'hi'\r\n").unwrap();
    let cert = load_cert(&source(&f)).unwrap();
    sign_file(&ps1, &cert, &SignOptions::default()).unwrap();
    assert_eq!(
        verify_file(&ps1).unwrap().status,
        VerifyStatus::UntrustedRoot
    );
}

#[test]
fn failed_timestamp_leaves_original_untouched() {
    let f = fixture();
    let exe = sample_exe(&f.root, "app.exe");
    let before = std::fs::read(&exe).unwrap();
    let cert = load_cert(&source(&f)).unwrap();
    // 連接埠 9（discard）沒有服務，連線會被拒絕
    let opts = SignOptions {
        timestamp_url: Some("http://127.0.0.1:9/".into()),
    };
    let err = sign_file(&exe, &cert, &opts).unwrap_err();
    assert!(matches!(err, CoreError::TimestampFailed(_)), "got {err:?}");
    assert_eq!(std::fs::read(&exe).unwrap(), before);
    assert!(leftover_temp_files(&f.root).is_empty());
}

#[test]
fn unsupported_and_missing_files_are_rejected() {
    let f = fixture();
    let cert = load_cert(&source(&f)).unwrap();
    let txt = f.root.join("a.txt");
    std::fs::write(&txt, "x").unwrap();
    assert_eq!(
        sign_file(&txt, &cert, &SignOptions::default()),
        Err(CoreError::UnsupportedFileType)
    );
    assert_eq!(
        sign_file(&f.root.join("missing.exe"), &cert, &SignOptions::default()),
        Err(CoreError::FileNotFound)
    );
}

#[test]
#[ignore = "需要網路：cargo test -- --ignored"]
fn timestamp_is_recorded() {
    let f = fixture();
    let exe = sample_exe(&f.root, "app.exe");
    let cert = load_cert(&source(&f)).unwrap();
    let opts = SignOptions {
        timestamp_url: Some(code_signer::core::signer::DEFAULT_TIMESTAMP_URL.into()),
    };
    sign_file(&exe, &cert, &opts).unwrap();
    let r = verify_file(&exe).unwrap();
    let ts = r.timestamp.expect("timestamp");
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    assert!(
        (now - ts).abs() < 600,
        "timestamp {ts} too far from now {now}"
    );
}
