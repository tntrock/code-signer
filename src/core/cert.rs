//! 憑證：解析摘要、產生自簽憑證、從 .pfx 或 Windows 憑證存放區載入、匯入信任清單。

use std::path::{Path, PathBuf};

use serde::Serialize;
use windows::core::{w, PCWSTR};
use windows::Win32::Security::Cryptography::*;
use zeroize::Zeroizing;

use super::error::MIN_PASSWORD_LEN;
use super::CoreError;

/// 密碼：離開作用域時自動清除記憶體內容。
pub type Secret = Zeroizing<String>;

/// 憑證的可顯示摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertSummary {
    pub subject_cn: String,
    pub organization: Option<String>,
    pub issuer_cn: String,
    /// SHA-1 指紋（大寫十六進位，無分隔），即 Windows 顯示的「指紋」
    pub sha1: String,
    pub sha256: String,
    /// Unix 秒
    pub not_before: i64,
    pub not_after: i64,
    /// 是否含 Code Signing EKU（或未限制 EKU／含 anyExtendedKeyUsage）
    #[serde(skip)]
    pub code_signing: bool,
}

/// 解析 DER 編碼的 X.509 憑證。
pub fn summarize_der(der: &[u8]) -> Result<CertSummary, CoreError> {
    use sha1::Digest as _;
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der).map_err(|_| CoreError::PfxInvalid)?;
    let first = |it: &mut dyn Iterator<Item = &AttributeTypeAndValue>| {
        it.next().and_then(|a| a.as_str().ok()).map(str::to_string)
    };
    let subject_cn = first(&mut cert.subject().iter_common_name()).unwrap_or_default();
    let organization = first(&mut cert.subject().iter_organization());
    let issuer_cn = first(&mut cert.issuer().iter_common_name()).unwrap_or_default();
    let code_signing = match cert.extended_key_usage() {
        Ok(Some(eku)) => eku.value.code_signing || eku.value.any,
        Ok(None) => true,
        Err(_) => false,
    };
    Ok(CertSummary {
        subject_cn,
        organization,
        issuer_cn,
        sha1: hex_upper(&sha1::Sha1::digest(der)),
        sha256: hex_upper(&sha2::Sha256::digest(der)),
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        code_signing,
    })
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// 檢查憑證能否用於程式碼簽章：EKU 與有效期間。
pub fn check_signing_usable(s: &CertSummary) -> Result<(), CoreError> {
    if !s.code_signing {
        return Err(CoreError::CertNotCodeSigning);
    }
    let now = now_unix();
    if now < s.not_before {
        return Err(CoreError::CertNotYetValid);
    }
    if now > s.not_after {
        return Err(CoreError::CertExpired);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 產生自簽憑證
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaBits {
    B2048,
    B3072,
    B4096,
}

impl RsaBits {
    pub const ALL: [RsaBits; 3] = [RsaBits::B2048, RsaBits::B3072, RsaBits::B4096];

    pub fn bits(self) -> usize {
        match self {
            RsaBits::B2048 => 2048,
            RsaBits::B3072 => 3072,
            RsaBits::B4096 => 4096,
        }
    }

    pub fn from_bits(bits: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|b| b.bits() == bits)
    }
}

/// 可選的有效年限。
pub const VALIDITY_YEARS: [u32; 5] = [1, 2, 3, 5, 10];

pub struct NewCertParams {
    pub common_name: String,
    pub organization: Option<String>,
    pub validity_years: u32,
    pub key_bits: RsaBits,
    pub out_path: PathBuf,
    pub password: Secret,
    /// 輸出檔已存在時是否覆寫
    pub overwrite: bool,
}

/// 產生結果：摘要與公開憑證 DER（供匯入信任清單使用）。
#[derive(Debug, Clone)]
pub struct CreatedCert {
    pub summary: CertSummary,
    pub der: Vec<u8>,
}

/// 產生自簽程式碼簽章憑證並寫出 .pfx。
pub fn create_self_signed(p: &NewCertParams) -> Result<CreatedCert, CoreError> {
    let cn = p.common_name.trim();
    if cn.is_empty() {
        return Err(CoreError::EmptyCommonName);
    }
    if p.password.chars().count() < MIN_PASSWORD_LEN {
        return Err(CoreError::PasswordTooShort);
    }
    if !(1..=10).contains(&p.validity_years) {
        return Err(CoreError::InvalidValidity);
    }
    if p.out_path.exists() && !p.overwrite {
        return Err(CoreError::OutputExists);
    }

    let internal = |m: String| CoreError::Win32 {
        hresult: 0x8000_4005,
        message: m,
    };

    // 1. RSA 金鑰（rcgen 的 ring 後端無法產生 RSA，改由 rsa crate 產生）
    use rsa::pkcs8::EncodePrivateKey;
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, p.key_bits.bits())
        .map_err(|e| internal(e.to_string()))?;
    let key_der = key.to_pkcs8_der().map_err(|e| internal(e.to_string()))?;
    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &key_der.as_bytes().into(),
        &rcgen::PKCS_RSA_SHA256,
    )
    .map_err(|e| internal(e.to_string()))?;

    // 2. 憑證內容
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    if let Some(org) = p
        .organization
        .as_deref()
        .map(str::trim)
        .filter(|o| !o.is_empty())
    {
        dn.push(rcgen::DnType::OrganizationName, org);
    }
    params.distinguished_name = dn;
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
    let now = time::OffsetDateTime::now_utc();
    // 往前推 5 分鐘，避免與其他電腦的時鐘誤差造成「尚未生效」
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::days(365 * p.validity_years as i64);
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| internal(e.to_string()))?;
    let cert_der = cert.der().to_vec();

    // 3. 包成 .pfx（p12-keystore 預設 PBES2 / AES-256 + HMAC-SHA256，Windows 可讀）
    let mut ks = p12_keystore::KeyStore::new();
    let local_key_id = <sha1::Sha1 as sha1::Digest>::digest(&cert_der).to_vec();
    let chain = p12_keystore::PrivateKeyChain::new(
        local_key_id,
        p12_keystore::PrivateKey::from_der(key_der.as_bytes())
            .map_err(|e| internal(e.to_string()))?,
        [p12_keystore::Certificate::from_der(&cert_der).map_err(|e| internal(e.to_string()))?],
    );
    ks.add_entry(cn, p12_keystore::KeyStoreEntry::PrivateKeyChain(chain));
    let pfx = ks
        .writer(&p.password)
        .write()
        .map_err(|e| internal(e.to_string()))?;
    std::fs::write(&p.out_path, pfx).map_err(|e| CoreError::from_io(&e))?;

    Ok(CreatedCert {
        summary: summarize_der(&cert_der)?,
        der: cert_der,
    })
}

// ---------------------------------------------------------------------------
// 載入憑證（Win32）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreLocation {
    CurrentUser,
    LocalMachine,
}

impl StoreLocation {
    fn flag(self) -> u32 {
        match self {
            StoreLocation::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
            StoreLocation::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
        }
    }
}

#[derive(Clone)]
pub enum CertSource {
    Pfx {
        path: PathBuf,
        password: Secret,
    },
    Store {
        thumbprint: String,
        location: StoreLocation,
    },
}

impl std::fmt::Debug for CertSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertSource::Pfx { path, password: _ } => f
                .debug_struct("Pfx")
                .field("path", &path)
                .field("password", &"***")
                .finish(),
            CertSource::Store {
                thumbprint,
                location,
            } => f
                .debug_struct("Store")
                .field("thumbprint", &thumbprint)
                .field("location", &location)
                .finish(),
        }
    }
}

/// 已載入、可用於簽章的憑證。持有 Win32 資源，Drop 時釋放。
///
/// 含原始指標，不可跨執行緒傳遞：請在要簽章的執行緒內呼叫 `load_cert`。
pub struct LoadedCert {
    store: HCERTSTORE,
    cert: *const CERT_CONTEXT,
    pub summary: CertSummary,
}

impl LoadedCert {
    pub(crate) fn store(&self) -> HCERTSTORE {
        self.store
    }
    pub(crate) fn context(&self) -> *const CERT_CONTEXT {
        self.cert
    }
}

impl Drop for LoadedCert {
    fn drop(&mut self) {
        // SAFETY: cert 與 store 皆由本結構獨占持有，且只在這裡釋放一次。
        unsafe {
            let _ = CertFreeCertificateContext(Some(self.cert));
            let _ = CertCloseStore(Some(self.store), 0);
        }
    }
}

/// 讀出 CERT_CONTEXT 內的 DER 位元組。
///
/// SAFETY: `ctx` 必須是有效且未釋放的 CERT_CONTEXT。
unsafe fn context_der<'a>(ctx: *const CERT_CONTEXT) -> &'a [u8] {
    unsafe { std::slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize) }
}

/// 憑證是否帶有可取得的私鑰（不跳出任何 UI）。
///
/// SAFETY: `ctx` 必須是有效且未釋放的 CERT_CONTEXT。
unsafe fn has_private_key(ctx: *const CERT_CONTEXT) -> bool {
    let mut handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
    // CACHE_FLAG：金鑰控制代碼由憑證內容快取管理，呼叫端不需釋放
    unsafe {
        CryptAcquireCertificatePrivateKey(
            ctx,
            CRYPT_ACQUIRE_CACHE_FLAG
                | CRYPT_ACQUIRE_SILENT_FLAG
                | CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
            None,
            &mut handle,
            None,
            None,
        )
        .is_ok()
    }
}

/// 憑證是否登記了私鑰（只看屬性，不存取金鑰；用於列出存放區，避免觸發智慧卡 PIN 視窗）。
///
/// SAFETY: `ctx` 必須是有效且未釋放的 CERT_CONTEXT。
unsafe fn has_key_prov_info(ctx: *const CERT_CONTEXT) -> bool {
    let mut size = 0u32;
    unsafe {
        CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, None, &mut size).is_ok()
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// 載入簽章憑證，並檢查私鑰、EKU、有效期間。
pub fn load_cert(src: &CertSource) -> Result<LoadedCert, CoreError> {
    let loaded = match src {
        CertSource::Pfx { path, password } => load_pfx(path, password)?,
        CertSource::Store {
            thumbprint,
            location,
        } => load_from_store(thumbprint, *location)?,
    };
    check_signing_usable(&loaded.summary)?;
    Ok(loaded)
}

fn load_pfx(path: &Path, password: &str) -> Result<LoadedCert, CoreError> {
    let data = std::fs::read(path).map_err(|e| CoreError::from_io(&e))?;
    let blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let pw = Zeroizing::new(wide(password));
    // SAFETY: blob 指向 data，在本函式內有效；pw 以 NUL 結尾。
    unsafe {
        if !PFXIsPFXBlob(&blob).as_bool() {
            return Err(CoreError::PfxInvalid);
        }
        // NO_PERSIST_KEY + ALWAYS_CNG_KSP：私鑰只存在記憶體，不留在使用者設定檔。
        // （只用 NO_PERSIST_KEY 時 SignerSignEx2 會回 NTE_BAD_TYPE，已實測）
        let store = PFXImportCertStore(
            &blob,
            PCWSTR(pw.as_ptr()),
            PKCS12_NO_PERSIST_KEY | PKCS12_ALWAYS_CNG_KSP,
        )
        .map_err(|e| CoreError::from_win(&e))?;

        let mut found: *const CERT_CONTEXT = std::ptr::null();
        let mut cur = CertEnumCertificatesInStore(store, None);
        while !cur.is_null() {
            if has_private_key(cur) {
                found = CertDuplicateCertificateContext(Some(cur));
                let _ = CertFreeCertificateContext(Some(cur)); // 結束列舉
                break;
            }
            cur = CertEnumCertificatesInStore(store, Some(cur));
        }
        if found.is_null() {
            let _ = CertCloseStore(Some(store), 0);
            return Err(CoreError::PfxNoSigningCert);
        }
        let summary = match summarize_der(context_der(found)) {
            Ok(s) => s,
            Err(e) => {
                let _ = CertFreeCertificateContext(Some(found));
                let _ = CertCloseStore(Some(store), 0);
                return Err(e);
            }
        };
        Ok(LoadedCert {
            store,
            cert: found,
            summary,
        })
    }
}

/// 解析指紋：允許空白與冒號、不分大小寫，必須是 40 個十六進位字元（SHA-1）。
pub fn parse_thumbprint(s: &str) -> Result<[u8; 20], CoreError> {
    let hex: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if hex.len() != 40 {
        return Err(CoreError::InvalidThumbprint);
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| CoreError::InvalidThumbprint)?;
    }
    Ok(out)
}

/// 開啟系統憑證存放區（例如 "MY"、"Root"）。
fn open_system_store(
    name: PCWSTR,
    location: StoreLocation,
    readonly: bool,
) -> Result<HCERTSTORE, CoreError> {
    let mut flags = location.flag() | CERT_STORE_OPEN_EXISTING_FLAG.0;
    if readonly {
        flags |= CERT_STORE_READONLY_FLAG.0;
    }
    // SAFETY: name 為靜態 NUL 結尾字串。
    unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            CERT_OPEN_STORE_FLAGS(flags),
            Some(name.as_ptr() as *const core::ffi::c_void),
        )
        .map_err(|e| CoreError::from_win(&e))
    }
}

fn load_from_store(thumbprint: &str, location: StoreLocation) -> Result<LoadedCert, CoreError> {
    let hash = parse_thumbprint(thumbprint)?;
    let store = open_system_store(w!("MY"), location, true)?;
    let blob = CRYPT_INTEGER_BLOB {
        cbData: 20,
        pbData: hash.as_ptr() as *mut u8,
    };
    // SAFETY: store 有效；blob 指向 hash，在本函式內有效。
    unsafe {
        let ctx = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SHA1_HASH,
            Some(&blob as *const _ as *const core::ffi::c_void),
            None,
        );
        if ctx.is_null() {
            let _ = CertCloseStore(Some(store), 0);
            return Err(CoreError::CertNotFound);
        }
        if !has_key_prov_info(ctx) {
            let _ = CertFreeCertificateContext(Some(ctx));
            let _ = CertCloseStore(Some(store), 0);
            return Err(CoreError::CertNoPrivateKey);
        }
        match summarize_der(context_der(ctx)) {
            Ok(summary) => Ok(LoadedCert {
                store,
                cert: ctx,
                summary,
            }),
            Err(e) => {
                let _ = CertFreeCertificateContext(Some(ctx));
                let _ = CertCloseStore(Some(store), 0);
                Err(e)
            }
        }
    }
}

/// 列出指定位置 MY 存放區中可用於程式碼簽章的憑證（有私鑰、EKU 允許、在有效期間內）。
pub fn list_store_signing_certs(location: StoreLocation) -> Result<Vec<CertSummary>, CoreError> {
    let store = open_system_store(w!("MY"), location, true)?;
    let mut out = Vec::new();
    // SAFETY: store 有效；列舉過程中 CertEnumCertificatesInStore 負責釋放前一個 context。
    unsafe {
        let mut cur = CertEnumCertificatesInStore(store, None);
        while !cur.is_null() {
            if has_key_prov_info(cur) {
                if let Ok(s) = summarize_der(context_der(cur)) {
                    if check_signing_usable(&s).is_ok() {
                        out.push(s);
                    }
                }
            }
            cur = CertEnumCertificatesInStore(store, Some(cur));
        }
        let _ = CertCloseStore(Some(store), 0);
    }
    out.sort_by(|a, b| a.subject_cn.cmp(&b.subject_cn));
    Ok(out)
}

/// 把公開憑證加入目前使用者的「受信任的根憑證」與「受信任的發行者」（測試用）。
///
/// 加入 Root 時 Windows 會跳出確認視窗；使用者拒絕時回傳 `UserCancelled`，
/// 且不會加入 TrustedPublisher。
pub fn install_trust(cert_der: &[u8]) -> Result<(), CoreError> {
    for name in [w!("Root"), w!("TrustedPublisher")] {
        let store = open_system_store(name, StoreLocation::CurrentUser, false)?;
        // SAFETY: store 有效；cert_der 在呼叫期間有效。
        let r = unsafe {
            CertAddEncodedCertificateToStore(
                Some(store),
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                cert_der,
                CERT_STORE_ADD_REPLACE_EXISTING,
                None,
            )
        };
        unsafe {
            let _ = CertCloseStore(Some(store), 0);
        }
        r.map_err(|e| CoreError::from_win(&e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(dir: &Path, name: &str) -> NewCertParams {
        NewCertParams {
            common_name: "Unit Test Signing".into(),
            organization: Some("Test Org".into()),
            validity_years: 1,
            key_bits: RsaBits::B2048,
            out_path: dir.join(name),
            password: Secret::new("correct horse".into()),
            overwrite: false,
        }
    }

    #[test]
    fn parses_thumbprints() {
        let t = format!("a1 B2:c3 {}", "d4".repeat(17));
        assert_eq!(parse_thumbprint(&t).unwrap()[..3], [0xA1, 0xB2, 0xC3]);
        assert_eq!(parse_thumbprint("zz"), Err(CoreError::InvalidThumbprint));
        assert_eq!(
            parse_thumbprint(&"G".repeat(40)),
            Err(CoreError::InvalidThumbprint)
        );
        assert_eq!(parse_thumbprint(&"ab".repeat(20)).unwrap(), [0xAB; 20]);
    }

    #[test]
    fn rsa_bits_roundtrip() {
        assert_eq!(RsaBits::from_bits(3072), Some(RsaBits::B3072));
        assert_eq!(RsaBits::from_bits(1024), None);
    }

    #[test]
    fn create_validates_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = params(dir.path(), "a.pfx");
        p.common_name = "  ".into();
        assert_eq!(
            create_self_signed(&p).unwrap_err(),
            CoreError::EmptyCommonName
        );

        let mut p = params(dir.path(), "a.pfx");
        p.password = Secret::new("short".into());
        assert_eq!(
            create_self_signed(&p).unwrap_err(),
            CoreError::PasswordTooShort
        );

        let mut p = params(dir.path(), "a.pfx");
        p.validity_years = 0;
        assert_eq!(
            create_self_signed(&p).unwrap_err(),
            CoreError::InvalidValidity
        );

        std::fs::write(dir.path().join("exists.pfx"), b"x").unwrap();
        let p = params(dir.path(), "exists.pfx");
        assert_eq!(create_self_signed(&p).unwrap_err(), CoreError::OutputExists);
    }

    #[test]
    fn created_pfx_loads_with_windows_and_is_usable() {
        let dir = tempfile::tempdir().unwrap();
        let p = params(dir.path(), "t.pfx");
        let created = create_self_signed(&p).unwrap();
        assert_eq!(created.summary.subject_cn, "Unit Test Signing");
        assert_eq!(created.summary.organization.as_deref(), Some("Test Org"));
        assert_eq!(created.summary.issuer_cn, "Unit Test Signing");
        assert!(created.summary.code_signing);
        assert_eq!(created.summary.sha1.len(), 40);

        let loaded = load_cert(&CertSource::Pfx {
            path: p.out_path.clone(),
            password: Secret::new("correct horse".into()),
        })
        .unwrap();
        assert_eq!(loaded.summary, created.summary);
    }

    #[test]
    fn wrong_password_and_invalid_file_are_distinguished() {
        let dir = tempfile::tempdir().unwrap();
        let p = params(dir.path(), "t.pfx");
        create_self_signed(&p).unwrap();
        let err = load_cert(&CertSource::Pfx {
            path: p.out_path.clone(),
            password: Secret::new("wrong password".into()),
        })
        .err()
        .unwrap();
        assert_eq!(err, CoreError::PfxWrongPassword);

        let junk = dir.path().join("junk.pfx");
        std::fs::write(&junk, b"not a pfx").unwrap();
        let err = load_cert(&CertSource::Pfx {
            path: junk,
            password: Secret::new("x".into()),
        })
        .err()
        .unwrap();
        assert_eq!(err, CoreError::PfxInvalid);

        let err = load_cert(&CertSource::Pfx {
            path: dir.path().join("missing.pfx"),
            password: Secret::new("x".into()),
        })
        .err()
        .unwrap();
        assert_eq!(err, CoreError::FileNotFound);
    }

    #[test]
    fn store_lookup_reports_not_found_and_listing_works() {
        let err = load_cert(&CertSource::Store {
            thumbprint: "00".repeat(20),
            location: StoreLocation::CurrentUser,
        })
        .err()
        .unwrap();
        assert_eq!(err, CoreError::CertNotFound);
        // 只確認可以列出且不會失敗；內容取決於這台電腦
        list_store_signing_certs(StoreLocation::CurrentUser).unwrap();
    }

    #[test]
    fn signing_usability_checks_expiry_and_eku() {
        let base = CertSummary {
            subject_cn: "x".into(),
            organization: None,
            issuer_cn: "x".into(),
            sha1: String::new(),
            sha256: String::new(),
            not_before: 0,
            not_after: i64::MAX,
            code_signing: true,
        };
        assert!(check_signing_usable(&base).is_ok());
        assert_eq!(
            check_signing_usable(&CertSummary {
                code_signing: false,
                ..base.clone()
            }),
            Err(CoreError::CertNotCodeSigning)
        );
        assert_eq!(
            check_signing_usable(&CertSummary {
                not_after: 1,
                ..base.clone()
            }),
            Err(CoreError::CertExpired)
        );
        assert_eq!(
            check_signing_usable(&CertSummary {
                not_before: i64::MAX,
                ..base
            }),
            Err(CoreError::CertNotYetValid)
        );
    }

    #[test]
    fn cert_source_debug_redacts_password() {
        let src_pfx = CertSource::Pfx {
            path: PathBuf::from("test.pfx"),
            password: Secret::new("hunter2-secret".into()),
        };
        let debug_str = format!("{src_pfx:?}");
        assert!(!debug_str.contains("hunter2-secret"));
        assert!(debug_str.contains("***"));

        let src_store = CertSource::Store {
            thumbprint: "00".repeat(20),
            location: StoreLocation::CurrentUser,
        };
        let debug_str = format!("{src_store:?}");
        assert!(debug_str.contains("0000"));
    }
}
