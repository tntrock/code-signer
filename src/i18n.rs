//! 介面語言：繁體中文 / English。
//!
//! 每個介面字串都是 `Strings` 的欄位，`ZH_TW` 與 `EN` 各寫一份；
//! 少寫任何一個欄位都會編譯失敗，不會在執行時缺字。

use crate::core::verify::VerifyStatus;
use crate::core::CoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    ZhTw,
    En,
}

impl Lang {
    pub const ALL: [Lang; 2] = [Lang::ZhTw, Lang::En];

    /// 設定檔與 `--lang` 使用的代碼。
    pub fn code(self) -> &'static str {
        match self {
            Lang::ZhTw => "zh-TW",
            Lang::En => "en",
        }
    }

    /// 語言選單顯示的名稱（永遠用該語言本身書寫）。
    pub fn native_name(self) -> &'static str {
        match self {
            Lang::ZhTw => "繁體中文",
            Lang::En => "English",
        }
    }

    /// 解析語言代碼（不分大小寫；`zh`、`zh-tw`、`zh_TW` 皆視為繁中）。
    pub fn parse(s: &str) -> Option<Lang> {
        let s = s.trim().to_ascii_lowercase().replace('_', "-");
        match s.as_str() {
            "zh" | "zh-tw" | "zh-hant" | "zh-hk" | "zh-mo" => Some(Lang::ZhTw),
            "en" | "en-us" | "en-gb" => Some(Lang::En),
            _ => None,
        }
    }

    /// 由 Windows LANGID 判斷：zh-TW(0x0404)、zh-HK(0x0C04)、zh-MO(0x1404) → 繁中，其餘英文。
    pub fn from_langid(langid: u16) -> Lang {
        match langid {
            0x0404 | 0x0C04 | 0x1404 => Lang::ZhTw,
            _ => Lang::En,
        }
    }

    /// 依 Windows 顯示語言決定預設語言。
    pub fn detect() -> Lang {
        // SAFETY: 無參數、無副作用的查詢。
        let id = unsafe { windows::Win32::Globalization::GetUserDefaultUILanguage() };
        Lang::from_langid(id)
    }

    pub fn strings(self) -> &'static Strings {
        match self {
            Lang::ZhTw => &ZH_TW,
            Lang::En => &EN,
        }
    }
}

pub struct Strings {
    // 此份字串所屬的語言
    pub lang: Lang,
    // ---- 共用 / 視窗 ----
    pub app_title: &'static str,
    pub tab_sign: &'static str,
    pub tab_verify: &'static str,
    pub tab_cert: &'static str,
    pub add_files: &'static str,
    pub add_folder: &'static str,
    pub clear: &'static str,
    pub drop_hint: &'static str,
    pub file_filter_name: &'static str,
    pub col_file: &'static str,
    pub col_status: &'static str,
    pub col_signer: &'static str,
    pub col_timestamp: &'static str,
    pub st_pending: &'static str,
    pub st_running: &'static str,
    pub st_signed: &'static str,
    pub browse: &'static str,
    pub password: &'static str,
    // ---- 簽章分頁 ----
    pub cert_source: &'static str,
    pub cert_pfx: &'static str,
    pub cert_store: &'static str,
    pub refresh: &'static str,
    pub no_store_certs: &'static str,
    pub timestamp: &'static str,
    pub start_sign: &'static str,
    pub cancel: &'static str,
    pub need_files: &'static str,
    pub need_cert: &'static str,
    // ---- 驗證分頁 ----
    pub details: &'static str,
    pub sha1_thumbprint: &'static str,
    pub sha256_thumbprint: &'static str,
    pub issuer: &'static str,
    pub valid_from: &'static str,
    pub valid_to: &'static str,
    pub chain: &'static str,
    pub no_timestamp: &'static str,
    // ---- 產生憑證分頁 ----
    pub cn: &'static str,
    pub org_optional: &'static str,
    pub validity: &'static str,
    pub key_size: &'static str,
    pub out_path: &'static str,
    pub confirm_password: &'static str,
    pub install_trust: &'static str,
    pub install_trust_note: &'static str,
    pub generate: &'static str,
    pub generating: &'static str,
    pub password_mismatch: &'static str,
    pub overwrite_confirm: &'static str,
    pub yes: &'static str,
    pub no: &'static str,
    pub cert_created: &'static str,
    pub trust_installed: &'static str,
    pub trust_failed: &'static str,
    // ---- 驗證狀態 ----
    pub vs_valid: &'static str,
    pub vs_unsigned: &'static str,
    pub vs_tampered: &'static str,
    pub vs_untrusted_root: &'static str,
    pub vs_expired: &'static str,
    pub vs_distrusted: &'static str,
    pub vs_other: &'static str,
    // ---- 錯誤 ----
    pub err_pfx_wrong_password: &'static str,
    pub err_pfx_invalid: &'static str,
    pub err_pfx_no_signing_cert: &'static str,
    pub err_invalid_thumbprint: &'static str,
    pub err_cert_not_found: &'static str,
    pub err_cert_no_private_key: &'static str,
    pub err_cert_not_code_signing: &'static str,
    pub err_cert_expired: &'static str,
    pub err_cert_not_yet_valid: &'static str,
    pub err_file_not_found: &'static str,
    pub err_file_in_use: &'static str,
    pub err_access_denied: &'static str,
    pub err_unsupported_file_type: &'static str,
    pub err_timestamp_failed: &'static str,
    pub err_user_cancelled: &'static str,
    pub err_output_exists: &'static str,
    pub err_empty_common_name: &'static str,
    pub err_password_too_short: &'static str,
    pub err_invalid_validity: &'static str,
    pub err_win32: &'static str,
    pub err_env_missing: &'static str,
    pub err_no_files: &'static str,
    // ---- CLI ----
    pub cli_about: &'static str,
    pub cli_sign_about: &'static str,
    pub cli_verify_about: &'static str,
    pub cli_new_cert_about: &'static str,
    pub h_paths: &'static str,
    pub h_pfx: &'static str,
    pub h_thumbprint: &'static str,
    pub h_store: &'static str,
    pub h_password_env: &'static str,
    pub h_timestamp: &'static str,
    pub h_recursive: &'static str,
    pub h_json: &'static str,
    pub h_lang: &'static str,
    pub h_cn: &'static str,
    pub h_org: &'static str,
    pub h_years: &'static str,
    pub h_key_size: &'static str,
    pub h_out: &'static str,
    pub h_install_trust: &'static str,
    pub h_force: &'static str,
    pub prompt_password: &'static str,
    pub prompt_new_password: &'static str,
    pub prompt_confirm_password: &'static str,
    pub cli_trust_prompt_note: &'static str,
}

impl Strings {
    /// 核心錯誤 → 使用者可讀訊息。
    pub fn error(&self, e: &CoreError) -> String {
        match e {
            CoreError::PfxWrongPassword => self.err_pfx_wrong_password.into(),
            CoreError::PfxInvalid => self.err_pfx_invalid.into(),
            CoreError::PfxNoSigningCert => self.err_pfx_no_signing_cert.into(),
            CoreError::InvalidThumbprint => self.err_invalid_thumbprint.into(),
            CoreError::CertNotFound => self.err_cert_not_found.into(),
            CoreError::CertNoPrivateKey => self.err_cert_no_private_key.into(),
            CoreError::CertNotCodeSigning => self.err_cert_not_code_signing.into(),
            CoreError::CertExpired => self.err_cert_expired.into(),
            CoreError::CertNotYetValid => self.err_cert_not_yet_valid.into(),
            CoreError::FileNotFound => self.err_file_not_found.into(),
            CoreError::FileInUse => self.err_file_in_use.into(),
            CoreError::AccessDenied => self.err_access_denied.into(),
            CoreError::UnsupportedFileType => self.err_unsupported_file_type.into(),
            CoreError::TimestampFailed(hr) => format!("{} (0x{hr:08X})", self.err_timestamp_failed),
            CoreError::UserCancelled => self.err_user_cancelled.into(),
            CoreError::OutputExists => self.err_output_exists.into(),
            CoreError::EmptyCommonName => self.err_empty_common_name.into(),
            CoreError::PasswordTooShort => self.err_password_too_short.into(),
            CoreError::InvalidValidity => self.err_invalid_validity.into(),
            CoreError::Win32 { hresult, message } if message.is_empty() => {
                format!("{} 0x{hresult:08X}", self.err_win32)
            }
            CoreError::Win32 { hresult, message } => {
                format!("{} 0x{hresult:08X}: {message}", self.err_win32)
            }
        }
    }

    /// 驗證狀態 → 使用者可讀訊息。
    pub fn status(&self, s: &VerifyStatus) -> String {
        match s {
            VerifyStatus::Valid => self.vs_valid.into(),
            VerifyStatus::Unsigned => self.vs_unsigned.into(),
            VerifyStatus::Tampered => self.vs_tampered.into(),
            VerifyStatus::UntrustedRoot => self.vs_untrusted_root.into(),
            VerifyStatus::Expired => self.vs_expired.into(),
            VerifyStatus::Distrusted => self.vs_distrusted.into(),
            VerifyStatus::Other(code) => format!("{} (0x{code:08X})", self.vs_other),
        }
    }

    pub fn progress(&self, done: usize, total: usize) -> String {
        format!("{done} / {total}")
    }

    pub fn summary(&self, total: usize, ok: usize, failed: usize) -> String {
        match self.lang {
            Lang::ZhTw => format!("共 {total} 個檔案：成功 {ok}、失敗 {failed}"),
            Lang::En => format!("{total} file(s): {ok} succeeded, {failed} failed"),
        }
    }

    pub fn years(&self, n: u32) -> String {
        match self.lang {
            Lang::ZhTw => format!("{n} 年"),
            Lang::En => {
                if n == 1 {
                    "1 year".into()
                } else {
                    format!("{n} years")
                }
            }
        }
    }
}

/// Unix 秒 → `YYYY-MM-DD HH:MM:SS UTC`。
pub fn format_time(unix: i64) -> String {
    let fmt =
        time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second] UTC");
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| t.format(&fmt).ok())
        .unwrap_or_else(|| unix.to_string())
}

pub static ZH_TW: Strings = Strings {
    lang: Lang::ZhTw,
    app_title: "code-signer 程式碼簽章工具",
    tab_sign: "簽章",
    tab_verify: "驗證",
    tab_cert: "產生憑證",
    add_files: "加入檔案",
    add_folder: "加入資料夾",
    clear: "清除",
    drop_hint: "把檔案或資料夾拖放到這裡",
    file_filter_name: "可簽章的檔案",
    col_file: "檔案",
    col_status: "狀態",
    col_signer: "簽章者",
    col_timestamp: "時間戳記",
    st_pending: "等待中",
    st_running: "處理中…",
    st_signed: "已簽章",
    browse: "瀏覽…",
    password: "密碼",
    cert_source: "憑證",
    cert_pfx: ".pfx 檔",
    cert_store: "憑證存放區",
    refresh: "重新整理",
    no_store_certs: "（找不到可用於程式碼簽章的憑證）",
    timestamp: "時間戳記",
    start_sign: "開始簽章",
    cancel: "取消",
    need_files: "請先加入要簽章的檔案",
    need_cert: "請先選擇憑證",
    details: "詳細資訊",
    sha1_thumbprint: "SHA-1 指紋",
    sha256_thumbprint: "SHA-256 指紋",
    issuer: "簽發者",
    valid_from: "生效日",
    valid_to: "到期日",
    chain: "憑證鏈",
    no_timestamp: "（無）",
    cn: "名稱（CN）",
    org_optional: "組織（O，選填）",
    validity: "有效期限",
    key_size: "金鑰長度",
    out_path: "輸出 .pfx",
    confirm_password: "確認密碼",
    install_trust: "同時匯入本機信任清單（僅目前使用者，測試用）",
    install_trust_note: "Windows 會跳出安全性確認視窗，請選「是」",
    generate: "產生",
    generating: "產生中…",
    password_mismatch: "兩次輸入的密碼不一致",
    overwrite_confirm: "檔案已存在，要覆寫嗎？",
    yes: "是",
    no: "否",
    cert_created: "已產生憑證",
    trust_installed: "已加入目前使用者的信任清單",
    trust_failed: "憑證已產生，但加入信任清單失敗",
    vs_valid: "簽章有效",
    vs_unsigned: "未簽章",
    vs_tampered: "檔案已被竄改",
    vs_untrusted_root: "根憑證不受信任",
    vs_expired: "憑證已過期",
    vs_distrusted: "憑證已被明確列為不信任",
    vs_other: "簽章無效",
    err_pfx_wrong_password: ".pfx 密碼錯誤",
    err_pfx_invalid: "不是有效的 .pfx（PKCS#12）檔案",
    err_pfx_no_signing_cert: ".pfx 中沒有含私鑰的憑證",
    err_invalid_thumbprint: "指紋格式錯誤（需為 40 個十六進位字元）",
    err_cert_not_found: "憑證存放區中找不到此指紋的憑證",
    err_cert_no_private_key: "憑證沒有私鑰，無法簽章",
    err_cert_not_code_signing: "此憑證不能用於程式碼簽章",
    err_cert_expired: "憑證已過期",
    err_cert_not_yet_valid: "憑證尚未生效",
    err_file_not_found: "找不到檔案",
    err_file_in_use: "檔案正被其他程式使用",
    err_access_denied: "存取被拒（檔案可能正在執行或為唯讀）",
    err_unsupported_file_type: "不支援此檔案類型",
    err_timestamp_failed: "無法連線到時間戳記伺服器",
    err_user_cancelled: "使用者已取消",
    err_output_exists: "輸出檔已存在",
    err_empty_common_name: "請輸入名稱（CN）",
    err_password_too_short: "密碼至少需要 8 個字元",
    err_invalid_validity: "有效期限需介於 1 到 10 年",
    err_win32: "Windows 錯誤",
    err_env_missing: "找不到環境變數",
    err_no_files: "沒有找到可處理的檔案",
    cli_about: "Windows Authenticode 程式碼簽章工具。不帶參數執行會開啟圖形介面。",
    cli_sign_about: "對檔案進行 Authenticode 簽章",
    cli_verify_about: "驗證檔案的 Authenticode 簽章",
    cli_new_cert_about: "產生自簽程式碼簽章憑證（.pfx）",
    h_paths: "檔案或資料夾",
    h_pfx: "使用 .pfx 檔簽章",
    h_thumbprint: "使用 Windows 憑證存放區中的憑證（SHA-1 指紋）",
    h_store: "搭配 --thumbprint 的存放區位置",
    h_password_env: "從此環境變數讀取密碼（未指定時會提示輸入）",
    h_timestamp:
        "加上時間戳記；自訂伺服器請用 --timestamp=URL，否則預設使用 http://timestamp.digicert.com",
    h_recursive: "資料夾遞迴處理子資料夾",
    h_json: "以 JSON 格式輸出結果",
    h_lang: "介面語言（zh-TW 或 en）",
    h_cn: "憑證名稱（CN）",
    h_org: "組織名稱（O）",
    h_years: "有效年限（1–10）",
    h_key_size: "RSA 金鑰長度",
    h_out: "輸出的 .pfx 路徑",
    h_install_trust: "同時加入目前使用者的信任清單（測試用）",
    h_force: "輸出檔已存在時覆寫",
    prompt_password: ".pfx 密碼：",
    prompt_new_password: "設定 .pfx 密碼（至少 8 字元）：",
    prompt_confirm_password: "再次輸入密碼：",
    cli_trust_prompt_note: "Windows 將跳出安全性確認視窗，請選「是」以加入信任清單。",
};

pub static EN: Strings = Strings {
    lang: Lang::En,
    app_title: "code-signer",
    tab_sign: "Sign",
    tab_verify: "Verify",
    tab_cert: "New certificate",
    add_files: "Add files",
    add_folder: "Add folder",
    clear: "Clear",
    drop_hint: "Drop files or folders here",
    file_filter_name: "Signable files",
    col_file: "File",
    col_status: "Status",
    col_signer: "Signer",
    col_timestamp: "Timestamp",
    st_pending: "Pending",
    st_running: "Working…",
    st_signed: "Signed",
    browse: "Browse…",
    password: "Password",
    cert_source: "Certificate",
    cert_pfx: ".pfx file",
    cert_store: "Certificate store",
    refresh: "Refresh",
    no_store_certs: "(no code signing certificates found)",
    timestamp: "Timestamp",
    start_sign: "Sign",
    cancel: "Cancel",
    need_files: "Add files to sign first",
    need_cert: "Choose a certificate first",
    details: "Details",
    sha1_thumbprint: "SHA-1 thumbprint",
    sha256_thumbprint: "SHA-256 thumbprint",
    issuer: "Issuer",
    valid_from: "Valid from",
    valid_to: "Valid to",
    chain: "Certificate chain",
    no_timestamp: "(none)",
    cn: "Name (CN)",
    org_optional: "Organization (O, optional)",
    validity: "Validity",
    key_size: "Key size",
    out_path: "Output .pfx",
    confirm_password: "Confirm password",
    install_trust: "Also trust it on this PC (current user only, for testing)",
    install_trust_note: "Windows will show a security prompt; choose Yes",
    generate: "Generate",
    generating: "Generating…",
    password_mismatch: "Passwords do not match",
    overwrite_confirm: "The file already exists. Overwrite it?",
    yes: "Yes",
    no: "No",
    cert_created: "Certificate created",
    trust_installed: "Added to the current user's trusted certificates",
    trust_failed: "Certificate created, but adding it to the trust list failed",
    vs_valid: "Valid signature",
    vs_unsigned: "Not signed",
    vs_tampered: "File has been tampered with",
    vs_untrusted_root: "Root certificate is not trusted",
    vs_expired: "Certificate expired",
    vs_distrusted: "Certificate is explicitly distrusted",
    vs_other: "Invalid signature",
    err_pfx_wrong_password: "Wrong .pfx password",
    err_pfx_invalid: "Not a valid .pfx (PKCS#12) file",
    err_pfx_no_signing_cert: "The .pfx has no certificate with a private key",
    err_invalid_thumbprint: "Invalid thumbprint (expected 40 hex characters)",
    err_cert_not_found: "No certificate with this thumbprint in the store",
    err_cert_no_private_key: "The certificate has no private key",
    err_cert_not_code_signing: "This certificate cannot be used for code signing",
    err_cert_expired: "Certificate expired",
    err_cert_not_yet_valid: "Certificate is not yet valid",
    err_file_not_found: "File not found",
    err_file_in_use: "File is in use by another program",
    err_access_denied: "Access denied (the file may be running or read-only)",
    err_unsupported_file_type: "Unsupported file type",
    err_timestamp_failed: "Could not reach the timestamp server",
    err_user_cancelled: "Cancelled by user",
    err_output_exists: "Output file already exists",
    err_empty_common_name: "Enter a name (CN)",
    err_password_too_short: "Password must be at least 8 characters",
    err_invalid_validity: "Validity must be between 1 and 10 years",
    err_win32: "Windows error",
    err_env_missing: "Environment variable not found",
    err_no_files: "No files to process",
    cli_about: "Windows Authenticode code signing tool. Run without arguments to open the GUI.",
    cli_sign_about: "Sign files with Authenticode",
    cli_verify_about: "Verify Authenticode signatures",
    cli_new_cert_about: "Create a self-signed code signing certificate (.pfx)",
    h_paths: "Files or folders",
    h_pfx: "Sign with a .pfx file",
    h_thumbprint: "Sign with a certificate from the Windows store (SHA-1 thumbprint)",
    h_store: "Store location for --thumbprint",
    h_password_env: "Read the password from this environment variable (prompts if omitted)",
    h_timestamp: "Add a timestamp; use --timestamp=URL for a custom server, otherwise defaults to http://timestamp.digicert.com",
    h_recursive: "Include subfolders",
    h_json: "Print results as JSON",
    h_lang: "Interface language (zh-TW or en)",
    h_cn: "Certificate name (CN)",
    h_org: "Organization (O)",
    h_years: "Validity in years (1-10)",
    h_key_size: "RSA key size",
    h_out: "Output .pfx path",
    h_install_trust: "Also add it to the current user's trust list (for testing)",
    h_force: "Overwrite the output file if it exists",
    prompt_password: ".pfx password: ",
    prompt_new_password: "New .pfx password (min. 8 characters): ",
    prompt_confirm_password: "Confirm password: ",
    cli_trust_prompt_note:
        "Windows will show a security prompt; choose Yes to trust the certificate.",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_language_codes() {
        assert_eq!(Lang::parse("zh-TW"), Some(Lang::ZhTw));
        assert_eq!(Lang::parse("zh_tw"), Some(Lang::ZhTw));
        assert_eq!(Lang::parse("EN"), Some(Lang::En));
        assert_eq!(Lang::parse("fr"), None);
        for l in Lang::ALL {
            assert_eq!(Lang::parse(l.code()), Some(l));
        }
    }

    #[test]
    fn maps_langids() {
        assert_eq!(Lang::from_langid(0x0404), Lang::ZhTw);
        assert_eq!(Lang::from_langid(0x0C04), Lang::ZhTw);
        assert_eq!(Lang::from_langid(0x0804), Lang::En); // 簡中 → 英文
        assert_eq!(Lang::from_langid(0x0409), Lang::En);
    }

    #[test]
    fn translates_errors_and_statuses_in_both_languages() {
        let zh = Lang::ZhTw.strings();
        let en = Lang::En.strings();
        assert_eq!(zh.error(&CoreError::PfxWrongPassword), ".pfx 密碼錯誤");
        assert_eq!(
            en.error(&CoreError::PfxWrongPassword),
            "Wrong .pfx password"
        );
        assert_eq!(
            en.error(&CoreError::Win32 {
                hresult: 0x8009_0006,
                message: "Bad signature.".into()
            }),
            "Windows error 0x80090006: Bad signature."
        );
        assert!(zh
            .error(&CoreError::TimestampFailed(0x8007_2EFD))
            .contains("0x80072EFD"));
        assert_eq!(zh.status(&VerifyStatus::Tampered), "檔案已被竄改");
        assert_eq!(
            en.status(&VerifyStatus::Other(5)),
            "Invalid signature (0x00000005)"
        );
    }

    #[test]
    fn formats_summary_years_and_time() {
        assert_eq!(
            Lang::ZhTw.strings().summary(3, 2, 1),
            "共 3 個檔案：成功 2、失敗 1"
        );
        assert_eq!(
            Lang::En.strings().summary(3, 2, 1),
            "3 file(s): 2 succeeded, 1 failed"
        );
        assert_eq!(Lang::En.strings().years(1), "1 year");
        assert_eq!(Lang::ZhTw.strings().years(5), "5 年");
        assert_eq!(format_time(946_684_800), "2000-01-01 00:00:00 UTC");
    }

    #[test]
    fn strings_know_their_language() {
        assert_eq!(Lang::ZhTw.strings().lang, Lang::ZhTw);
        assert_eq!(Lang::En.strings().lang, Lang::En);
    }
}
