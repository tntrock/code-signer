//! 單檔簽章驗證：WinVerifyTrust + 讀出簽章者、憑證鏈與時間戳記。

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use serde::Serialize;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{FILETIME, HWND};
use windows::Win32::Security::WinTrust::*;

use super::batch::is_supported;
use super::cert::{summarize_der, CertSummary};
use super::CoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyStatus {
    Valid,
    Unsigned,
    Tampered,
    UntrustedRoot,
    Expired,
    Distrusted,
    Other(u32),
}

impl VerifyStatus {
    /// WinVerifyTrust 回傳值 → 狀態。
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => VerifyStatus::Valid,
            0x800B_0100 | 0x800B_0003 => VerifyStatus::Unsigned, // NOSIGNATURE, SUBJECT_FORM_UNKNOWN
            0x8009_6010 => VerifyStatus::Tampered,               // TRUST_E_BAD_DIGEST
            0x800B_0109 | 0x800B_010A => VerifyStatus::UntrustedRoot, // UNTRUSTEDROOT, CHAINING
            0x800B_0101 => VerifyStatus::Expired,                // CERT_E_EXPIRED
            0x800B_0111 => VerifyStatus::Distrusted,             // TRUST_E_EXPLICIT_DISTRUST
            other => VerifyStatus::Other(other),
        }
    }

    /// 穩定的英文代碼（--json 用）。
    pub fn code(&self) -> &'static str {
        match self {
            VerifyStatus::Valid => "valid",
            VerifyStatus::Unsigned => "unsigned",
            VerifyStatus::Tampered => "tampered",
            VerifyStatus::UntrustedRoot => "untrusted_root",
            VerifyStatus::Expired => "expired",
            VerifyStatus::Distrusted => "distrusted",
            VerifyStatus::Other(_) => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyReport {
    #[serde(skip)]
    pub status: VerifyStatus,
    pub signer: Option<CertSummary>,
    /// 時間戳記時間（Unix 秒）；沒有時間戳記為 None
    pub timestamp: Option<i64>,
    /// 憑證鏈（簽章者在前、根憑證在後）
    pub chain: Vec<CertSummary>,
}

fn filetime_to_unix(ft: FILETIME) -> i64 {
    let ticks = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
    (ticks as i64 - 116_444_736_000_000_000) / 10_000_000
}

/// 驗證單一檔案。檔案不存在或格式不支援時回傳錯誤；其餘結果都以 `VerifyReport` 表示。
pub fn verify_file(path: &Path) -> Result<VerifyReport, CoreError> {
    if !is_supported(path) {
        return Err(CoreError::UnsupportedFileType);
    }
    if !path.is_file() {
        return Err(CoreError::FileNotFound);
    }
    let wpath: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wpath.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        // 不做線上撤銷檢查，避免離線時卡住
        dwProvFlags: WTD_REVOCATION_CHECK_NONE,
        ..Default::default()
    };
    data.Anonymous.pFile = &mut file_info;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // INVALID_HANDLE_VALUE：不顯示任何 UI
    let no_ui = HWND(-1isize as *mut c_void);

    // SAFETY: data/file_info/wpath 在兩次呼叫期間都有效；狀態資料在 CLOSE 時釋放。
    unsafe {
        let code = WinVerifyTrust(no_ui, &mut action, &mut data as *mut _ as *mut c_void) as u32;
        let mut report = VerifyReport {
            status: VerifyStatus::from_code(code),
            signer: None,
            timestamp: None,
            chain: Vec::new(),
        };
        read_signer_details(data.hWVTStateData, &mut report);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(no_ui, &mut action, &mut data as *mut _ as *mut c_void);
        Ok(report)
    }
}

/// 從 WinVerifyTrust 狀態資料讀出簽章者、憑證鏈、時間戳記。
///
/// SAFETY: `state` 必須是 WTD_STATEACTION_VERIFY 後、CLOSE 前的狀態控制代碼。
unsafe fn read_signer_details(
    state: windows::Win32::Foundation::HANDLE,
    report: &mut VerifyReport,
) {
    unsafe {
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if sgnr.is_null() {
            return;
        }
        for i in 0..(*sgnr).csCertChain {
            let pc = WTHelperGetProvCertFromChain(sgnr, i);
            if pc.is_null() || (*pc).pCert.is_null() {
                continue;
            }
            let ctx = (*pc).pCert;
            let der =
                std::slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize);
            if let Ok(s) = summarize_der(der) {
                report.chain.push(s);
            }
        }
        report.signer = report.chain.first().cloned();
        if (*sgnr).csCounterSigners > 0 && !(*sgnr).pasCounterSigners.is_null() {
            let ts = &*(*sgnr).pasCounterSigners;
            report.timestamp = Some(filetime_to_unix(ts.sftVerifyAsOf));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_trust_codes() {
        assert_eq!(VerifyStatus::from_code(0), VerifyStatus::Valid);
        assert_eq!(VerifyStatus::from_code(0x800B_0100), VerifyStatus::Unsigned);
        assert_eq!(VerifyStatus::from_code(0x8009_6010), VerifyStatus::Tampered);
        assert_eq!(
            VerifyStatus::from_code(0x800B_0109),
            VerifyStatus::UntrustedRoot
        );
        assert_eq!(VerifyStatus::from_code(0x800B_0101), VerifyStatus::Expired);
        assert_eq!(
            VerifyStatus::from_code(0x800B_0111),
            VerifyStatus::Distrusted
        );
        assert_eq!(VerifyStatus::from_code(0x1234), VerifyStatus::Other(0x1234));
        assert_eq!(VerifyStatus::UntrustedRoot.code(), "untrusted_root");
    }

    #[test]
    fn converts_filetime() {
        // 2000-01-01T00:00:00Z = 946684800
        let ticks: u64 = (946_684_800 + 11_644_473_600) * 10_000_000;
        let ft = FILETIME {
            dwLowDateTime: ticks as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };
        assert_eq!(filetime_to_unix(ft), 946_684_800);
    }

    #[test]
    fn rejects_missing_and_unsupported() {
        assert_eq!(
            verify_file(Path::new("no-such-file.exe")),
            Err(CoreError::FileNotFound)
        );
        assert_eq!(
            verify_file(Path::new("readme.txt")),
            Err(CoreError::UnsupportedFileType)
        );
    }
}
