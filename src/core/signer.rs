//! 單檔 Authenticode 簽章：複製成暫存檔 → SignerSignEx2 → 取代原檔。

use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Cryptography::*;

use super::batch::is_supported;
use super::cert::LoadedCert;
use super::CoreError;

/// 預設時間戳記伺服器（RFC 3161）。
pub const DEFAULT_TIMESTAMP_URL: &str = "http://timestamp.digicert.com";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignOptions {
    /// RFC 3161 時間戳記伺服器；None 表示不加時間戳記
    pub timestamp_url: Option<String>,
}

/// 暫存檔：Drop 時若尚未交出就刪除，確保失敗時不留垃圾。
struct TempFile {
    path: PathBuf,
    armed: bool,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// 暫存檔路徑：同資料夾、隱藏式命名，並保留原副檔名（SIP 依副檔名判斷格式）。
fn temp_path_for(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.code-signer-tmp.{ext}"))
}

fn wide_path(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// 對單一檔案簽章（SHA-256）。任何失敗都不會改動原檔。
pub fn sign_file(path: &Path, cert: &LoadedCert, opts: &SignOptions) -> Result<(), CoreError> {
    if !is_supported(path) {
        return Err(CoreError::UnsupportedFileType);
    }
    if !path.is_file() {
        return Err(CoreError::FileNotFound);
    }

    let mut tmp = TempFile {
        path: temp_path_for(path),
        armed: true,
    };
    std::fs::copy(path, &tmp.path).map_err(|e| CoreError::from_io(&e))?;
    sign_in_place(&tmp.path, cert, opts)?;
    // std::fs::rename 在 Windows 上即 MoveFileExW(MOVEFILE_REPLACE_EXISTING)
    std::fs::rename(&tmp.path, path).map_err(|e| CoreError::from_io(&e))?;
    tmp.armed = false;
    Ok(())
}

/// 直接對 `path` 呼叫 SignerSignEx2。
fn sign_in_place(path: &Path, cert: &LoadedCert, opts: &SignOptions) -> Result<(), CoreError> {
    let wpath = wide_path(path);
    let ts_url: Option<Vec<u16>> = opts
        .timestamp_url
        .as_deref()
        .map(|u| u.encode_utf16().chain(Some(0)).collect());

    let mut index = 0u32;
    let mut file_info = SIGNER_FILE_INFO {
        cbSize: size_of::<SIGNER_FILE_INFO>() as u32,
        pwszFileName: PCWSTR(wpath.as_ptr()),
        hFile: HANDLE::default(),
    };
    let mut subject = SIGNER_SUBJECT_INFO {
        cbSize: size_of::<SIGNER_SUBJECT_INFO>() as u32,
        pdwIndex: &mut index,
        dwSubjectChoice: SIGNER_SUBJECT_FILE,
        ..Default::default()
    };
    subject.Anonymous.pSignerFileInfo = &mut file_info;

    let mut store_info = SIGNER_CERT_STORE_INFO {
        cbSize: size_of::<SIGNER_CERT_STORE_INFO>() as u32,
        pSigningCert: cert.context(),
        dwCertPolicy: SIGNER_CERT_POLICY_CHAIN,
        hCertStore: cert.store(),
    };
    let mut signer_cert = SIGNER_CERT {
        cbSize: size_of::<SIGNER_CERT>() as u32,
        dwCertChoice: SIGNER_CERT_STORE,
        ..Default::default()
    };
    signer_cert.Anonymous.pCertStoreInfo = &mut store_info;

    let mut authcode = SIGNER_ATTR_AUTHCODE {
        cbSize: size_of::<SIGNER_ATTR_AUTHCODE>() as u32,
        ..Default::default()
    };
    let mut sig_info = SIGNER_SIGNATURE_INFO {
        cbSize: size_of::<SIGNER_SIGNATURE_INFO>() as u32,
        algidHash: CALG_SHA_256,
        dwAttrChoice: SIGNER_AUTHCODE_ATTR,
        ..Default::default()
    };
    sig_info.Anonymous.pAttrAuthcode = &mut authcode;

    let mut ctx: *mut SIGNER_CONTEXT = std::ptr::null_mut();
    // SAFETY: 所有結構與字串緩衝區都活到呼叫結束；cert 的 context/store 由 LoadedCert 持有。
    let result = unsafe {
        SignerSignEx2(
            SIGNER_SIGN_FLAGS(0),
            &subject,
            &signer_cert,
            &sig_info,
            None,
            ts_url.as_ref().map(|_| SIGNER_TIMESTAMP_RFC3161),
            if ts_url.is_some() {
                szOID_NIST_sha256
            } else {
                PCSTR::null()
            },
            ts_url
                .as_ref()
                .map(|u| PCWSTR(u.as_ptr()))
                .unwrap_or(PCWSTR::null()),
            None,
            None,
            &mut ctx,
            None,
            None,
        )
    };
    if !ctx.is_null() {
        // SAFETY: ctx 由 SignerSignEx2 配置，只釋放一次。
        unsafe {
            let _ = SignerFreeSignerContext(ctx);
        }
    }
    result.map_err(|e| CoreError::from_win(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_path_keeps_extension_and_folder() {
        let p = Path::new(r"C:\build\app.exe");
        assert_eq!(
            temp_path_for(p),
            PathBuf::from(r"C:\build\.app.exe.code-signer-tmp.exe")
        );
        let p = Path::new(r"D:\s\tool.ps1");
        assert_eq!(
            temp_path_for(p),
            PathBuf::from(r"D:\s\.tool.ps1.code-signer-tmp.ps1")
        );
    }
}
