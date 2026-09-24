//! 核心錯誤類型，以及 Windows HRESULT / I/O 錯誤到 `CoreError` 的對應。

/// 核心層的所有錯誤。只描述「發生了什麼」，轉成使用者可讀的文字由 `i18n` 負責。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    #[error("wrong .pfx password")]
    PfxWrongPassword,
    #[error("not a valid PKCS#12 file")]
    PfxInvalid,
    #[error("no certificate with a private key in .pfx")]
    PfxNoSigningCert,
    #[error("invalid thumbprint")]
    InvalidThumbprint,
    #[error("certificate not found in store")]
    CertNotFound,
    #[error("certificate has no private key")]
    CertNoPrivateKey,
    #[error("certificate is not valid for code signing")]
    CertNotCodeSigning,
    #[error("certificate expired")]
    CertExpired,
    #[error("certificate not yet valid")]
    CertNotYetValid,
    #[error("file not found")]
    FileNotFound,
    #[error("file is in use")]
    FileInUse,
    #[error("access denied")]
    AccessDenied,
    #[error("unsupported file type")]
    UnsupportedFileType,
    #[error("timestamp server failed (0x{0:08X})")]
    TimestampFailed(u32),
    #[error("cancelled by user")]
    UserCancelled,
    #[error("output file already exists")]
    OutputExists,
    #[error("common name is empty")]
    EmptyCommonName,
    #[error("password too short")]
    PasswordTooShort,
    #[error("invalid validity period")]
    InvalidValidity,
    #[error("Win32 error 0x{hresult:08X}: {message}")]
    Win32 { hresult: u32, message: String },
}

/// 產生憑證時密碼的最小長度。
pub const MIN_PASSWORD_LEN: usize = 8;

impl CoreError {
    /// 穩定的英文代碼，用於 `--json` 輸出；不隨介面語言改變。
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::PfxWrongPassword => "pfx_wrong_password",
            CoreError::PfxInvalid => "pfx_invalid",
            CoreError::PfxNoSigningCert => "pfx_no_signing_cert",
            CoreError::InvalidThumbprint => "invalid_thumbprint",
            CoreError::CertNotFound => "cert_not_found",
            CoreError::CertNoPrivateKey => "cert_no_private_key",
            CoreError::CertNotCodeSigning => "cert_not_code_signing",
            CoreError::CertExpired => "cert_expired",
            CoreError::CertNotYetValid => "cert_not_yet_valid",
            CoreError::FileNotFound => "file_not_found",
            CoreError::FileInUse => "file_in_use",
            CoreError::AccessDenied => "access_denied",
            CoreError::UnsupportedFileType => "unsupported_file_type",
            CoreError::TimestampFailed(_) => "timestamp_failed",
            CoreError::UserCancelled => "user_cancelled",
            CoreError::OutputExists => "output_exists",
            CoreError::EmptyCommonName => "empty_common_name",
            CoreError::PasswordTooShort => "password_too_short",
            CoreError::InvalidValidity => "invalid_validity",
            CoreError::Win32 { .. } => "win32_error",
        }
    }

    /// 把 Windows HRESULT 對應成 `CoreError`；對不上的保留原始碼與系統訊息。
    pub fn from_hresult(hresult: u32, message: impl Into<String>) -> Self {
        match hresult {
            0x8007_0056 => CoreError::PfxWrongPassword, // ERROR_INVALID_PASSWORD
            0x800B_0003 => CoreError::UnsupportedFileType, // TRUST_E_SUBJECT_FORM_UNKNOWN
            0x8007_0002 | 0x8007_0003 => CoreError::FileNotFound, // FILE/PATH_NOT_FOUND
            0x8007_0020 | 0x8007_0021 => CoreError::FileInUse, // SHARING/LOCK_VIOLATION
            0x8007_0005 => CoreError::AccessDenied,
            0x8007_04C7 => CoreError::UserCancelled, // ERROR_CANCELLED
            0x8009_0016 | 0x8009_200B => CoreError::CertNoPrivateKey, // NTE_BAD_KEYSET, CRYPT_E_NO_KEY_PROPERTY
            0x800B_0101 => CoreError::CertExpired,                    // CERT_E_EXPIRED
            0x800B_0110 => CoreError::CertNotCodeSigning,             // CERT_E_WRONG_USAGE
            // WinINet 錯誤（12000–12175）＝連不上時間戳記伺服器；TRUST_E_TIME_STAMP
            0x8007_2EE0..=0x8007_2F8F | 0x8009_6005 => CoreError::TimestampFailed(hresult),
            _ => CoreError::Win32 {
                hresult,
                message: message.into().trim().to_string(),
            },
        }
    }

    /// 把 `windows::core::Error` 轉成 `CoreError`。
    pub fn from_win(e: &windows::core::Error) -> Self {
        Self::from_hresult(e.code().0 as u32, e.message())
    }

    /// 把 `std::io::Error` 轉成 `CoreError`。
    pub fn from_io(e: &std::io::Error) -> Self {
        match e.raw_os_error() {
            Some(2) | Some(3) => CoreError::FileNotFound,
            Some(32) | Some(33) => CoreError::FileInUse,
            Some(5) => CoreError::AccessDenied,
            Some(code) => Self::from_hresult(0x8007_0000 | (code as u32 & 0xFFFF), e.to_string()),
            None if e.kind() == std::io::ErrorKind::NotFound => CoreError::FileNotFound,
            None => CoreError::Win32 {
                hresult: 0x8000_4005, // E_FAIL
                message: e.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_hresults() {
        assert_eq!(
            CoreError::from_hresult(0x8007_0056, ""),
            CoreError::PfxWrongPassword
        );
        assert_eq!(
            CoreError::from_hresult(0x800B_0003, ""),
            CoreError::UnsupportedFileType
        );
        assert_eq!(
            CoreError::from_hresult(0x8007_0020, ""),
            CoreError::FileInUse
        );
        assert_eq!(
            CoreError::from_hresult(0x8007_04C7, ""),
            CoreError::UserCancelled
        );
        assert_eq!(
            CoreError::from_hresult(0x8007_2EFD, ""),
            CoreError::TimestampFailed(0x8007_2EFD)
        );
    }

    #[test]
    fn unknown_hresult_keeps_code_and_trimmed_message() {
        assert_eq!(
            CoreError::from_hresult(0x8009_0006, " 無效的簽章。\r\n"),
            CoreError::Win32 {
                hresult: 0x8009_0006,
                message: "無效的簽章。".into()
            }
        );
    }

    #[test]
    fn maps_io_errors() {
        let e = std::io::Error::from_raw_os_error(32);
        assert_eq!(CoreError::from_io(&e), CoreError::FileInUse);
        let e = std::io::Error::from_raw_os_error(2);
        assert_eq!(CoreError::from_io(&e), CoreError::FileNotFound);
        let e = std::io::Error::from_raw_os_error(5);
        assert_eq!(CoreError::from_io(&e), CoreError::AccessDenied);
    }

    #[test]
    fn codes_are_snake_case_and_stable() {
        assert_eq!(CoreError::PfxWrongPassword.code(), "pfx_wrong_password");
        assert_eq!(CoreError::TimestampFailed(1).code(), "timestamp_failed");
        assert_eq!(
            CoreError::Win32 {
                hresult: 1,
                message: String::new()
            }
            .code(),
            "win32_error"
        );
    }
}
