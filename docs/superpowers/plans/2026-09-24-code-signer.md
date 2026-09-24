# code-signer 實作計畫

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 做出單一 `code-signer.exe`：Windows Authenticode 簽章／驗證／產生自簽憑證，GUI（egui）與 CLI（clap）兩用，介面可切換繁體中文 / English，並放上 GitHub（`tntrock/code-signer`，公開）。

**Architecture:** `src/core/` 是純核心層（不依賴 CLI、GUI、i18n），直接呼叫 Windows 原生 API（`SignerSignEx2`、`WinVerifyTrust`、CryptoAPI 憑證存放區），並用 `rsa` + `rcgen` + `p12-keystore` 產生自簽憑證。`cli.rs` 與 `gui/` 只是外殼，`i18n.rs` 負責所有顯示文字。crate 同時是 library（`code_signer`）與 binary（`code-signer`），整合測試直接呼叫 library。

**Tech Stack:** Rust 2021（已驗證 rustc 1.96）、`windows` 0.62、`eframe` 0.36、`rfd` 0.17、`clap` 4.6（builder API）、`rsa` 0.9、`rcgen` 0.14、`p12-keystore` 0.3、`x509-parser` 0.18、`thiserror` 2、`serde`/`serde_json`、`zeroize`、`rpassword` 7、`winresource` 0.1。

**Spec:** `docs/superpowers/specs/2026-09-24-code-signer-design.md`

## Global Constraints

- 只支援 Windows；簽章與驗證**不得**呼叫 PowerShell 或 `signtool`
- 雜湊一律 SHA-256；時間戳記一律 RFC 3161（`SIGNER_TIMESTAMP_RFC3161` + `szOID_NIST_sha256`）
- 預設時間戳記伺服器：`http://timestamp.digicert.com`
- 可簽章副檔名（不分大小寫）：`exe dll sys ocx msi cab cat ps1 psm1`
- `.pfx` 匯入旗標必須是 `PKCS12_NO_PERSIST_KEY | PKCS12_ALWAYS_CNG_KSP`（只用 `NO_PERSIST_KEY` 時 `SignerSignEx2` 會回 `NTE_BAD_TYPE`，已實測）
- 簽章前先複製成同資料夾的暫存檔 `.<原檔名>.code-signer-tmp.<副檔名>`，成功才取代原檔；失敗時原檔不變、暫存檔刪除
- 時間戳記失敗視為簽章失敗，不可退回成無時間戳記的簽章
- 絕不把密碼寫進設定檔、log 或命令列參數；CLI 只接受 `--password-env` 或提示輸入
- CLI exit code：`0` 全部成功；`1` 至少一個檔案失敗（verify：有非 `Valid`）；`2` 參數／憑證／前置錯誤
- `--json` 的欄位名與 `status` 代碼固定英文，另附翻譯後的 `message`
- 測試不得修改系統信任清單（`install_trust` 只做手動驗證）
- 所有 `unsafe` 集中在 `src/core/` 與 `src/main.rs` 的小函式內，並附 `SAFETY:` 註解
- 每個 commit 訊息結尾加上：`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`
- 每個 task 結束前 `cargo fmt --check` 與 `cargo clippy --all-targets -- -D warnings` 都必須通過（唯一例外：Task 4 的 dead-code 警告，見該 task）

## 關於本計畫的程式碼

本計畫的每一段程式碼都已在拋棄式原型中完整編譯並測試過（30 個單元測試、7 個 CLI 測試、7 個端對端測試含連網時間戳記、clippy 零警告、GUI 實際啟動截圖）。請**逐字照抄**，不要「改良」；如果照抄後編譯或測試失敗，先回報差異再修改。

模組內的單元測試與實作放在同一個檔案（Rust 慣例），因此這類 task 的步驟是「寫出含測試的完整檔案 → 執行測試」。整合測試（`tests/sign_verify.rs`、`tests/cli.rs`）則是**先寫測試、確認失敗，再寫實作**。

## 檔案結構

| 檔案 | 責任 |
|---|---|
| `Cargo.toml` / `build.rs` / `assets/` | 相依套件、建置設定、嵌入圖示與版本資訊 |
| `src/lib.rs` | library 根模組 |
| `src/main.rs` | 進入點：無參數 → GUI（並釋放多餘主控台），有參數 → CLI |
| `src/core/error.rs` | `CoreError`、HRESULT／I/O 錯誤對應、穩定錯誤代碼 |
| `src/core/batch.rs` | 副檔名過濾、路徑展開、逐檔批次執行與取消 |
| `src/core/cert.rs` | 憑證摘要、自簽憑證產生、`.pfx`／存放區載入、信任清單匯入 |
| `src/core/signer.rs` | 單檔簽章（暫存檔 → `SignerSignEx2` → 取代） |
| `src/core/verify.rs` | 單檔驗證（`WinVerifyTrust` → `VerifyReport`） |
| `src/i18n.rs` | `Lang`、`Strings`（`ZH_TW`／`EN`）、錯誤與狀態翻譯、時間格式 |
| `src/settings.rs` | `%APPDATA%\code-signer\settings.json` |
| `src/cli.rs` | clap 指令、文字／JSON 輸出、exit code |
| `src/gui/*.rs` | 主視窗、三個分頁、共用檔案清單 |
| `tests/sign_verify.rs` | 核心端對端測試 |
| `tests/cli.rs` | CLI 端對端測試 |

---

### Task 1: 專案骨架、授權、CI

**Files:**
- Create: `Cargo.toml`, `.gitignore`, `build.rs`, `assets/gen_icon.py`, `assets/icon.ico`（由腳本產生）, `src/lib.rs`, `src/main.rs`, `LICENSE-MIT`, `LICENSE-APACHE`, `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: 無（repo 已有 `docs/superpowers/specs/…`、`.gitignore` 與第一個 commit）
- Produces: 可編譯的 crate `code-signer`（lib 名 `code_signer`、bin 名 `code-signer`），之後所有 task 只新增模組

- [ ] **Step 1: 寫 `Cargo.toml`**（一次列出全部相依套件，之後的 task 不必再改）

`Cargo.toml`：

````toml
[package]
name = "code-signer"
version = "0.1.0"
edition = "2021"
description = "Windows Authenticode 程式碼簽章工具（GUI + CLI）"
license = "MIT OR Apache-2.0"
repository = "https://github.com/tntrock/code-signer"
build = "build.rs"

[lib]
name = "code_signer"
path = "src/lib.rs"

[[bin]]
name = "code-signer"
path = "src/main.rs"

[dependencies]
# ---- GUI ----
eframe = "0.36"
rfd = "0.17"

# ---- CLI ----
clap = { version = "4.6", features = ["string"] }
rpassword = "7"

# ---- 憑證產生（純 Rust）----
rsa = "0.9"
rcgen = "0.14"
p12-keystore = "0.3"
x509-parser = "0.18"
sha1 = "0.10"
sha2 = "0.10"
time = { version = "0.3", features = ["formatting", "macros"] }

# ---- 共用 ----
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
zeroize = "1"

# ---- Win32（簽章、驗證、憑證存放區）----
[dependencies.windows]
version = "0.62"
features = [
    "Win32_Foundation",
    "Win32_Globalization",
    "Win32_Security_Cryptography",
    "Win32_Security_Cryptography_Catalog",
    "Win32_Security_Cryptography_Sip",
    "Win32_Security_WinTrust",
    "Win32_System_Console",
]

[dev-dependencies]
tempfile = "3"

[target.'cfg(windows)'.build-dependencies]
winresource = "0.1"

# 開發/測試時也最佳化相依套件：RSA 金鑰產生在未最佳化時非常慢
[profile.dev.package."*"]
opt-level = 2

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
panic = "abort"
````

- [ ] **Step 2: 寫 `.gitignore`**

`.gitignore`：

````text
/target
````

（`Cargo.lock` 要納入版控，因為這是執行檔專案。）

- [ ] **Step 3: 寫圖示產生腳本並產生 `assets/icon.ico`**

`assets/gen_icon.py`：

````python
"""產生 assets/icon.ico（只用 Python 標準函式庫）。

圖案：藍色圓角方塊上的白色勾號，代表「已簽章」。
執行：python assets/gen_icon.py
"""
import math
import struct
import zlib
from pathlib import Path

SIZES = [16, 32, 48, 256]
BG = (0x1F, 0x6F, 0xEB)
FG = (0xFF, 0xFF, 0xFF)


def dist_to_segment(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def pixel(u, v):
    """u, v ∈ [0,1)；回傳 RGBA。"""
    r = 0.2  # 圓角半徑
    cx = min(max(u, r), 1 - r)
    cy = min(max(v, r), 1 - r)
    if math.hypot(u - cx, v - cy) > r:
        return (0, 0, 0, 0)
    d = min(
        dist_to_segment(u, v, 0.26, 0.52, 0.43, 0.69),
        dist_to_segment(u, v, 0.43, 0.69, 0.76, 0.33),
    )
    return (*FG, 255) if d < 0.075 else (*BG, 255)


def png(size):
    ss = 4  # 超取樣抗鋸齒
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(ss):
                for sx in range(ss):
                    p = pixel((x + (sx + 0.5) / ss) / size, (y + (sy + 0.5) / ss) / size)
                    for i in range(4):
                        acc[i] += p[i]
            row += bytes(c // (ss * ss) for c in acc)
        rows.append(bytes(row))

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b"")


def ico(images):
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for size, data in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
        blobs += data
    return header + entries + blobs


out = Path(__file__).with_name("icon.ico")
out.write_bytes(ico([(s, png(s)) for s in SIZES]))
print(f"wrote {out}")
````

Run: `python assets/gen_icon.py`
Expected: `wrote ...\assets\icon.ico`

- [ ] **Step 4: 寫 `build.rs`**

`build.rs`：

````rust
//! 建置腳本：在 Windows 目標上把 assets/icon.ico 與版本資訊嵌入 exe。
//!
//! build.rs 在「主機」上執行，所以用 CARGO_CFG_TARGET_OS 判斷目標平台，而不是 cfg!(target_os)。

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.set("ProductName", "code-signer");
        res.set(
            "FileDescription",
            "code-signer - Windows Authenticode 程式碼簽章工具",
        );
        // 缺 rc.exe 等工具時只警告，不中斷建置
        if let Err(e) = res.compile() {
            println!("cargo:warning=嵌入 Windows 資源失敗: {e}");
        }
    }
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");
}
````

- [ ] **Step 5: 暫時的 `src/lib.rs` 與 `src/main.rs`**

`src/lib.rs`：

````rust
//! code-signer 函式庫：CLI 與 GUI 共用的核心邏輯、語言與設定。
````

`src/main.rs`：

````rust
fn main() {}
````

- [ ] **Step 6: 授權檔**

`LICENSE-MIT`：

`LICENSE-MIT`：

````text
MIT License

Copyright (c) 2026 Allen Yen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
````

`LICENSE-APACHE`：下載官方全文。

Run: `curl -sSfL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE-APACHE`
Expected: 檔案約 11 KB，第一行是 `Apache License`

- [ ] **Step 7: CI workflow**

`.github/workflows/ci.yml`：

`.github/workflows/ci.yml`：

````yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - name: Format
        run: cargo fmt --check
      - name: Clippy
        run: cargo clippy --all-targets -- -D warnings
      - name: Test
        run: cargo test
````

- [ ] **Step 8: 建置並確認版本資訊已嵌入**

Run: `cargo build`
Expected: 成功，沒有 `嵌入 Windows 資源失敗` 警告（第一次會下載並編譯相依套件，需要幾分鐘）

Run（PowerShell）：`(Get-Item target\debug\code-signer.exe).VersionInfo.ProductName`
Expected: `code-signer`

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "chore: scaffold code-signer crate, CI and licenses

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `CoreError` 與錯誤碼對應

**Files:**
- Create: `src/core/mod.rs`, `src/core/error.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Produces:
  - `pub enum CoreError { PfxWrongPassword, PfxInvalid, PfxNoSigningCert, InvalidThumbprint, CertNotFound, CertNoPrivateKey, CertNotCodeSigning, CertExpired, CertNotYetValid, FileNotFound, FileInUse, AccessDenied, UnsupportedFileType, TimestampFailed(u32), UserCancelled, OutputExists, EmptyCommonName, PasswordTooShort, InvalidValidity, Win32 { hresult: u32, message: String } }`（`Debug, Clone, PartialEq, Eq, thiserror::Error`）
  - `CoreError::code(&self) -> &'static str`、`CoreError::from_hresult(u32, impl Into<String>)`、`CoreError::from_win(&windows::core::Error)`、`CoreError::from_io(&std::io::Error)`
  - `pub const MIN_PASSWORD_LEN: usize = 8`
  - re-export：`code_signer::core::CoreError`

- [ ] **Step 1: 寫 `src/core/error.rs`**

`src/core/error.rs`：

````rust
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
````

- [ ] **Step 2: 寫 `src/core/mod.rs`（此時只有 error）**

````rust
//! 核心邏輯：不依賴 CLI、GUI 或 i18n，只回傳結構化結果與 `CoreError`。

pub mod error;

pub use error::CoreError;
````

- [ ] **Step 3: `src/lib.rs` 加入 core**

````rust
//! code-signer 函式庫：CLI 與 GUI 共用的核心邏輯、語言與設定。

pub mod core;
````

- [ ] **Step 4: 執行測試**

Run: `cargo test --lib core::error`
Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(core): add CoreError with HRESULT and I/O mapping

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: 批次處理與副檔名過濾

**Files:**
- Create: `src/core/batch.rs`
- Modify: `src/core/mod.rs`

**Interfaces:**
- Consumes: `CoreError`（Task 2）
- Produces:
  - `pub const SUPPORTED_EXTENSIONS: &[&str]`
  - `pub fn is_supported(path: &Path) -> bool`
  - `pub fn expand_paths(inputs: &[PathBuf], recursive: bool) -> Vec<PathBuf>`（資料夾展開並排序；其他路徑原樣保留；去重）
  - `pub struct FileResult<T> { pub path: PathBuf, pub result: Result<T, CoreError> }`
  - `pub fn run_batch<T>(files: &[PathBuf], cancel: &AtomicBool, op: impl FnMut(&Path) -> Result<T, CoreError>, on_result: impl FnMut(usize, &FileResult<T>)) -> Vec<FileResult<T>>`

- [ ] **Step 1: 寫 `src/core/batch.rs`**

`src/core/batch.rs`：

````rust
//! 批次處理：展開檔案/資料夾清單、過濾可簽章的副檔名、逐檔執行並回報結果。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use super::CoreError;

/// 可做 Authenticode 簽章的副檔名（小寫、不含點）。
pub const SUPPORTED_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "ocx", "msi", "cab", "cat", "ps1", "psm1",
];

/// 副檔名是否可簽章（不分大小寫）。
pub fn is_supported(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| SUPPORTED_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// 展開輸入清單：
/// - 資料夾 → 其中可簽章的檔案（`recursive` 決定是否進入子資料夾），依路徑排序
/// - 其他（檔案或不存在的路徑）→ 原樣保留，交給後續操作回報錯誤
///
/// 結果去除重複並保留第一次出現的順序。
pub fn expand_paths(inputs: &[PathBuf], recursive: bool) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for input in inputs {
        if input.is_dir() {
            let mut found = Vec::new();
            collect_dir(input, recursive, &mut found);
            found.sort();
            out.extend(found);
        } else {
            out.push(input.clone());
        }
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|p| seen.insert(p.clone()));
    out
}

fn collect_dir(dir: &Path, recursive: bool, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                collect_dir(&path, true, out);
            }
        } else if is_supported(&path) {
            out.push(path);
        }
    }
}

/// 單一檔案的處理結果。
#[derive(Debug, Clone, PartialEq)]
pub struct FileResult<T> {
    pub path: PathBuf,
    pub result: Result<T, CoreError>,
}

/// 依序對每個檔案執行 `op`。單檔失敗不影響其他檔案。
///
/// - 每處理完一個檔案呼叫 `on_result(索引, 結果)`，供 GUI 即時更新
/// - `cancel` 設為 true 後，處理完目前檔案即停止；未處理的檔案不會出現在結果中
pub fn run_batch<T>(
    files: &[PathBuf],
    cancel: &AtomicBool,
    mut op: impl FnMut(&Path) -> Result<T, CoreError>,
    mut on_result: impl FnMut(usize, &FileResult<T>),
) -> Vec<FileResult<T>> {
    let mut results = Vec::with_capacity(files.len());
    for (i, path) in files.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let r = FileResult {
            path: path.clone(),
            result: op(path),
        };
        on_result(i, &r);
        results.push(r);
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn touch(p: &Path) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b"x").unwrap();
    }

    #[test]
    fn supported_extensions_are_case_insensitive() {
        assert!(is_supported(Path::new("a.EXE")));
        assert!(is_supported(Path::new(r"C:\x\setup.msi")));
        assert!(is_supported(Path::new("m.psm1")));
        assert!(!is_supported(Path::new("readme.txt")));
        assert!(!is_supported(Path::new("noext")));
        assert!(!is_supported(Path::new("app.msix")));
    }

    #[test]
    fn expands_folders_and_filters_extensions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("b.dll"));
        touch(&root.join("a.exe"));
        touch(&root.join("notes.txt"));
        touch(&root.join("sub").join("c.msi"));

        let flat = expand_paths(&[root.to_path_buf()], false);
        assert_eq!(flat, vec![root.join("a.exe"), root.join("b.dll")]);

        let deep = expand_paths(&[root.to_path_buf()], true);
        assert_eq!(
            deep,
            vec![
                root.join("a.exe"),
                root.join("b.dll"),
                root.join("sub").join("c.msi")
            ]
        );
    }

    #[test]
    fn keeps_explicit_files_even_if_unsupported_and_dedupes() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("a.exe");
        touch(&exe);
        let txt = dir.path().join("x.txt");
        let got = expand_paths(&[txt.clone(), exe.clone(), dir.path().to_path_buf()], false);
        assert_eq!(got, vec![txt, exe]);
    }

    #[test]
    fn run_batch_continues_after_errors_and_reports_each() {
        let files = vec![
            PathBuf::from("ok1"),
            PathBuf::from("bad"),
            PathBuf::from("ok2"),
        ];
        let cancel = AtomicBool::new(false);
        let mut seen = Vec::new();
        let results = run_batch(
            &files,
            &cancel,
            |p| {
                if p == Path::new("bad") {
                    Err(CoreError::FileInUse)
                } else {
                    Ok(())
                }
            },
            |i, _| seen.push(i),
        );
        assert_eq!(seen, vec![0, 1, 2]);
        assert_eq!(results[1].result, Err(CoreError::FileInUse));
        assert!(results[0].result.is_ok() && results[2].result.is_ok());
    }

    #[test]
    fn run_batch_stops_when_cancelled() {
        let files = vec![PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")];
        let cancel = AtomicBool::new(false);
        let results = run_batch(
            &files,
            &cancel,
            |_| {
                cancel.store(true, Ordering::Relaxed);
                Ok(())
            },
            |_, _| {},
        );
        assert_eq!(results.len(), 1);
    }
}
````

- [ ] **Step 2: `src/core/mod.rs` 加入 batch**

````rust
//! 核心邏輯：不依賴 CLI、GUI 或 i18n，只回傳結構化結果與 `CoreError`。

pub mod batch;
pub mod error;

pub use error::CoreError;
````

- [ ] **Step 3: 執行測試**

Run: `cargo test --lib core::batch`
Expected: `5 passed`

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(core): add batch path expansion and runner

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: 憑證（摘要、產生、載入、存放區、信任清單）

**Files:**
- Create: `src/core/cert.rs`
- Modify: `src/core/mod.rs`

**Interfaces:**
- Consumes: `CoreError`、`MIN_PASSWORD_LEN`（Task 2）
- Produces:
  - `pub type Secret = zeroize::Zeroizing<String>`
  - `pub struct CertSummary { subject_cn: String, organization: Option<String>, issuer_cn: String, sha1: String, sha256: String, not_before: i64, not_after: i64, code_signing: bool /* serde skip */ }`（`Serialize`；指紋為大寫十六進位無分隔）
  - `pub fn summarize_der(der: &[u8]) -> Result<CertSummary, CoreError>`
  - `pub fn check_signing_usable(s: &CertSummary) -> Result<(), CoreError>`
  - `pub enum RsaBits { B2048, B3072, B4096 }`（`ALL`、`bits()`、`from_bits(usize)`）、`pub const VALIDITY_YEARS: [u32; 5] = [1, 2, 3, 5, 10]`
  - `pub struct NewCertParams { common_name, organization: Option<String>, validity_years: u32, key_bits: RsaBits, out_path: PathBuf, password: Secret, overwrite: bool }`
  - `pub struct CreatedCert { pub summary: CertSummary, pub der: Vec<u8> }`
  - `pub fn create_self_signed(p: &NewCertParams) -> Result<CreatedCert, CoreError>`
  - `pub enum StoreLocation { CurrentUser, LocalMachine }`
  - `pub enum CertSource { Pfx { path: PathBuf, password: Secret }, Store { thumbprint: String, location: StoreLocation } }`
  - `pub struct LoadedCert { pub summary: CertSummary, .. }`（`pub(crate) fn store()`、`pub(crate) fn context()`；非 `Send`）
  - `pub fn load_cert(src: &CertSource) -> Result<LoadedCert, CoreError>`
  - `pub fn parse_thumbprint(s: &str) -> Result<[u8; 20], CoreError>`
  - `pub fn list_store_signing_certs(location: StoreLocation) -> Result<Vec<CertSummary>, CoreError>`
  - `pub fn install_trust(cert_der: &[u8]) -> Result<(), CoreError>`

- [ ] **Step 1: 寫 `src/core/cert.rs`**

`src/core/cert.rs`：

````rust
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

#[derive(Debug, Clone)]
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
}
````

- [ ] **Step 2: `src/core/mod.rs` 加入 cert**

````rust
//! 核心邏輯：不依賴 CLI、GUI 或 i18n，只回傳結構化結果與 `CoreError`。

pub mod batch;
pub mod cert;
pub mod error;

pub use error::CoreError;
````

- [ ] **Step 3: 執行測試**

Run: `cargo test --lib core::cert`
Expected: `7 passed`。其中 `created_pfx_loads_with_windows_and_is_usable` 證明 `p12-keystore` 產生的 `.pfx` 能被 Windows `PFXImportCertStore` 讀取；`wrong_password_and_invalid_file_are_distinguished` 證明錯誤密碼得到 `PfxWrongPassword`。

注意：此時 clippy 會警告 `store`/`context` 未使用（Task 5 會用到）。這個 task 只要求 `cargo test` 通過；`cargo clippy` 的零警告要求從 Task 5 開始適用。

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(core): self-signed cert creation, pfx/store loading, trust install

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: 簽章與驗證

**Files:**
- Create: `tests/sign_verify.rs`, `src/core/signer.rs`, `src/core/verify.rs`
- Modify: `src/core/mod.rs`

**Interfaces:**
- Consumes: `is_supported`（Task 3）、`LoadedCert`、`summarize_der`、`CertSummary`、`create_self_signed`、`load_cert`（Task 4）
- Produces:
  - `pub const DEFAULT_TIMESTAMP_URL: &str = "http://timestamp.digicert.com"`
  - `pub struct SignOptions { pub timestamp_url: Option<String> }`（`Default`）
  - `pub fn sign_file(path: &Path, cert: &LoadedCert, opts: &SignOptions) -> Result<(), CoreError>`
  - `pub enum VerifyStatus { Valid, Unsigned, Tampered, UntrustedRoot, Expired, Distrusted, Other(u32) }`（`from_code(u32)`、`code() -> &'static str`）
  - `pub struct VerifyReport { status: VerifyStatus /* serde skip */, signer: Option<CertSummary>, timestamp: Option<i64>, chain: Vec<CertSummary> }`
  - `pub fn verify_file(path: &Path) -> Result<VerifyReport, CoreError>`

- [ ] **Step 1: 先寫整合測試 `tests/sign_verify.rs`**

`tests/sign_verify.rs`：

````rust
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
````

- [ ] **Step 2: 確認測試失敗**

Run: `cargo test --test sign_verify`
Expected: 編譯失敗，`unresolved import code_signer::core::signer`（以及 `verify`）

- [ ] **Step 3: 寫 `src/core/signer.rs`**

`src/core/signer.rs`：

````rust
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
````

- [ ] **Step 4: 寫 `src/core/verify.rs`**

`src/core/verify.rs`：

````rust
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
````

- [ ] **Step 5: `src/core/mod.rs` 加入 signer 與 verify（最終版）**

`src/core/mod.rs`：

````rust
//! 核心邏輯：不依賴 CLI、GUI 或 i18n，只回傳結構化結果與 `CoreError`。

pub mod batch;
pub mod cert;
pub mod error;
pub mod signer;
pub mod verify;

pub use error::CoreError;
````

- [ ] **Step 6: 執行全部測試（含連網時間戳記）**

Run: `cargo test`
Expected: lib `20 passed`（error 4 + batch 5 + cert 7 + signer 1 + verify 3）；`sign_verify` `6 passed; 1 ignored`

Run: `cargo test --test sign_verify -- --ignored`
Expected: `timestamp_is_recorded ... ok`（需要網路；離線時會失敗，屬預期）

Run: `cargo clippy --all-targets -- -D warnings`
Expected: 無警告

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(core): Authenticode signing via SignerSignEx2 and verification via WinVerifyTrust

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: 多語系 `i18n`

**Files:**
- Create: `src/i18n.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `CoreError`（Task 2）、`VerifyStatus`（Task 5）
- Produces:
  - `pub enum Lang { ZhTw, En }`：`ALL`、`code()`、`native_name()`、`parse(&str) -> Option<Lang>`、`from_langid(u16)`、`detect()`、`strings() -> &'static Strings`
  - `pub struct Strings { … }`（所有介面文字欄位，見程式碼）與方法 `error(&CoreError) -> String`、`status(&VerifyStatus) -> String`、`progress(done, total)`、`summary(total, ok, failed)`、`years(n)`
  - `pub fn format_time(unix: i64) -> String`（`YYYY-MM-DD HH:MM:SS UTC`）
  - `pub static ZH_TW: Strings`、`pub static EN: Strings`

- [ ] **Step 1: 寫 `src/i18n.rs`**

`src/i18n.rs`：

````rust
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
        if std::ptr::eq(self, &ZH_TW) {
            format!("共 {total} 個檔案：成功 {ok}、失敗 {failed}")
        } else {
            format!("{total} file(s): {ok} succeeded, {failed} failed")
        }
    }

    pub fn years(&self, n: u32) -> String {
        if std::ptr::eq(self, &ZH_TW) {
            format!("{n} 年")
        } else if n == 1 {
            "1 year".into()
        } else {
            format!("{n} years")
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
    cli_about: "Windows Authenticode 程式碼簽章工具。不帶參數執行會開啟圖形介面。",
    cli_sign_about: "對檔案進行 Authenticode 簽章",
    cli_verify_about: "驗證檔案的 Authenticode 簽章",
    cli_new_cert_about: "產生自簽程式碼簽章憑證（.pfx）",
    h_paths: "檔案或資料夾",
    h_pfx: "使用 .pfx 檔簽章",
    h_thumbprint: "使用 Windows 憑證存放區中的憑證（SHA-1 指紋）",
    h_store: "搭配 --thumbprint 的存放區位置",
    h_password_env: "從此環境變數讀取密碼（未指定時會提示輸入）",
    h_timestamp: "加上時間戳記；未指定 URL 時使用 http://timestamp.digicert.com",
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
    cli_about: "Windows Authenticode code signing tool. Run without arguments to open the GUI.",
    cli_sign_about: "Sign files with Authenticode",
    cli_verify_about: "Verify Authenticode signatures",
    cli_new_cert_about: "Create a self-signed code signing certificate (.pfx)",
    h_paths: "Files or folders",
    h_pfx: "Sign with a .pfx file",
    h_thumbprint: "Sign with a certificate from the Windows store (SHA-1 thumbprint)",
    h_store: "Store location for --thumbprint",
    h_password_env: "Read the password from this environment variable (prompts if omitted)",
    h_timestamp: "Add a timestamp; uses http://timestamp.digicert.com if no URL is given",
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
}
````

- [ ] **Step 2: `src/lib.rs` 加入 i18n**

````rust
//! code-signer 函式庫：CLI 與 GUI 共用的核心邏輯、語言與設定。

pub mod core;
pub mod i18n;
````

- [ ] **Step 3: 執行測試**

Run: `cargo test --lib i18n`
Expected: `4 passed`

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: add zh-TW / English strings with compile-time completeness

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: 設定檔

**Files:**
- Create: `src/settings.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `DEFAULT_TIMESTAMP_URL`（Task 5）
- Produces: `pub struct Settings { lang: Option<String>, last_pfx: Option<PathBuf>, use_store: bool, store_thumbprint: Option<String>, timestamp_enabled: bool, timestamp_url: String }`（`#[serde(default)]`；`Default` 的 `timestamp_enabled = true`、`timestamp_url = DEFAULT_TIMESTAMP_URL`）、`Settings::default_path() -> Option<PathBuf>`、`Settings::load_from(&Path) -> Settings`、`Settings::save_to(&self, &Path) -> io::Result<()>`

- [ ] **Step 1: 寫 `src/settings.rs`**

`src/settings.rs`：

````rust
//! GUI 設定：%APPDATA%\code-signer\settings.json。絕不儲存密碼。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::core::signer::DEFAULT_TIMESTAMP_URL;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// 語言代碼（zh-TW / en）；None = 依系統語言
    pub lang: Option<String>,
    pub last_pfx: Option<PathBuf>,
    /// true = 使用憑證存放區，false = .pfx
    pub use_store: bool,
    pub store_thumbprint: Option<String>,
    pub timestamp_enabled: bool,
    pub timestamp_url: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            lang: None,
            last_pfx: None,
            use_store: false,
            store_thumbprint: None,
            timestamp_enabled: true,
            timestamp_url: DEFAULT_TIMESTAMP_URL.into(),
        }
    }
}

impl Settings {
    /// 預設路徑：%APPDATA%\code-signer\settings.json
    pub fn default_path() -> Option<PathBuf> {
        std::env::var_os("APPDATA")
            .map(|d| PathBuf::from(d).join("code-signer").join("settings.json"))
    }

    /// 讀取設定；檔案不存在或內容損毀時回傳預設值。
    pub fn load_from(path: &Path) -> Settings {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_corrupt_file_gives_defaults() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            Settings::load_from(&dir.path().join("none.json")),
            Settings::default()
        );
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, "{ not json").unwrap();
        assert_eq!(Settings::load_from(&bad), Settings::default());
    }

    #[test]
    fn roundtrips_and_fills_missing_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("settings.json");
        let s = Settings {
            lang: Some("en".into()),
            last_pfx: Some(PathBuf::from(r"D:\certs\a.pfx")),
            use_store: true,
            store_thumbprint: Some("AB".repeat(20)),
            timestamp_enabled: false,
            timestamp_url: "http://ts.example".into(),
        };
        s.save_to(&path).unwrap();
        assert_eq!(Settings::load_from(&path), s);

        std::fs::write(&path, r#"{"lang":"zh-TW"}"#).unwrap();
        let partial = Settings::load_from(&path);
        assert_eq!(partial.lang.as_deref(), Some("zh-TW"));
        assert_eq!(partial.timestamp_url, DEFAULT_TIMESTAMP_URL);
        assert!(partial.timestamp_enabled);
    }

    #[test]
    fn never_serializes_a_password_field() {
        let json = serde_json::to_string(&Settings::default()).unwrap();
        assert!(!json.to_lowercase().contains("password"));
    }
}
````

- [ ] **Step 2: `src/lib.rs` 加入 settings**

````rust
//! code-signer 函式庫：CLI 與 GUI 共用的核心邏輯、語言與設定。

pub mod core;
pub mod i18n;
pub mod settings;
````

- [ ] **Step 3: 執行測試**

Run: `cargo test --lib settings`
Expected: `3 passed`

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: persist GUI settings without passwords

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: CLI

**Files:**
- Create: `tests/cli.rs`, `src/cli.rs`
- Modify: `src/lib.rs`, `src/main.rs`

**Interfaces:**
- Consumes: Task 3–7 的全部公開介面
- Produces: `pub const EXIT_OK: i32 = 0`、`EXIT_FILE_FAILED = 1`、`EXIT_SETUP_FAILED = 2`、`pub fn resolve_lang(&[OsString]) -> Lang`、`pub fn build_command(&'static Strings) -> clap::Command`、`pub fn run(Vec<OsString>) -> i32`

- [ ] **Step 1: 先寫 CLI 端對端測試 `tests/cli.rs`**

`tests/cli.rs`：

````rust
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
````

- [ ] **Step 2: 確認測試失敗**

Run: `cargo test --test cli`
Expected: 多個測試 FAIL（目前的 `main` 什麼都不做，exit code 都是 0、沒有輸出）

- [ ] **Step 3: 寫 `src/cli.rs`**

`src/cli.rs`：

````rust
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
fn read_password(m: &ArgMatches, t: &Strings, prompt: &str) -> Result<Secret, String> {
    if let Some(var) = m.get_one::<String>("password-env") {
        return std::env::var(var)
            .map(Secret::new)
            .map_err(|_| format!("{}: {var}", t.err_env_missing));
    }
    rpassword::prompt_password(prompt)
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
    let files = paths_of(m);
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
}
````

- [ ] **Step 4: `src/lib.rs` 加入 cli**

````rust
//! code-signer 函式庫：CLI 與 GUI 共用的核心邏輯、語言與設定。

pub mod cli;
pub mod core;
pub mod i18n;
pub mod settings;
````

- [ ] **Step 5: 暫時的 `src/main.rs`（GUI 在 Task 9 加入）**

````rust
//! code-signer 進入點（暫時只有 CLI）。

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    std::process::exit(code_signer::cli::run(args));
}
````

- [ ] **Step 6: 執行測試**

Run: `cargo test`
Expected: lib `30 passed`（i18n 4 + settings 3 + cli 3 已加入）、`cli` `7 passed`、`sign_verify` `6 passed; 1 ignored`

Run: `cargo clippy --all-targets -- -D warnings`
Expected: 無警告

- [ ] **Step 7: 手動看一下輸出**

Run: `cargo run -q -- --lang zh-TW sign --help`
Expected: 中文說明，列出 `--pfx`、`--thumbprint`、`--store`、`--password-env`、`--timestamp [<URL>]`、`-r`

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(cli): sign / verify / new-cert with localized help, JSON output and exit codes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: GUI

**Files:**
- Create: `src/gui/mod.rs`, `src/gui/file_list.rs`, `src/gui/sign_tab.rs`, `src/gui/verify_tab.rs`, `src/gui/cert_tab.rs`, `src/gui/app.rs`
- Modify: `src/lib.rs`, `src/main.rs`

**Interfaces:**
- Consumes: 全部核心介面、`Lang`/`Strings`/`format_time`、`Settings`
- Produces: `pub fn code_signer::gui::run() -> eframe::Result`

egui 0.36 的 API 與舊版不同，照抄時注意：`eframe::App` 要實作 `fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame)`；面板用 `egui::Panel::top(id).show(ui, …)` 與 `egui::CentralPanel::default_margins().show(ui, …)`；拖放檔案是 `i.raw.dropped_files`（元素為 `DroppedFileHandle`，用 `.path()`）；`FontDefinitions::font_data` 的值是 `Arc<FontData>`。

- [ ] **Step 1: 寫 `src/gui/mod.rs`**

`src/gui/mod.rs`：

````rust
//! 圖形介面（egui / eframe）。

mod app;
mod cert_tab;
mod file_list;
mod sign_tab;
mod verify_tab;

use std::sync::Arc;

use eframe::egui;

/// 開啟 GUI，直到視窗關閉。
pub fn run() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([820.0, 600.0])
            .with_min_inner_size([640.0, 460.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "code-signer",
        options,
        Box::new(|cc| {
            setup_fonts(&cc.egui_ctx);
            Ok(Box::new(app::App::new()))
        }),
    )
}

/// 載入系統中文字型作為備援字型，不把字型檔塞進 exe。
fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let candidates = [
        r"C:\Windows\Fonts\msjh.ttc",    // 微軟正黑體
        r"C:\Windows\Fonts\msjhl.ttc",   // 微軟正黑體 Light
        r"C:\Windows\Fonts\mingliu.ttc", // 細明體
        r"C:\Windows\Fonts\msyh.ttc",    // 微軟雅黑（後備）
        r"C:\Windows\Fonts\simsun.ttc",  // 宋體（後備）
    ];
    if let Some(bytes) = candidates.iter().find_map(|p| std::fs::read(p).ok()) {
        fonts.font_data.insert(
            "cjk".to_owned(),
            Arc::new(egui::FontData::from_owned(bytes)),
        );
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .push("cjk".to_owned());
        }
    }
    ctx.set_fonts(fonts);
}
````

- [ ] **Step 2: 寫 `src/gui/file_list.rs`**

`src/gui/file_list.rs`：

````rust
//! 簽章/驗證分頁共用：檔案工具列、拖放、狀態顏色。

use std::path::PathBuf;

use eframe::egui;

use crate::core::batch::{expand_paths, SUPPORTED_EXTENSIONS};
use crate::i18n::Strings;

pub enum ListAction {
    None,
    Add(Vec<PathBuf>),
    Clear,
}

/// [加入檔案] [加入資料夾] [清除]；資料夾一律遞迴展開。
pub fn toolbar(ui: &mut egui::Ui, t: &Strings, enabled: bool) -> ListAction {
    let mut action = ListAction::None;
    ui.add_enabled_ui(enabled, |ui| {
        ui.horizontal(|ui| {
            if ui.button(t.add_files).clicked() {
                if let Some(files) = rfd::FileDialog::new()
                    .add_filter(t.file_filter_name, SUPPORTED_EXTENSIONS)
                    .pick_files()
                {
                    action = ListAction::Add(files);
                }
            }
            if ui.button(t.add_folder).clicked() {
                if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                    action = ListAction::Add(expand_paths(&[dir], true));
                }
            }
            if ui.button(t.clear).clicked() {
                action = ListAction::Clear;
            }
        });
    });
    action
}

/// 本畫面被拖放進來的路徑（資料夾遞迴展開）。
pub fn dropped_paths(ctx: &egui::Context) -> Vec<PathBuf> {
    let dropped: Vec<PathBuf> = ctx.input(|i| {
        i.raw
            .dropped_files
            .iter()
            .map(|f| f.path().to_path_buf())
            .collect()
    });
    if dropped.is_empty() {
        dropped
    } else {
        expand_paths(&dropped, true)
    }
}

/// 加入時略過清單中已有的路徑。
pub fn merge_unique(
    existing: impl Iterator<Item = PathBuf>,
    incoming: Vec<PathBuf>,
) -> Vec<PathBuf> {
    let have: std::collections::HashSet<PathBuf> = existing.collect();
    incoming.into_iter().filter(|p| !have.contains(p)).collect()
}

pub const OK_COLOR: egui::Color32 = egui::Color32::from_rgb(0x2E, 0x9E, 0x44);
pub const ERR_COLOR: egui::Color32 = egui::Color32::from_rgb(0xD0, 0x3A, 0x3A);
pub const WARN_COLOR: egui::Color32 = egui::Color32::from_rgb(0xC8, 0x8A, 0x10);

/// 空清單時顯示拖放提示。
pub fn empty_hint(ui: &mut egui::Ui, t: &Strings) {
    ui.add_space(24.0);
    ui.vertical_centered(|ui| ui.weak(t.drop_hint));
    ui.add_space(24.0);
}
````

- [ ] **Step 3: 寫 `src/gui/sign_tab.rs`**

`src/gui/sign_tab.rs`：

````rust
//! 簽章分頁。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;

use eframe::egui;

use super::file_list::{self, ListAction, ERR_COLOR, OK_COLOR};
use crate::core::batch::run_batch;
use crate::core::cert::{
    list_store_signing_certs, load_cert, CertSource, CertSummary, Secret, StoreLocation,
};
use crate::core::signer::{sign_file, SignOptions};
use crate::core::CoreError;
use crate::i18n::Strings;
use crate::settings::Settings;

enum RowState {
    Pending,
    Running,
    Done(Result<(), CoreError>),
}

struct Row {
    path: PathBuf,
    state: RowState,
}

enum Msg {
    Started(usize),
    Finished(usize, Result<(), CoreError>),
    SetupFailed(CoreError),
    AllDone,
}

struct Worker {
    rx: Receiver<Msg>,
    cancel: Arc<AtomicBool>,
}

enum Notice {
    NeedFiles,
    NeedCert,
    Setup(CoreError),
    Summary {
        total: usize,
        ok: usize,
        failed: usize,
    },
}

pub struct SignTab {
    rows: Vec<Row>,
    use_store: bool,
    pfx_path: String,
    password: String,
    store_certs: Option<Result<Vec<CertSummary>, CoreError>>,
    store_thumbprint: Option<String>,
    ts_enabled: bool,
    ts_url: String,
    worker: Option<Worker>,
    notice: Option<Notice>,
}

impl SignTab {
    pub fn from_settings(s: &Settings) -> Self {
        SignTab {
            rows: Vec::new(),
            use_store: s.use_store,
            pfx_path: s
                .last_pfx
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            password: String::new(),
            store_certs: None,
            store_thumbprint: s.store_thumbprint.clone(),
            ts_enabled: s.timestamp_enabled,
            ts_url: s.timestamp_url.clone(),
            worker: None,
            notice: None,
        }
    }

    /// 把目前選擇寫回設定（不含密碼）。
    pub fn write_settings(&self, s: &mut Settings) {
        s.use_store = self.use_store;
        s.last_pfx =
            (!self.pfx_path.trim().is_empty()).then(|| PathBuf::from(self.pfx_path.trim()));
        s.store_thumbprint = self.store_thumbprint.clone();
        s.timestamp_enabled = self.ts_enabled;
        s.timestamp_url = self.ts_url.clone();
    }

    /// 產生憑證後帶入 .pfx 路徑。
    pub fn set_pfx(&mut self, path: PathBuf) {
        self.use_store = false;
        self.pfx_path = path.display().to_string();
        self.password.clear();
    }

    pub fn is_busy(&self) -> bool {
        self.worker.is_some()
    }

    pub fn add_paths(&mut self, paths: Vec<PathBuf>) {
        if self.is_busy() {
            return;
        }
        let new = file_list::merge_unique(self.rows.iter().map(|r| r.path.clone()), paths);
        self.rows.extend(new.into_iter().map(|path| Row {
            path,
            state: RowState::Pending,
        }));
    }

    fn poll(&mut self) {
        let Some(worker) = &self.worker else { return };
        let mut finished = false;
        while let Ok(msg) = worker.rx.try_recv() {
            match msg {
                Msg::Started(i) => self.rows[i].state = RowState::Running,
                Msg::Finished(i, r) => self.rows[i].state = RowState::Done(r),
                Msg::SetupFailed(e) => {
                    self.notice = Some(Notice::Setup(e));
                    finished = true;
                }
                Msg::AllDone => finished = true,
            }
        }
        if finished {
            self.worker = None;
            // 取消時尚未處理的列回到「等待中」
            for row in &mut self.rows {
                if matches!(row.state, RowState::Running) {
                    row.state = RowState::Pending;
                }
            }
            if !matches!(self.notice, Some(Notice::Setup(_))) {
                let done: Vec<_> = self
                    .rows
                    .iter()
                    .filter_map(|r| match &r.state {
                        RowState::Done(res) => Some(res.is_ok()),
                        _ => None,
                    })
                    .collect();
                let ok = done.iter().filter(|b| **b).count();
                self.notice = Some(Notice::Summary {
                    total: done.len(),
                    ok,
                    failed: done.len() - ok,
                });
            }
        }
    }

    fn cert_source(&self) -> Option<CertSource> {
        if self.use_store {
            self.store_thumbprint
                .clone()
                .map(|thumbprint| CertSource::Store {
                    thumbprint,
                    location: StoreLocation::CurrentUser,
                })
        } else if self.pfx_path.trim().is_empty() {
            None
        } else {
            Some(CertSource::Pfx {
                path: PathBuf::from(self.pfx_path.trim()),
                password: Secret::new(self.password.clone()),
            })
        }
    }

    /// 開始簽章；回傳 true 表示設定有變動、應儲存。
    fn start(&mut self, ctx: &egui::Context) -> bool {
        if self.rows.is_empty() {
            self.notice = Some(Notice::NeedFiles);
            return false;
        }
        let Some(source) = self.cert_source() else {
            self.notice = Some(Notice::NeedCert);
            return false;
        };
        self.notice = None;
        for row in &mut self.rows {
            row.state = RowState::Pending;
        }
        let paths: Vec<PathBuf> = self.rows.iter().map(|r| r.path.clone()).collect();
        let opts = SignOptions {
            timestamp_url: (self.ts_enabled && !self.ts_url.trim().is_empty())
                .then(|| self.ts_url.trim().to_string()),
        };
        let (tx, rx) = channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_flag = cancel.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            // LoadedCert 不可跨執行緒，因此在工作執行緒內載入
            let cert = match load_cert(&source) {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Msg::SetupFailed(e));
                    ctx.request_repaint();
                    return;
                }
            };
            let mut next = 0usize;
            run_batch(
                &paths,
                &cancel_flag,
                |p| {
                    let _ = tx.send(Msg::Started(next));
                    ctx.request_repaint();
                    next += 1;
                    sign_file(p, &cert, &opts)
                },
                |i, r| {
                    let _ = tx.send(Msg::Finished(i, r.result.clone()));
                    ctx.request_repaint();
                },
            );
            let _ = tx.send(Msg::AllDone);
            ctx.request_repaint();
        });
        self.worker = Some(Worker { rx, cancel });
        true
    }

    fn refresh_store(&mut self) {
        let list = list_store_signing_certs(StoreLocation::CurrentUser);
        if let Ok(certs) = &list {
            let still_there = self
                .store_thumbprint
                .as_ref()
                .is_some_and(|t| certs.iter().any(|c| &c.sha1 == t));
            if !still_there {
                self.store_thumbprint = certs.first().map(|c| c.sha1.clone());
            }
        }
        self.store_certs = Some(list);
    }

    /// 繪製分頁；回傳 true 表示設定有變動、應儲存。
    pub fn ui(&mut self, ui: &mut egui::Ui, t: &Strings) -> bool {
        self.poll();
        let busy = self.is_busy();
        let mut settings_changed = false;

        match file_list::toolbar(ui, t, !busy) {
            ListAction::Add(paths) => self.add_paths(paths),
            ListAction::Clear => {
                self.rows.clear();
                self.notice = None;
            }
            ListAction::None => {}
        }

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_height(180.0);
            egui::ScrollArea::vertical()
                .max_height(220.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    if self.rows.is_empty() {
                        file_list::empty_hint(ui, t);
                        return;
                    }
                    egui::Grid::new("sign_rows")
                        .striped(true)
                        .num_columns(2)
                        .min_col_width(120.0)
                        .show(ui, |ui| {
                            ui.strong(t.col_file);
                            ui.strong(t.col_status);
                            ui.end_row();
                            for row in &self.rows {
                                ui.label(row.path.display().to_string());
                                match &row.state {
                                    RowState::Pending => ui.weak(t.st_pending),
                                    RowState::Running => ui.label(t.st_running),
                                    RowState::Done(Ok(())) => {
                                        ui.colored_label(OK_COLOR, format!("✔ {}", t.st_signed))
                                    }
                                    RowState::Done(Err(e)) => {
                                        ui.colored_label(ERR_COLOR, format!("✘ {}", t.error(e)))
                                    }
                                };
                                ui.end_row();
                            }
                        });
                });
        });

        ui.add_space(8.0);
        ui.add_enabled_ui(!busy, |ui| {
            egui::Grid::new("sign_opts")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label(t.cert_source);
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.use_store, false, t.cert_pfx);
                        if ui
                            .radio_value(&mut self.use_store, true, t.cert_store)
                            .clicked()
                            && self.store_certs.is_none()
                        {
                            self.refresh_store();
                        }
                    });
                    ui.end_row();

                    if self.use_store {
                        ui.label("");
                        ui.horizontal(|ui| {
                            if self.store_certs.is_none() {
                                self.refresh_store();
                            }
                            match &self.store_certs {
                                Some(Ok(certs)) if !certs.is_empty() => {
                                    let label = |c: &CertSummary| {
                                        format!(
                                            "{} ({}…) — {}",
                                            c.subject_cn,
                                            &c.sha1[..8],
                                            crate::i18n::format_time(c.not_after)
                                        )
                                    };
                                    let selected = self
                                        .store_thumbprint
                                        .as_ref()
                                        .and_then(|t| certs.iter().find(|c| &c.sha1 == t))
                                        .map(label)
                                        .unwrap_or_default();
                                    egui::ComboBox::from_id_salt("store_cert")
                                        .width(420.0)
                                        .selected_text(selected)
                                        .show_ui(ui, |ui| {
                                            for c in certs {
                                                ui.selectable_value(
                                                    &mut self.store_thumbprint,
                                                    Some(c.sha1.clone()),
                                                    label(c),
                                                );
                                            }
                                        });
                                }
                                Some(Ok(_)) => {
                                    ui.weak(t.no_store_certs);
                                }
                                Some(Err(e)) => {
                                    ui.colored_label(ERR_COLOR, t.error(e));
                                }
                                None => {}
                            }
                            if ui.button(t.refresh).clicked() {
                                self.refresh_store();
                            }
                        });
                        ui.end_row();
                    } else {
                        ui.label("");
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.pfx_path).desired_width(360.0),
                            );
                            if ui.button(t.browse).clicked() {
                                if let Some(p) = rfd::FileDialog::new()
                                    .add_filter("PFX", &["pfx", "p12"])
                                    .pick_file()
                                {
                                    self.pfx_path = p.display().to_string();
                                }
                            }
                            ui.label(t.password);
                            ui.add(
                                egui::TextEdit::singleline(&mut self.password)
                                    .password(true)
                                    .desired_width(140.0),
                            );
                        });
                        ui.end_row();
                    }

                    ui.checkbox(&mut self.ts_enabled, t.timestamp);
                    ui.add_enabled(
                        self.ts_enabled,
                        egui::TextEdit::singleline(&mut self.ts_url).desired_width(360.0),
                    );
                    ui.end_row();
                });
        });

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let total = self.rows.len();
            let done = self
                .rows
                .iter()
                .filter(|r| matches!(r.state, RowState::Done(_)))
                .count();
            let fraction = if total == 0 {
                0.0
            } else {
                done as f32 / total as f32
            };
            ui.add(
                egui::ProgressBar::new(fraction)
                    .text(t.progress(done, total))
                    .desired_width(ui.available_width() - 130.0),
            );
            if let Some(w) = &self.worker {
                if ui.button(t.cancel).clicked() {
                    w.cancel.store(true, Ordering::Relaxed);
                }
            } else if ui
                .button(egui::RichText::new(t.start_sign).strong())
                .clicked()
            {
                settings_changed = self.start(ui.ctx());
            }
        });

        match &self.notice {
            Some(Notice::NeedFiles) => {
                ui.colored_label(ERR_COLOR, t.need_files);
            }
            Some(Notice::NeedCert) => {
                ui.colored_label(ERR_COLOR, t.need_cert);
            }
            Some(Notice::Setup(e)) => {
                ui.colored_label(ERR_COLOR, format!("✘ {}", t.error(e)));
            }
            Some(Notice::Summary { total, ok, failed }) => {
                let color = if *failed == 0 { OK_COLOR } else { ERR_COLOR };
                ui.colored_label(color, t.summary(*total, *ok, *failed));
            }
            None => {}
        }
        settings_changed
    }
}
````

- [ ] **Step 4: 寫 `src/gui/verify_tab.rs`**

`src/gui/verify_tab.rs`：

````rust
//! 驗證分頁：加入檔案後自動在背景驗證。

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};

use eframe::egui;

use super::file_list::{self, ListAction, ERR_COLOR, OK_COLOR, WARN_COLOR};
use crate::core::cert::CertSummary;
use crate::core::verify::{verify_file, VerifyReport, VerifyStatus};
use crate::core::CoreError;
use crate::i18n::{format_time, Strings};

struct Row {
    path: PathBuf,
    result: Option<Result<VerifyReport, CoreError>>,
}

/// (清單世代, 列索引, 結果)。清除清單後世代遞增，舊結果直接丟棄。
type Msg = (u64, usize, Result<VerifyReport, CoreError>);

pub struct VerifyTab {
    rows: Vec<Row>,
    selected: Option<usize>,
    generation: u64,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
}

impl Default for VerifyTab {
    fn default() -> Self {
        let (tx, rx) = channel();
        VerifyTab {
            rows: Vec::new(),
            selected: None,
            generation: 0,
            tx,
            rx,
        }
    }
}

impl VerifyTab {
    pub fn add_paths(&mut self, paths: Vec<PathBuf>, ctx: &egui::Context) {
        let new = file_list::merge_unique(self.rows.iter().map(|r| r.path.clone()), paths);
        if new.is_empty() {
            return;
        }
        let start = self.rows.len();
        self.rows
            .extend(new.iter().cloned().map(|path| Row { path, result: None }));
        let (tx, ctx, generation) = (self.tx.clone(), ctx.clone(), self.generation);
        std::thread::spawn(move || {
            for (offset, path) in new.iter().enumerate() {
                let _ = tx.send((generation, start + offset, verify_file(path)));
                ctx.request_repaint();
            }
        });
    }

    fn poll(&mut self) {
        while let Ok((generation, i, result)) = self.rx.try_recv() {
            if generation == self.generation {
                if let Some(row) = self.rows.get_mut(i) {
                    row.result = Some(result);
                }
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, t: &Strings) {
        self.poll();
        match file_list::toolbar(ui, t, true) {
            ListAction::Add(paths) => self.add_paths(paths, &ui.ctx().clone()),
            ListAction::Clear => {
                self.rows.clear();
                self.selected = None;
                self.generation += 1;
            }
            ListAction::None => {}
        }

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_height(220.0);
            egui::ScrollArea::vertical()
                .max_height(260.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    if self.rows.is_empty() {
                        file_list::empty_hint(ui, t);
                        return;
                    }
                    egui::Grid::new("verify_rows")
                        .striped(true)
                        .num_columns(4)
                        .min_col_width(80.0)
                        .show(ui, |ui| {
                            ui.strong(t.col_file);
                            ui.strong(t.col_status);
                            ui.strong(t.col_signer);
                            ui.strong(t.col_timestamp);
                            ui.end_row();
                            for (i, row) in self.rows.iter().enumerate() {
                                let name = row
                                    .path
                                    .file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_default();
                                if ui
                                    .selectable_label(self.selected == Some(i), name)
                                    .on_hover_text(row.path.display().to_string())
                                    .clicked()
                                {
                                    self.selected = Some(i);
                                }
                                match &row.result {
                                    None => {
                                        ui.weak(t.st_running);
                                        ui.label("");
                                        ui.label("");
                                    }
                                    Some(Err(e)) => {
                                        ui.colored_label(ERR_COLOR, format!("✘ {}", t.error(e)));
                                        ui.label("");
                                        ui.label("");
                                    }
                                    Some(Ok(rep)) => {
                                        let (color, mark) = match rep.status {
                                            VerifyStatus::Valid => (OK_COLOR, "✔"),
                                            VerifyStatus::UntrustedRoot => (WARN_COLOR, "⚠"),
                                            _ => (ERR_COLOR, "✘"),
                                        };
                                        ui.colored_label(
                                            color,
                                            format!("{mark} {}", t.status(&rep.status)),
                                        );
                                        ui.label(
                                            rep.signer
                                                .as_ref()
                                                .map(|s| s.subject_cn.as_str())
                                                .unwrap_or(""),
                                        );
                                        ui.label(
                                            rep.timestamp.map(format_time).unwrap_or_default(),
                                        );
                                    }
                                }
                                ui.end_row();
                            }
                        });
                });
        });

        if let Some(Some(Ok(rep))) = self
            .selected
            .and_then(|i| self.rows.get(i))
            .map(|r| r.result.as_ref())
        {
            ui.add_space(8.0);
            ui.strong(t.details);
            egui::ScrollArea::vertical()
                .id_salt("verify_details")
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("{}:", t.col_timestamp));
                        ui.label(
                            rep.timestamp
                                .map(format_time)
                                .unwrap_or_else(|| t.no_timestamp.into()),
                        );
                    });
                    for (depth, cert) in rep.chain.iter().enumerate() {
                        let title = if depth == 0 {
                            format!("{} — {}", t.col_signer, cert.subject_cn)
                        } else {
                            format!("{} {} — {}", t.chain, depth, cert.subject_cn)
                        };
                        egui::CollapsingHeader::new(title)
                            .id_salt(("chain", depth))
                            .default_open(depth == 0)
                            .show(ui, |ui| {
                                cert_details(ui, t, cert);
                            });
                    }
                });
        }
    }
}

fn cert_details(ui: &mut egui::Ui, t: &Strings, c: &CertSummary) {
    egui::Grid::new(("cert", &c.sha1))
        .num_columns(2)
        .show(ui, |ui| {
            ui.label(t.issuer);
            ui.label(&c.issuer_cn);
            ui.end_row();
            ui.label(t.valid_from);
            ui.label(format_time(c.not_before));
            ui.end_row();
            ui.label(t.valid_to);
            ui.label(format_time(c.not_after));
            ui.end_row();
            ui.label(t.sha1_thumbprint);
            ui.monospace(&c.sha1);
            ui.end_row();
            ui.label(t.sha256_thumbprint);
            ui.monospace(&c.sha256);
            ui.end_row();
        });
}
````

- [ ] **Step 5: 寫 `src/gui/cert_tab.rs`**

`src/gui/cert_tab.rs`：

````rust
//! 產生憑證分頁。

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};

use eframe::egui;

use super::file_list::{ERR_COLOR, OK_COLOR, WARN_COLOR};
use crate::core::cert::{
    create_self_signed, install_trust, CreatedCert, NewCertParams, RsaBits, Secret, VALIDITY_YEARS,
};
use crate::core::CoreError;
use crate::i18n::Strings;

struct Outcome {
    created: Result<CreatedCert, CoreError>,
    trust: Option<Result<(), CoreError>>,
    path: PathBuf,
}

enum Notice {
    PasswordMismatch,
    ConfirmOverwrite,
    Done(Box<Outcome>),
}

pub struct CertTab {
    cn: String,
    org: String,
    years: u32,
    key_bits: RsaBits,
    out_path: String,
    pw1: String,
    pw2: String,
    install_trust: bool,
    worker: Option<Receiver<Outcome>>,
    notice: Option<Notice>,
}

impl Default for CertTab {
    fn default() -> Self {
        CertTab {
            cn: String::new(),
            org: String::new(),
            years: 3,
            key_bits: RsaBits::B3072,
            out_path: String::new(),
            pw1: String::new(),
            pw2: String::new(),
            install_trust: false,
            worker: None,
            notice: None,
        }
    }
}

impl CertTab {
    fn start(&mut self, ctx: &egui::Context, overwrite: bool) {
        if self.pw1 != self.pw2 {
            self.notice = Some(Notice::PasswordMismatch);
            return;
        }
        let path = PathBuf::from(self.out_path.trim());
        if path.exists() && !overwrite {
            self.notice = Some(Notice::ConfirmOverwrite);
            return;
        }
        self.notice = None;
        let params = NewCertParams {
            common_name: self.cn.clone(),
            organization: Some(self.org.clone()),
            validity_years: self.years,
            key_bits: self.key_bits,
            out_path: path.clone(),
            password: Secret::new(self.pw1.clone()),
            overwrite,
        };
        let want_trust = self.install_trust;
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let created = create_self_signed(&params);
            let trust = match (&created, want_trust) {
                (Ok(c), true) => Some(install_trust(&c.der)),
                _ => None,
            };
            let _ = tx.send(Outcome {
                created,
                trust,
                path,
            });
            ctx.request_repaint();
        });
        self.worker = Some(rx);
    }

    /// 繪製分頁；成功產生憑證時回傳其路徑，讓簽章分頁帶入。
    pub fn ui(&mut self, ui: &mut egui::Ui, t: &Strings) -> Option<PathBuf> {
        let mut created_path = None;
        if let Some(rx) = &self.worker {
            if let Ok(outcome) = rx.try_recv() {
                self.worker = None;
                if outcome.created.is_ok() {
                    created_path = Some(outcome.path.clone());
                    self.pw1.clear();
                    self.pw2.clear();
                }
                self.notice = Some(Notice::Done(Box::new(outcome)));
            }
        }
        let busy = self.worker.is_some();

        ui.add_enabled_ui(!busy, |ui| {
            egui::Grid::new("cert_form")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t.cn);
                    ui.add(egui::TextEdit::singleline(&mut self.cn).desired_width(320.0));
                    ui.end_row();

                    ui.label(t.org_optional);
                    ui.add(egui::TextEdit::singleline(&mut self.org).desired_width(320.0));
                    ui.end_row();

                    ui.label(t.validity);
                    egui::ComboBox::from_id_salt("years")
                        .selected_text(t.years(self.years))
                        .show_ui(ui, |ui| {
                            for y in VALIDITY_YEARS {
                                ui.selectable_value(&mut self.years, y, t.years(y));
                            }
                        });
                    ui.end_row();

                    ui.label(t.key_size);
                    egui::ComboBox::from_id_salt("key_bits")
                        .selected_text(format!("RSA {}", self.key_bits.bits()))
                        .show_ui(ui, |ui| {
                            for b in RsaBits::ALL {
                                ui.selectable_value(
                                    &mut self.key_bits,
                                    b,
                                    format!("RSA {}", b.bits()),
                                );
                            }
                        });
                    ui.end_row();

                    ui.label(t.out_path);
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut self.out_path).desired_width(320.0));
                        if ui.button(t.browse).clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("PFX", &["pfx"])
                                .set_file_name("code-signing.pfx")
                                .save_file()
                            {
                                self.out_path = p.display().to_string();
                            }
                        }
                    });
                    ui.end_row();

                    ui.label(t.password);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pw1)
                            .password(true)
                            .desired_width(200.0),
                    );
                    ui.end_row();

                    ui.label(t.confirm_password);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pw2)
                            .password(true)
                            .desired_width(200.0),
                    );
                    ui.end_row();
                });

            ui.add_space(6.0);
            ui.checkbox(&mut self.install_trust, t.install_trust);
            if self.install_trust {
                ui.colored_label(WARN_COLOR, t.install_trust_note);
            }
            ui.add_space(6.0);
            let can_generate = !self.cn.trim().is_empty()
                && !self.out_path.trim().is_empty()
                && !self.pw1.is_empty();
            let label = if busy { t.generating } else { t.generate };
            if ui
                .add_enabled(
                    can_generate,
                    egui::Button::new(egui::RichText::new(label).strong()),
                )
                .clicked()
            {
                self.start(ui.ctx(), false);
            }
        });

        let mut overwrite_choice = None;
        match &self.notice {
            Some(Notice::PasswordMismatch) => {
                ui.colored_label(ERR_COLOR, t.password_mismatch);
            }
            Some(Notice::ConfirmOverwrite) => {
                ui.horizontal(|ui| {
                    ui.colored_label(WARN_COLOR, t.overwrite_confirm);
                    if ui.button(t.yes).clicked() {
                        overwrite_choice = Some(true);
                    }
                    if ui.button(t.no).clicked() {
                        overwrite_choice = Some(false);
                    }
                });
            }
            Some(Notice::Done(o)) => match &o.created {
                Err(e) => {
                    ui.colored_label(ERR_COLOR, format!("✘ {}", t.error(e)));
                }
                Ok(c) => {
                    ui.colored_label(
                        OK_COLOR,
                        format!("✔ {} — {}", t.cert_created, o.path.display()),
                    );
                    ui.monospace(format!("SHA-1 {}", c.summary.sha1));
                    match &o.trust {
                        Some(Ok(())) => {
                            ui.colored_label(OK_COLOR, format!("✔ {}", t.trust_installed));
                        }
                        Some(Err(e)) => {
                            ui.colored_label(
                                ERR_COLOR,
                                format!("✘ {}: {}", t.trust_failed, t.error(e)),
                            );
                        }
                        None => {}
                    }
                }
            },
            None => {}
        }
        match overwrite_choice {
            Some(true) => self.start(ui.ctx(), true),
            Some(false) => self.notice = None,
            None => {}
        }
        created_path
    }
}
````

- [ ] **Step 6: 寫 `src/gui/app.rs`**

`src/gui/app.rs`：

````rust
//! 主視窗：分頁切換、語言選單、設定儲存、拖放分派。

use std::path::PathBuf;

use eframe::egui;

use super::cert_tab::CertTab;
use super::file_list;
use super::sign_tab::SignTab;
use super::verify_tab::VerifyTab;
use crate::i18n::Lang;
use crate::settings::Settings;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Sign,
    Verify,
    Cert,
}

pub struct App {
    lang: Lang,
    settings: Settings,
    settings_path: Option<PathBuf>,
    tab: Tab,
    sign: SignTab,
    verify: VerifyTab,
    cert: CertTab,
}

impl App {
    pub fn new() -> Self {
        let settings_path = Settings::default_path();
        let settings = settings_path
            .as_deref()
            .map(Settings::load_from)
            .unwrap_or_default();
        let lang = settings
            .lang
            .as_deref()
            .and_then(Lang::parse)
            .unwrap_or_else(Lang::detect);
        App {
            lang,
            sign: SignTab::from_settings(&settings),
            settings,
            settings_path,
            tab: Tab::Sign,
            verify: VerifyTab::default(),
            cert: CertTab::default(),
        }
    }

    fn save_settings(&mut self) {
        self.sign.write_settings(&mut self.settings);
        self.settings.lang = Some(self.lang.code().into());
        if let Some(path) = &self.settings_path {
            let _ = self.settings.save_to(path);
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let t = self.lang.strings();
        let ctx = ui.ctx().clone();
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(t.app_title.into()));

        // 拖放：簽章分頁以外一律交給驗證分頁
        let dropped = file_list::dropped_paths(&ctx);
        if !dropped.is_empty() {
            match self.tab {
                Tab::Sign => self.sign.add_paths(dropped),
                _ => {
                    self.tab = Tab::Verify;
                    self.verify.add_paths(dropped, &ctx);
                }
            }
        }

        egui::Panel::top("tabs").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Sign, t.tab_sign);
                ui.selectable_value(&mut self.tab, Tab::Verify, t.tab_verify);
                ui.selectable_value(&mut self.tab, Tab::Cert, t.tab_cert);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let before = self.lang;
                    egui::ComboBox::from_id_salt("lang")
                        .selected_text(self.lang.native_name())
                        .show_ui(ui, |ui| {
                            for l in Lang::ALL {
                                ui.selectable_value(&mut self.lang, l, l.native_name());
                            }
                        });
                    if self.lang != before {
                        self.save_settings();
                    }
                });
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default_margins().show(ui, |ui| match self.tab {
            Tab::Sign => {
                if self.sign.ui(ui, t) {
                    self.save_settings();
                }
            }
            Tab::Verify => self.verify.ui(ui, t),
            Tab::Cert => {
                if let Some(path) = self.cert.ui(ui, t) {
                    self.sign.set_pfx(path);
                    self.save_settings();
                }
            }
        });
    }
}
````

- [ ] **Step 7: `src/lib.rs`（最終版）**

`src/lib.rs`：

````rust
//! code-signer 函式庫：CLI 與 GUI 共用的核心邏輯、語言與設定。

pub mod cli;
pub mod core;
pub mod gui;
pub mod i18n;
pub mod settings;
````

- [ ] **Step 8: `src/main.rs`（最終版）**

`src/main.rs`：

````rust
//! code-signer 進入點：不帶參數開 GUI，帶參數走 CLI。

use std::ffi::OsString;

fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();
    if args.len() <= 1 {
        detach_console_if_owned();
        if let Err(e) = code_signer::gui::run() {
            eprintln!("{e}");
            std::process::exit(code_signer::cli::EXIT_SETUP_FAILED);
        }
    } else {
        std::process::exit(code_signer::cli::run(args));
    }
}

/// 從檔案總管雙擊啟動時，Windows 會為這個主控台程式建立專屬的主控台視窗；
/// 若主控台上只有本程序（代表不是從終端機執行），就釋放它，只留下 GUI。
fn detach_console_if_owned() {
    use windows::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
    let mut pids = [0u32; 2];
    // SAFETY: 緩衝區長度正確；兩個 API 都沒有其他前置條件。
    unsafe {
        if GetConsoleProcessList(&mut pids) == 1 {
            let _ = FreeConsole();
        }
    }
}
````

- [ ] **Step 9: 建置與自動測試**

Run: `cargo build && cargo test && cargo clippy --all-targets -- -D warnings`
Expected: 全部通過、無警告

- [ ] **Step 10: 手動驗證 GUI**

**截圖只能用 `PrintWindow` 擷取本程式的視窗**，不可用 `CopyFromScreen` 擷取螢幕（會拍到使用者畫面上的其他內容）。截圖腳本見 Task 10 Step 1。

逐項確認：

1. 在檔案總管雙擊 `target\debug\code-signer.exe` → 只出現 GUI，沒有殘留的黑色主控台視窗
2. 在 PowerShell 執行 `.\target\debug\code-signer.exe verify .\target\debug\code-signer.exe` → 終端機正常輸出並回傳 exit code 1
3. 右上角切換 English ↔ 繁體中文 → 標題、分頁、按鈕立即改變；重開程式後維持上次選擇
4. 「產生憑證」：填 CN、輸出路徑 `%TEMP%\gui-test.pfx`、密碼兩次 → 成功，顯示 SHA-1；簽章分頁的 .pfx 欄位自動帶入。再按一次 → 出現「檔案已存在，要覆寫嗎？」
5. 勾選「同時匯入本機信任清單」再產生一次（選覆寫）→ Windows 跳出確認視窗：
   - 按「否」→ 顯示「憑證已產生，但加入信任清單失敗：使用者已取消」
   - 再試一次按「是」→ 顯示「已加入目前使用者的信任清單」
6. 「簽章」：拖入一份 exe 的複本（例如 `copy target\debug\code-signer.exe %TEMP%\s.exe`）→ 輸入密碼 → 開始簽章 → ✔ 已簽章，摘要列出成功 1
7. 故意輸入錯誤密碼 → 顯示「✘ .pfx 密碼錯誤」，檔案清單狀態不變
8. 「驗證」：拖入剛簽好的檔案 → 因為第 5 步已信任，應顯示「✔ 簽章有效」；點檔名可展開 SHA-1／SHA-256、有效期間與憑證鏈
9. 「憑證存放區」模式：下拉選單只列出有私鑰、可做程式碼簽章的憑證（沒有就顯示提示文字）
10. 清理：在 `certmgr.msc` 的「受信任的根憑證授權單位」與「受信任的發行者」中刪除測試憑證

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "feat(gui): egui interface with sign, verify and certificate tabs

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: README、截圖、Release workflow、最終驗證

**Files:**
- Create: `README.md`, `docs/screenshot.png`, `.github/workflows/release.yml`

**Interfaces:**
- Consumes: 完成的程式
- Produces: 可發佈的 repo 內容

- [ ] **Step 1: 截取 GUI 畫面（只擷取本程式視窗）**

把以下腳本存成 `$env:TEMP\shot.ps1` 後執行：`powershell -NoProfile -File $env:TEMP\shot.ps1`（不要 commit 這個腳本）。

````powershell
$exe = Join-Path (Get-Location) "target\debug\code-signer.exe"
$out = Join-Path (Get-Location) "docs\screenshot.png"
New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System; using System.Runtime.InteropServices;
public class Shot { [StructLayout(LayoutKind.Sequential)] public struct R { public int L,T,Rt,B; }
 public delegate bool EP(IntPtr h, IntPtr l);
 [DllImport("user32.dll")] public static extern bool EnumWindows(EP cb, IntPtr l);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out R r);
 [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
 [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
 public static IntPtr Find(uint pid) { IntPtr best = IntPtr.Zero; int area = 0;
  EnumWindows((h, l) => { uint p; GetWindowThreadProcessId(h, out p);
   if (p == pid && IsWindowVisible(h)) { R r; GetWindowRect(h, out r); int a = (r.Rt-r.L)*(r.B-r.T); if (a > area) { area = a; best = h; } }
   return true; }, IntPtr.Zero);
  return best; } }
'@
[Shot]::SetProcessDPIAware() | Out-Null
$p = Start-Process $exe -PassThru
Start-Sleep -Seconds 3
$h = [Shot]::Find([uint32]$p.Id)
$r = New-Object Shot+R; [Shot]::GetWindowRect($h, [ref]$r) | Out-Null
$bmp = New-Object System.Drawing.Bitmap ($r.Rt - $r.L), ($r.B - $r.T)
$g = [System.Drawing.Graphics]::FromImage($bmp); $hdc = $g.GetHdc()
[Shot]::PrintWindow($h, $hdc, 2) | Out-Null   # PW_RENDERFULLCONTENT：只畫這個視窗
$g.ReleaseHdc($hdc); $bmp.Save($out)
Stop-Process $p -Force
"saved $out"
````

Expected: `docs\screenshot.png` 是繁中介面的簽章分頁。打開圖片確認內容只有本程式視窗。

- [ ] **Step 2: 寫 `README.md`（中文在上、英文在下）**

`README.md`：

`````markdown
# code-signer

[![CI](https://github.com/tntrock/code-signer/actions/workflows/ci.yml/badge.svg)](https://github.com/tntrock/code-signer/actions/workflows/ci.yml)

**繁體中文** · [English](#english)

Windows 用的 Authenticode 程式碼簽章工具。單一 exe，同時提供圖形介面與命令列，介面可切換繁體中文 / English。

![簽章畫面](docs/screenshot.png)

## 功能

- **簽章**：`.exe` `.dll` `.sys` `.ocx` `.msi` `.cab` `.cat` `.ps1` `.psm1`，SHA-256
- **時間戳記**：RFC 3161（預設 `http://timestamp.digicert.com`），憑證過期後簽章仍有效
- **批次**：一次處理多個檔案或整個資料夾；單一檔案失敗不影響其他檔案
- **驗證**：顯示簽章狀態、簽章者、時間戳記與憑證鏈
- **產生自簽憑證**：帶程式碼簽章用途的 RSA 憑證，匯出 `.pfx`，可選擇加入本機信任清單以便測試
- **憑證來源**：`.pfx` 檔，或 Windows 憑證存放區（以指紋指定）
- 直接呼叫 Windows 原生簽章 API，**不需要安裝 Windows SDK / signtool**
- 簽章失敗時原檔不會被改動；不儲存任何密碼

## 下載

到 [Releases](https://github.com/tntrock/code-signer/releases) 下載 `code-signer.exe`，免安裝。可用同頁的 `.sha256` 檔核對雜湊值。

## 圖形介面

直接雙擊 `code-signer.exe`。

1. **產生憑證**分頁：填入名稱、密碼與輸出路徑後按「產生」。勾選「同時匯入本機信任清單」時，Windows 會跳出安全性確認視窗
2. **簽章**分頁：把檔案或資料夾拖進視窗，選擇憑證、輸入密碼，按「開始簽章」
3. **驗證**分頁：把檔案拖進視窗即自動驗證，點選檔案可看詳細資訊

## 命令列

```powershell
# 產生自簽憑證（密碼從環境變數讀取；未指定 --password-env 時會提示輸入）
$env:PFX_PW = "your-password"
code-signer new-cert --cn "My Company Test" --out test.pfx --password-env PFX_PW

# 簽章（含時間戳記），資料夾遞迴
code-signer sign .\dist -r --pfx test.pfx --password-env PFX_PW --timestamp

# 使用憑證存放區中的憑證
code-signer sign app.exe --thumbprint A1B2C3... --timestamp

# 驗證，並輸出 JSON
code-signer verify app.exe --json
```

| Exit code | 意義 |
|---|---|
| 0 | 全部成功（verify：全部簽章有效） |
| 1 | 至少一個檔案失敗（verify：有未簽章或簽章無效的檔案） |
| 2 | 參數、憑證或其他前置錯誤，沒有處理任何檔案 |

語言：`--lang zh-TW|en`，或設定環境變數 `CODE_SIGNER_LANG`；預設依 Windows 顯示語言。`--json` 的欄位名稱與 `status` 代碼固定為英文。

## 關於自簽憑證

自簽憑證只在**信任它的電腦**上會顯示「簽章有效」，其他電腦會顯示「根憑證不受信任」，SmartScreen 也不會因此信任你的程式。要公開發佈，請向 CA 購買程式碼簽章憑證，再用本工具的「憑證存放區」或 `.pfx` 模式簽章。

測試完畢後，可在「管理使用者憑證」（`certmgr.msc`）的「受信任的根憑證授權單位」與「受信任的發行者」中刪除測試憑證。

## 從原始碼建置

需要 Rust（stable）與 Windows 上的 MSVC 工具鏈。

```powershell
cargo build --release     # 產物：target\release\code-signer.exe
cargo test                # 單元 + 整合測試
cargo test -- --ignored   # 需要網路的時間戳記測試
```

## 授權

MIT 或 Apache-2.0，擇一使用。

---

<a id="english"></a>

## English

A Windows Authenticode code signing tool. One exe with both a GUI and a CLI; the interface is available in Traditional Chinese and English.

### Features

- **Sign** `.exe` `.dll` `.sys` `.ocx` `.msi` `.cab` `.cat` `.ps1` `.psm1` with SHA-256
- **Timestamp** via RFC 3161 (default `http://timestamp.digicert.com`) so signatures outlive the certificate
- **Batch** many files or whole folders; one failure does not stop the rest
- **Verify** status, signer, timestamp and certificate chain
- **Create self-signed certificates** (RSA, Code Signing EKU) as `.pfx`, optionally trusted on this PC for testing
- **Certificate sources**: a `.pfx` file or the Windows certificate store (by thumbprint)
- Calls the native Windows signing APIs — **no Windows SDK / signtool required**
- The original file is untouched if signing fails; passwords are never stored

### Download

Get `code-signer.exe` from [Releases](https://github.com/tntrock/code-signer/releases). No installation needed. Check it against the `.sha256` file on the same page.

### GUI

Double-click `code-signer.exe`.

1. **New certificate** tab: enter a name, password and output path, then click Generate. If you tick "Also trust it on this PC", Windows shows a security prompt
2. **Sign** tab: drop files or folders onto the window, pick a certificate, enter its password and click Sign
3. **Verify** tab: drop files to verify them; click a file for details

### CLI

```powershell
# Create a self-signed certificate (password from an environment variable; prompts if --password-env is omitted)
$env:PFX_PW = "your-password"
code-signer new-cert --cn "My Company Test" --out test.pfx --password-env PFX_PW

# Sign a folder recursively with a timestamp
code-signer sign .\dist -r --pfx test.pfx --password-env PFX_PW --timestamp

# Use a certificate from the Windows store
code-signer sign app.exe --thumbprint A1B2C3... --timestamp

# Verify and print JSON
code-signer verify app.exe --json
```

| Exit code | Meaning |
|---|---|
| 0 | Everything succeeded (verify: all signatures valid) |
| 1 | At least one file failed (verify: unsigned or invalid signature) |
| 2 | Argument, certificate or other setup error; no files were processed |

Language: `--lang zh-TW|en` or the `CODE_SIGNER_LANG` environment variable; defaults to the Windows display language. `--json` field names and `status` codes are always English.

### About self-signed certificates

A self-signed certificate only shows as valid on PCs that **trust it**; elsewhere Windows reports an untrusted root, and SmartScreen will not trust your program because of it. For public releases, buy a code signing certificate from a CA and sign with this tool's certificate store or `.pfx` mode.

After testing, remove the test certificate from "Trusted Root Certification Authorities" and "Trusted Publishers" in `certmgr.msc`.

### Building from source

Requires stable Rust and the MSVC toolchain on Windows.

```powershell
cargo build --release     # output: target\release\code-signer.exe
cargo test                # unit + integration tests
cargo test -- --ignored   # networked timestamp test
```

### License

Licensed under either MIT or Apache-2.0, at your option.
`````

- [ ] **Step 3: Release workflow `.github/workflows/release.yml`**

`.github/workflows/release.yml`：

````yaml
name: Release

on:
  push:
    tags: ["v*"]

permissions:
  contents: write

jobs:
  release:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Test
        run: cargo test
      - name: Build
        run: cargo build --release
      - name: Checksum
        shell: pwsh
        run: |
          $hash = (Get-FileHash target/release/code-signer.exe -Algorithm SHA256).Hash.ToLower()
          "$hash  code-signer.exe" | Out-File -Encoding ascii target/release/code-signer.exe.sha256
      - uses: softprops/action-gh-release@v2
        with:
          files: |
            target/release/code-signer.exe
            target/release/code-signer.exe.sha256
          generate_release_notes: true
````

- [ ] **Step 4: 最終驗證**

Run: `cargo fmt --check`
Expected: 無輸出

Run: `cargo clippy --all-targets -- -D warnings`
Expected: 無警告

Run: `cargo test`
Expected: lib `30 passed`、`cli` `7 passed`、`sign_verify` `6 passed; 1 ignored`

Run: `cargo test --test sign_verify -- --ignored`
Expected: `1 passed`（需要網路）

Run: `cargo build --release`
Expected: 產出 `target\release\code-signer.exe`（約 10 MB）

Run: `.\target\release\code-signer.exe --lang en --help`
Expected: 英文說明、exit code 0

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "docs: bilingual README, screenshot and release workflow

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: 發佈到 GitHub

**Files:** 無

**Interfaces:**
- Consumes: 完成並已 commit 的 `main` 分支
- Produces: 公開 repo `https://github.com/tntrock/code-signer`，CI 通過

- [ ] **Step 1: 取得使用者確認**

建立公開 repo 並推送屬於對外動作，**必須先問使用者並得到明確同意**才執行 Step 2。

- [ ] **Step 2: 建立 repo 並推送**

Run: `gh repo create tntrock/code-signer --public --source . --remote origin --description "Windows Authenticode 程式碼簽章工具（GUI + CLI，繁中 / English）" --push`
Expected: 輸出 repo URL，`main` 已推送

- [ ] **Step 3: 確認 CI**

Run: `gh run watch --exit-status $(gh run list --workflow ci.yml --limit 1 --json databaseId --jq '.[0].databaseId')`
Expected: CI 在 `windows-latest` 上通過。若失敗，用 `gh run view --log-failed` 查看並修正後重新 push。

- [ ] **Step 4:（選擇性）發佈第一版**

只有使用者要求時才做：

```bash
git tag v0.1.0
git push origin v0.1.0
```

Expected: Release workflow 建置並上傳 `code-signer.exe` 與 `.sha256`
