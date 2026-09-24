# code-signer 設計文件

- 日期：2026-09-24
- 狀態：已核准（2026-09-24）；介面細節以實作計畫 `docs/superpowers/plans/2026-09-24-code-signer.md` 為準
- Repo：`tntrock/code-signer`（公開）
- 本機路徑：`D:\VSCode\code-signer`

## 1. 目標與範圍

一個 Windows 用的 Authenticode 程式碼簽章工具，單一 exe，同時提供 GUI 與 CLI，介面可切換繁體中文 / English。

### 第一版功能

| 功能 | 說明 |
|------|------|
| 簽章 | 對 PE / MSI / CAB / CAT / PowerShell 腳本做 Authenticode 簽章，SHA-256 |
| 時間戳記 | 可選 RFC 3161 時間戳記伺服器 |
| 批次 | 一次處理多個檔案或資料夾（可遞迴） |
| 驗證 | 檢查簽章狀態、簽章者、時間戳記、憑證鏈 |
| 產生自簽憑證 | 產生帶程式碼簽章 EKU 的 RSA 憑證並匯出 `.pfx`，可選擇匯入目前使用者信任清單 |
| 雙語介面 | 繁體中文 / English，GUI 即時切換，CLI 以參數或環境變數指定 |

### 不在第一版範圍

- 分離式簽章（`.sig`）、GPG、minisign
- MSIX / APPX 簽章（需另一套流程與發行者比對）
- 雙重簽章（在既有簽章上附加簽章）；重新簽章一律取代既有簽章
- 非 Windows 平台
- 儲存密碼

## 2. 技術選型

| 項目 | 選擇 | 理由 |
|------|------|------|
| 語言 | Rust（edition 2021） | 與 `cert-converter`、`file-crypto` 一致 |
| GUI | `eframe` / `egui` | 同上；原生支援拖放；單一小 exe |
| 檔案對話框 | `rfd` | 同上 |
| CLI | `clap`（derive） | 標準做法 |
| Win32 API | `windows` crate | 官方型別綁定：`SignerSignEx2`、`WinVerifyTrust`、CryptoAPI 憑證存放區 |
| 產生憑證 | `rsa` + `rcgen` + `p12-keystore` | 純 Rust：`rsa` 產生 RSA 金鑰（`rcgen` 預設後端 ring 無法產生 RSA 金鑰，而 aws-lc-rs 後端在 Windows 需 cmake/nasm），`rcgen` 簽出 X.509，`p12-keystore` 匯出 PKCS#12；`rsa` 與 `p12-keystore` 皆已用於 `cert-converter` |
| 其他 | `serde` / `serde_json`（設定檔、`--json`）、`thiserror`（core 錯誤）、`x509-parser` + `sha1`/`sha2`（憑證摘要與指紋）、`zeroize`（密碼）、`rpassword`（CLI 密碼輸入） | |

簽章與驗證**直接呼叫 Windows 原生 API**，不依賴 PowerShell 或 Windows SDK 的 `signtool`。

建置設定沿用既有專案：release profile `opt-level = "z"`、`lto`、`codegen-units = 1`、`strip`、`panic = "abort"`；`build.rs` 以 `winresource` 嵌入圖示與版本資訊。

## 3. 架構

### 3.1 執行模式

同一個 `code-signer.exe`：

- 無參數 → 開啟 GUI
- 帶子指令（`sign` / `verify` / `new-cert`）→ CLI 模式

exe 編譯為主控台子系統（console subsystem），確保 CLI 輸出與 exit code 可靠。以 GUI 模式啟動時，若主控台是專為本程序建立的（`GetConsoleProcessList` 回傳的程序數為 1，代表從檔案總管雙擊啟動），就以 `FreeConsole` 釋放它，避免留下空白的主控台視窗；若是從既有終端機執行，則保留。

### 3.2 模組

```
src/
  main.rs        進入點：解析參數 → CLI 或 GUI；主控台處理
  cli.rs         clap 定義、文字 / JSON 輸出、exit code
  i18n.rs        語言列舉、Strings 結構、ZH_TW / EN、系統語言偵測
  settings.rs    %APPDATA%\code-signer\settings.json 讀寫
  core/
    mod.rs
    error.rs     CoreError 列舉與 HRESULT 對應
    cert.rs      載入憑證、列出存放區憑證、產生自簽憑證、匯入信任清單
    signer.rs    單檔簽章（暫存檔 → 簽章 → 取代）
    verify.rs    單檔驗證並產生 VerifyReport
    batch.rs     展開路徑、過濾副檔名、逐檔執行並回報進度
  gui/
    mod.rs
    app.rs       分頁框架、語言選單、字型載入
    sign_tab.rs
    verify_tab.rs
    cert_tab.rs
```

原則：**`core/` 不依賴 CLI、GUI 或 i18n**。它只接收參數、回傳結構化結果與 `CoreError`；轉成使用者可讀的文字由外層負責。

### 3.3 核心介面（示意）

```rust
pub enum CertSource {
    Pfx { path: PathBuf, password: SecretString },
    Store { thumbprint: String, location: StoreLocation }, // CurrentUser | LocalMachine
}

pub struct SignOptions {
    pub timestamp_url: Option<String>,
}

pub struct LoadedCert { /* 持有 CERT_CONTEXT 與私鑰，Drop 時釋放 */ }

pub fn load_cert(src: &CertSource) -> Result<LoadedCert, CoreError>;
pub fn list_store_signing_certs(loc: StoreLocation) -> Result<Vec<CertSummary>, CoreError>;
pub fn sign_file(path: &Path, cert: &LoadedCert, opts: &SignOptions) -> Result<(), CoreError>;
pub fn verify_file(path: &Path) -> Result<VerifyReport, CoreError>;

pub struct NewCertParams {
    pub common_name: String,
    pub organization: Option<String>,
    pub validity_years: u32,   // 1..=10
    pub key_bits: RsaBits,     // 2048 | 3072 | 4096
    pub out_path: PathBuf,
    pub password: SecretString,
}
pub fn create_self_signed(p: &NewCertParams) -> Result<CreatedCert, CoreError>; // CreatedCert { summary, der }
pub fn install_trust(cert_der: &[u8]) -> Result<(), CoreError>; // CurrentUser Root + TrustedPublisher

// 資料夾展開並排序；其他路徑原樣保留，錯誤由後續操作逐檔回報
pub fn expand_paths(inputs: &[PathBuf], recursive: bool) -> Vec<PathBuf>;
pub fn run_batch<T>(files: &[PathBuf], cancel: &AtomicBool,
    op: impl FnMut(&Path) -> Result<T, CoreError>,
    on_result: impl FnMut(usize, &FileResult<T>)) -> Vec<FileResult<T>>;
```

`VerifyReport`：

```rust
pub struct VerifyReport {
    pub status: VerifyStatus,          // Valid | Unsigned | Tampered | UntrustedRoot
                                       // | Expired | Distrusted | Other(hresult)
    pub signer: Option<CertSummary>,   // CN、O、指紋(SHA-1/SHA-256)、有效期間
    pub timestamp: Option<DateTime>,   // 時間戳記時間
    pub chain: Vec<CertSummary>,
}
```

## 4. 行為細節

### 4.1 簽章流程（單檔）

1. 確認副檔名受支援
2. 在同一資料夾複製成暫存檔 `.<原檔名>.code-signer-tmp`
3. 對暫存檔呼叫 `SignerSignEx2`：SHA-256、`SIGNER_CERT_STORE_INFO` 帶入憑證；若有時間戳記 URL，使用 `SIGNER_TIMESTAMP_RFC3161` 與 SHA-256
4. 成功 → 以 `std::fs::rename` 取代原檔（在 Windows 上即 `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`）
5. 任何一步失敗 → 刪除暫存檔，原檔不變，回傳錯誤

時間戳記失敗視為簽章失敗，不會退回成無時間戳記的簽章。

### 4.2 批次

- 憑證在處理任何檔案**之前**載入並檢查（密碼、私鑰、程式碼簽章 EKU、有效期限）。失敗即整批中止（CLI exit code 2）
- 檔案層級錯誤只影響該檔案，其餘繼續處理
- 資料夾展開時只收以下副檔名（不分大小寫）：`.exe .dll .sys .ocx .msi .cab .cat .ps1 .psm1`；直接指定的檔案若副檔名不支援，回報為該檔案錯誤
- 依序處理（不平行），避免同一資料夾內同時寫檔與時間戳記伺服器限流
- 每處理完一個檔案呼叫 `on_result(索引, FileResult)`；GUI 在工作執行緒中把它轉成 channel 訊息

### 4.3 驗證

`WinVerifyTrust`（`WINTRUST_ACTION_GENERIC_VERIFY_V2`、`WTD_REVOKE_NONE`、`WTD_UI_NONE`）判定狀態，並從 `WTHelperProvDataFromStateData` 取得簽章者、憑證鏈與時間戳記。預設不做線上撤銷檢查，避免離線時驗證卡住。

| Windows 結果 | VerifyStatus |
|---|---|
| `ERROR_SUCCESS` | `Valid` |
| `TRUST_E_NOSIGNATURE`、`TRUST_E_SUBJECT_FORM_UNKNOWN`（且檔案可簽） | `Unsigned` |
| `TRUST_E_BAD_DIGEST` | `Tampered` |
| `CERT_E_UNTRUSTEDROOT`、`CERT_E_CHAINING` | `UntrustedRoot` |
| `CERT_E_EXPIRED`（且無有效時間戳記） | `Expired` |
| `TRUST_E_EXPLICIT_DISTRUST` | `Distrusted` |
| 其他 | `Other(hresult)` |

### 4.4 產生自簽憑證

- `rsa` 產生 RSA 金鑰，轉成 PKCS#8 後交給 `rcgen` 產生憑證：Subject = CN（+ 選填 O）；EKU = Code Signing（1.3.6.1.5.5.7.3.3）；KeyUsage = digitalSignature；BasicConstraints CA=false；有效期間 = 現在起 N 年
- `p12-keystore` 匯出為密碼保護的 `.pfx`，採用該 crate 支援、且 Windows `PFXImportCertStore` 能讀取的最強加密（優先 AES-256 / PBKDF2-SHA256）；整合測試會以 `load_cert` 讀回確認相容
- 密碼至少 8 字元，需輸入兩次確認（GUI）或提示兩次（CLI）
- 輸出檔已存在時：GUI 詢問是否覆寫；CLI 需加 `--force`，否則回報錯誤
- 選擇「匯入信任清單」時：以 `CertAddCertificateContextToStore` 把**公開憑證**（不含私鑰）加入 CurrentUser 的 `Root` 與 `TrustedPublisher`。加入 `Root` 時 Windows 會跳出確認視窗；使用者拒絕時回報為「使用者取消」，並保留已產生的 `.pfx`

### 4.5 憑證存放區清單

列出指定位置 `My` 存放區中，同時符合「有私鑰」「EKU 含 Code Signing（或未限制 EKU）」「目前在有效期間內」的憑證，顯示為 `CN (指紋前 8 碼) — 到期日`。

## 5. CLI

```
code-signer sign <PATH>... (--pfx <FILE> | --thumbprint <HEX>) [OPTIONS]
    --store <user|machine>     搭配 --thumbprint，預設 user
    --password-env <VAR>       從環境變數讀取 .pfx 密碼
    --timestamp [<URL>]        加時間戳記；未帶 URL 用預設 http://timestamp.digicert.com
    -r, --recursive

code-signer verify <PATH>... [-r]

code-signer new-cert --cn <NAME> --out <FILE.pfx>
    [--org <ORG>] [--years <1-10>，預設 3] [--key-size <2048|3072|4096>，預設 3072]
    [--password-env <VAR>] [--install-trust] [--force]

全域：--json、--lang <zh-TW|en>
```

- 不提供 `--password <明文>`。未指定 `--password-env` 時以 `rpassword` 提示輸入
- Exit code：`0` 全部成功；`1` 至少一個檔案失敗（verify：有非 `Valid` 的檔案）；`2` 參數、憑證或其他前置錯誤
- 文字輸出每檔一行：`✔ / ✘  路徑  訊息`，最後一行為摘要
- `--json`：輸出單一 JSON 物件，欄位名稱與 `status` 代碼固定為英文，另附翻譯過的 `message`：

```json
{
  "command": "verify",
  "results": [
    { "path": "D:\\build\\app.exe", "ok": false, "status": "untrusted_root",
      "message": "根憑證不受信任 — Allen Test",
      "signer": { "subject_cn": "Allen Test", "organization": null, "issuer_cn": "Allen Test",
                  "sha1": "…", "sha256": "…", "not_before": 1790000000, "not_after": 1884000000 },
      "timestamp": "2026-09-24 10:00:00 UTC" }
  ],
  "summary": { "total": 1, "succeeded": 0, "failed": 1 }
}
```

## 6. GUI

視窗頂端：三個分頁「簽章 / 驗證 / 產生憑證」；右上角語言下拉選單。

### 6.1 簽章分頁

- 檔案清單：拖放、「加入檔案」「加入資料夾」（遞迴）、「清除」；每列顯示路徑與狀態（等待中 / 處理中 / ✔ / ✘ + 訊息）
- 憑證：單選「.pfx 檔（路徑 + 瀏覽 + 密碼）」或「憑證存放區（下拉選單 + 重新整理）」
- 時間戳記：勾選框 + URL 欄位
- 進度條與「開始簽章」按鈕；執行中停用輸入，改為可「取消」（處理完目前這個檔案後停止）

### 6.2 驗證分頁

- 同樣的檔案清單操作；加入後自動驗證
- 表格欄位：檔案、狀態、簽章者、時間戳記；點選一列展開詳細資訊（SHA-1 / SHA-256 指紋、有效期間、憑證鏈）

### 6.3 產生憑證分頁

- 欄位：名稱（CN，必填）、組織（選填）、有效期限（1/2/3/5/10 年，預設 3）、金鑰長度（2048/3072/4096，預設 3072）、輸出路徑、密碼 ×2、「同時匯入本機信任清單（僅目前使用者，測試用）」
- 成功後自動把 `.pfx` 路徑帶入簽章分頁

### 6.4 其他

- 簽章、驗證、產生憑證都在背景執行緒進行，UI 以 channel 接收結果並 `request_repaint`
- 字型：執行時依序嘗試載入 `msjh.ttc`、`msjhl.ttc`、`mingliu.ttc`、`msyh.ttc`、`simsun.ttc`，作為 CJK 備援字型（沿用 `cert-converter` 做法）
- `settings.json` 儲存：語言、上次的 `.pfx` 路徑、上次的憑證來源、時間戳記 URL 與勾選狀態。**不儲存密碼**。檔案損毀或不存在時使用預設值

## 7. 多語系

- `i18n.rs`：`enum Lang { ZhTw, En }`；`struct Strings { … }`，每個介面字串為一個 `&'static str` 欄位；`const ZH_TW: Strings`、`const EN: Strings`。缺翻譯時編譯失敗
- 帶參數的訊息以方法實作（例如 `fn progress(&self, done: usize, total: usize) -> String`）
- `CoreError` / `VerifyStatus` 轉文字的函式放在 `i18n.rs`，依語言回傳
- 預設語言：`GetUserDefaultUILanguage` 為 zh-TW / zh-HK / zh-MO → 繁中，否則 English
- 語言優先順序：CLI 為 `--lang` > `CODE_SIGNER_LANG` > 系統；GUI 為 `settings.json` > 系統
- clap 的 `--help` 文字由 `Strings` 產生（以 builder 在執行時設定 `about` / `help`），隨語言切換

## 8. 錯誤處理

`CoreError`（`thiserror`）至少包含：

| 變體 | 情境 |
|---|---|
| `PfxWrongPassword` | `.pfx` 密碼錯誤 |
| `PfxInvalid` | 檔案不是有效的 PKCS#12 |
| `PfxNoSigningCert` | `.pfx` 中沒有含私鑰的憑證 |
| `InvalidThumbprint` | 指紋不是 40 個十六進位字元 |
| `CertNotFound` | 存放區找不到指定指紋 |
| `CertNoPrivateKey` | 憑證沒有私鑰 |
| `CertNotCodeSigning` | EKU 不含 Code Signing |
| `CertExpired` / `CertNotYetValid` | 不在有效期間 |
| `FileNotFound` / `FileInUse` / `AccessDenied` | 檔案層級 I/O |
| `UnsupportedFileType` | 副檔名或格式不支援簽章 |
| `TimestampFailed` | 時間戳記伺服器無法連線或回應錯誤 |
| `UserCancelled` | 使用者拒絕信任清單確認視窗 |
| `OutputExists` | 產生憑證時輸出檔已存在且未允許覆寫 |
| `EmptyCommonName` / `PasswordTooShort` / `InvalidValidity` | 產生憑證的輸入檢查 |
| `Win32 { hresult, message }` | 其他：顯示 `0x%08X` 與系統訊息（`FormatMessageW`） |

Win32 資源（`CERT_CONTEXT`、`HCERTSTORE`、WinTrust 狀態）以 RAII 包裝，在 `Drop` 中釋放。所有 `unsafe` 集中在 `core/` 內的小函式，並附上前置條件註解。

## 9. 測試

- **單元測試**：`expand_paths` 與副檔名過濾、HRESULT → `CoreError` 對應、`VerifyStatus` 對應、CLI 參數解析、`settings.json` 損毀時的預設值、兩種語言 `Strings` 皆可建構
- **整合測試**（`tests/`，僅 Windows）：
  1. 在暫存資料夾以 `create_self_signed` 產生 `.pfx`
  2. 複製測試執行檔本身（`std::env::current_exe()`）作為簽章樣本
  3. `sign_file` 成功；`verify_file` 回報 `UntrustedRoot`，簽章者 CN 與指紋正確（不修改系統信任清單）
  4. 修改已簽檔案的一個 byte → `verify_file` 回報 `Tampered`
  5. 錯誤密碼 → `PfxWrongPassword`，樣本檔內容與簽章前完全相同
  6. 未簽樣本 → `Unsigned`
  7. 時間戳記測試需連網，標記 `#[ignore]`
- **CLI 測試**：以 `std::process::Command` 執行 `CARGO_BIN_EXE_code-signer`，檢查 exit code 0 / 1 / 2 與 `--json` 結構
- **GUI**：手動檢查三個分頁、拖放、語言切換、雙擊啟動時沒有主控台殘留

## 10. Repo 與 CI

- 授權：`MIT OR Apache-2.0`（`LICENSE-MIT`、`LICENSE-APACHE`）
- `README.md`：單一檔案，中文在上、英文在下；內容包含功能、下載、GUI 截圖、CLI 用法、自簽憑證的限制說明（只在信任該憑證的電腦上有效，SmartScreen 不會因此信任）
- `.gitignore`：`/target`（`Cargo.lock` 納入版控，因為這是執行檔專案）
- GitHub Actions（`windows-latest`）：
  - `ci.yml`：push / PR 時執行 `cargo fmt --check`、`cargo clippy -- -D warnings`、`cargo test`
  - `release.yml`：推送 `v*` 標籤時建置 release 版，並把 `code-signer.exe` 與 SHA-256 雜湊檔上傳到 GitHub Release
