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
