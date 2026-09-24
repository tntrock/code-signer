//! 核心邏輯：不依賴 CLI、GUI 或 i18n，只回傳結構化結果與 `CoreError`。

pub mod batch;
pub mod cert;
pub mod error;

pub use error::CoreError;
