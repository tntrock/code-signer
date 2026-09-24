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
