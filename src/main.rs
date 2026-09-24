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
