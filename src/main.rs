//! code-signer 進入點：不帶參數開 GUI，帶參數走 CLI。

use std::ffi::OsString;
use std::process::ExitCode;

// 用回傳 ExitCode 而非 std::process::exit：後者在 Windows 直接呼叫 ExitProcess，
// 不會跑 atexit，覆蓋率資料（以及解構子）就不會寫出。
fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let code = if args.len() <= 1 {
        detach_console_if_owned();
        match code_signer::gui::run() {
            Ok(()) => code_signer::cli::EXIT_OK,
            Err(e) => {
                eprintln!("{e}");
                code_signer::cli::EXIT_SETUP_FAILED
            }
        }
    } else {
        code_signer::cli::run(args)
    };
    ExitCode::from(code as u8)
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
