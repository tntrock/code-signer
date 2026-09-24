//! code-signer 進入點（暫時只有 CLI）。

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    std::process::exit(code_signer::cli::run(args));
}
