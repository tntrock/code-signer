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
