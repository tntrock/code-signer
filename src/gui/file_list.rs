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
