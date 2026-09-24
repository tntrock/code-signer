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
