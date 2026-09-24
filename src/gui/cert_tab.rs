//! 產生憑證分頁。

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};

use eframe::egui;

use super::file_list::{ERR_COLOR, OK_COLOR, WARN_COLOR};
use crate::core::cert::{
    create_self_signed, install_trust, CreatedCert, NewCertParams, RsaBits, Secret, VALIDITY_YEARS,
};
use crate::core::CoreError;
use crate::i18n::Strings;

struct Outcome {
    created: Result<CreatedCert, CoreError>,
    trust: Option<Result<(), CoreError>>,
    path: PathBuf,
}

enum Notice {
    PasswordMismatch,
    ConfirmOverwrite,
    Done(Box<Outcome>),
}

pub struct CertTab {
    cn: String,
    org: String,
    years: u32,
    key_bits: RsaBits,
    out_path: String,
    pw1: String,
    pw2: String,
    install_trust: bool,
    worker: Option<Receiver<Outcome>>,
    notice: Option<Notice>,
}

impl Default for CertTab {
    fn default() -> Self {
        CertTab {
            cn: String::new(),
            org: String::new(),
            years: 3,
            key_bits: RsaBits::B3072,
            out_path: String::new(),
            pw1: String::new(),
            pw2: String::new(),
            install_trust: false,
            worker: None,
            notice: None,
        }
    }
}

impl CertTab {
    fn start(&mut self, ctx: &egui::Context, overwrite: bool) {
        if self.pw1 != self.pw2 {
            self.notice = Some(Notice::PasswordMismatch);
            return;
        }
        let path = PathBuf::from(self.out_path.trim());
        if path.exists() && !overwrite {
            self.notice = Some(Notice::ConfirmOverwrite);
            return;
        }
        self.notice = None;
        let params = NewCertParams {
            common_name: self.cn.clone(),
            organization: Some(self.org.clone()),
            validity_years: self.years,
            key_bits: self.key_bits,
            out_path: path.clone(),
            password: Secret::new(self.pw1.clone()),
            overwrite,
        };
        let want_trust = self.install_trust;
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let created = create_self_signed(&params);
            let trust = match (&created, want_trust) {
                (Ok(c), true) => Some(install_trust(&c.der)),
                _ => None,
            };
            let _ = tx.send(Outcome {
                created,
                trust,
                path,
            });
            ctx.request_repaint();
        });
        self.worker = Some(rx);
    }

    /// 繪製分頁；成功產生憑證時回傳其路徑，讓簽章分頁帶入。
    pub fn ui(&mut self, ui: &mut egui::Ui, t: &Strings) -> Option<PathBuf> {
        let mut created_path = None;
        if let Some(rx) = &self.worker {
            if let Ok(outcome) = rx.try_recv() {
                self.worker = None;
                if outcome.created.is_ok() {
                    created_path = Some(outcome.path.clone());
                    self.pw1.clear();
                    self.pw2.clear();
                }
                self.notice = Some(Notice::Done(Box::new(outcome)));
            }
        }
        let busy = self.worker.is_some();

        ui.add_enabled_ui(!busy, |ui| {
            egui::Grid::new("cert_form")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(t.cn);
                    ui.add(egui::TextEdit::singleline(&mut self.cn).desired_width(320.0));
                    ui.end_row();

                    ui.label(t.org_optional);
                    ui.add(egui::TextEdit::singleline(&mut self.org).desired_width(320.0));
                    ui.end_row();

                    ui.label(t.validity);
                    egui::ComboBox::from_id_salt("years")
                        .selected_text(t.years(self.years))
                        .show_ui(ui, |ui| {
                            for y in VALIDITY_YEARS {
                                ui.selectable_value(&mut self.years, y, t.years(y));
                            }
                        });
                    ui.end_row();

                    ui.label(t.key_size);
                    egui::ComboBox::from_id_salt("key_bits")
                        .selected_text(format!("RSA {}", self.key_bits.bits()))
                        .show_ui(ui, |ui| {
                            for b in RsaBits::ALL {
                                ui.selectable_value(
                                    &mut self.key_bits,
                                    b,
                                    format!("RSA {}", b.bits()),
                                );
                            }
                        });
                    ui.end_row();

                    ui.label(t.out_path);
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut self.out_path).desired_width(320.0));
                        if ui.button(t.browse).clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("PFX", &["pfx"])
                                .set_file_name("code-signing.pfx")
                                .save_file()
                            {
                                self.out_path = p.display().to_string();
                            }
                        }
                    });
                    ui.end_row();

                    ui.label(t.password);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pw1)
                            .password(true)
                            .desired_width(200.0),
                    );
                    ui.end_row();

                    ui.label(t.confirm_password);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pw2)
                            .password(true)
                            .desired_width(200.0),
                    );
                    ui.end_row();
                });

            ui.add_space(6.0);
            ui.checkbox(&mut self.install_trust, t.install_trust);
            if self.install_trust {
                ui.colored_label(WARN_COLOR, t.install_trust_note);
            }
            ui.add_space(6.0);
            let can_generate = !self.cn.trim().is_empty()
                && !self.out_path.trim().is_empty()
                && !self.pw1.is_empty();
            let label = if busy { t.generating } else { t.generate };
            if ui
                .add_enabled(
                    can_generate,
                    egui::Button::new(egui::RichText::new(label).strong()),
                )
                .clicked()
            {
                self.start(ui.ctx(), false);
            }
        });

        let mut overwrite_choice = None;
        match &self.notice {
            Some(Notice::PasswordMismatch) => {
                ui.colored_label(ERR_COLOR, t.password_mismatch);
            }
            Some(Notice::ConfirmOverwrite) => {
                ui.horizontal(|ui| {
                    ui.colored_label(WARN_COLOR, t.overwrite_confirm);
                    if ui.button(t.yes).clicked() {
                        overwrite_choice = Some(true);
                    }
                    if ui.button(t.no).clicked() {
                        overwrite_choice = Some(false);
                    }
                });
            }
            Some(Notice::Done(o)) => match &o.created {
                Err(e) => {
                    ui.colored_label(ERR_COLOR, format!("✘ {}", t.error(e)));
                }
                Ok(c) => {
                    ui.colored_label(
                        OK_COLOR,
                        format!("✔ {} — {}", t.cert_created, o.path.display()),
                    );
                    ui.monospace(format!("SHA-1 {}", c.summary.sha1));
                    match &o.trust {
                        Some(Ok(())) => {
                            ui.colored_label(OK_COLOR, format!("✔ {}", t.trust_installed));
                        }
                        Some(Err(e)) => {
                            ui.colored_label(
                                ERR_COLOR,
                                format!("✘ {}: {}", t.trust_failed, t.error(e)),
                            );
                        }
                        None => {}
                    }
                }
            },
            None => {}
        }
        match overwrite_choice {
            Some(true) => self.start(ui.ctx(), true),
            Some(false) => self.notice = None,
            None => {}
        }
        created_path
    }
}
