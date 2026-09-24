//! 簽章分頁。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::sync::Arc;

use eframe::egui;

use super::file_list::{self, ListAction, ERR_COLOR, OK_COLOR};
use crate::core::batch::run_batch;
use crate::core::cert::{
    list_store_signing_certs, load_cert, CertSource, CertSummary, Secret, StoreLocation,
};
use crate::core::signer::{sign_file, SignOptions};
use crate::core::CoreError;
use crate::i18n::Strings;
use crate::settings::Settings;

enum RowState {
    Pending,
    Running,
    Done(Result<(), CoreError>),
}

struct Row {
    path: PathBuf,
    state: RowState,
}

enum Msg {
    CertLoaded,
    Started(usize),
    Finished(usize, Result<(), CoreError>),
    SetupFailed(CoreError),
    AllDone,
}

struct Worker {
    rx: Receiver<Msg>,
    cancel: Arc<AtomicBool>,
}

enum Notice {
    NeedFiles,
    NeedCert,
    Setup(CoreError),
    Summary {
        total: usize,
        ok: usize,
        failed: usize,
    },
}

pub struct SignTab {
    rows: Vec<Row>,
    use_store: bool,
    pfx_path: String,
    password: Secret,
    store_certs: Option<Result<Vec<CertSummary>, CoreError>>,
    store_thumbprint: Option<String>,
    ts_enabled: bool,
    ts_url: String,
    worker: Option<Worker>,
    notice: Option<Notice>,
}

impl SignTab {
    pub fn from_settings(s: &Settings) -> Self {
        SignTab {
            rows: Vec::new(),
            use_store: s.use_store,
            pfx_path: s
                .last_pfx
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            password: Secret::new(String::new()),
            store_certs: None,
            store_thumbprint: s.store_thumbprint.clone(),
            ts_enabled: s.timestamp_enabled,
            ts_url: s.timestamp_url.clone(),
            worker: None,
            notice: None,
        }
    }

    /// 把目前選擇寫回設定（不含密碼）。
    pub fn write_settings(&self, s: &mut Settings) {
        s.use_store = self.use_store;
        s.last_pfx =
            (!self.pfx_path.trim().is_empty()).then(|| PathBuf::from(self.pfx_path.trim()));
        s.store_thumbprint = self.store_thumbprint.clone();
        s.timestamp_enabled = self.ts_enabled;
        s.timestamp_url = self.ts_url.clone();
    }

    /// 產生憑證後帶入 .pfx 路徑。
    pub fn set_pfx(&mut self, path: PathBuf) {
        self.use_store = false;
        self.pfx_path = path.display().to_string();
        self.password.clear();
    }

    pub fn is_busy(&self) -> bool {
        self.worker.is_some()
    }

    pub fn add_paths(&mut self, paths: Vec<PathBuf>) {
        if self.is_busy() {
            return;
        }
        let new = file_list::merge_unique(self.rows.iter().map(|r| r.path.clone()), paths);
        self.rows.extend(new.into_iter().map(|path| Row {
            path,
            state: RowState::Pending,
        }));
    }

    fn poll(&mut self) {
        let Some(worker) = &self.worker else { return };
        let mut finished = false;
        loop {
            match worker.rx.try_recv() {
                Ok(Msg::CertLoaded) => {
                    for row in &mut self.rows {
                        row.state = RowState::Pending;
                    }
                }
                Ok(Msg::Started(i)) => self.rows[i].state = RowState::Running,
                Ok(Msg::Finished(i, r)) => self.rows[i].state = RowState::Done(r),
                Ok(Msg::SetupFailed(e)) => {
                    self.notice = Some(Notice::Setup(e));
                    finished = true;
                }
                Ok(Msg::AllDone) => {
                    finished = true;
                }
                Err(TryRecvError::Empty) => break,
                // 工作執行緒中斷卻沒送出任何結果（例如 dev build 下 panic）：
                // 視為結束，避免 UI 永遠卡在忙碌狀態。
                Err(TryRecvError::Disconnected) => {
                    finished = true;
                    break;
                }
            }
        }
        if finished {
            self.worker = None;
            // 取消時尚未處理的列回到「等待中」
            for row in &mut self.rows {
                if matches!(row.state, RowState::Running) {
                    row.state = RowState::Pending;
                }
            }
            if !matches!(self.notice, Some(Notice::Setup(_))) {
                let done: Vec<_> = self
                    .rows
                    .iter()
                    .filter_map(|r| match &r.state {
                        RowState::Done(res) => Some(res.is_ok()),
                        _ => None,
                    })
                    .collect();
                let ok = done.iter().filter(|b| **b).count();
                self.notice = Some(Notice::Summary {
                    total: done.len(),
                    ok,
                    failed: done.len() - ok,
                });
            }
        }
    }

    fn cert_source(&self) -> Option<CertSource> {
        if self.use_store {
            self.store_thumbprint
                .clone()
                .map(|thumbprint| CertSource::Store {
                    thumbprint,
                    location: StoreLocation::CurrentUser,
                })
        } else if self.pfx_path.trim().is_empty() {
            None
        } else {
            Some(CertSource::Pfx {
                path: PathBuf::from(self.pfx_path.trim()),
                password: self.password.clone(),
            })
        }
    }

    /// 開始簽章；回傳 true 表示設定有變動、應儲存。
    fn start(&mut self, ctx: &egui::Context) -> bool {
        if self.rows.is_empty() {
            self.notice = Some(Notice::NeedFiles);
            return false;
        }
        let Some(source) = self.cert_source() else {
            self.notice = Some(Notice::NeedCert);
            return false;
        };
        self.notice = None;
        let paths: Vec<PathBuf> = self.rows.iter().map(|r| r.path.clone()).collect();
        let opts = SignOptions {
            timestamp_url: (self.ts_enabled && !self.ts_url.trim().is_empty())
                .then(|| self.ts_url.trim().to_string()),
        };
        let (tx, rx) = channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_flag = cancel.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            // LoadedCert 不可跨執行緒，因此在工作執行緒內載入
            let cert = match load_cert(&source) {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Msg::SetupFailed(e));
                    ctx.request_repaint();
                    return;
                }
            };
            let _ = tx.send(Msg::CertLoaded);
            ctx.request_repaint();
            let mut next = 0usize;
            run_batch(
                &paths,
                &cancel_flag,
                |p| {
                    let _ = tx.send(Msg::Started(next));
                    ctx.request_repaint();
                    next += 1;
                    sign_file(p, &cert, &opts)
                },
                |i, r| {
                    let _ = tx.send(Msg::Finished(i, r.result.clone()));
                    ctx.request_repaint();
                },
            );
            let _ = tx.send(Msg::AllDone);
            ctx.request_repaint();
        });
        self.worker = Some(Worker { rx, cancel });
        true
    }

    fn refresh_store(&mut self) {
        let list = list_store_signing_certs(StoreLocation::CurrentUser);
        if let Ok(certs) = &list {
            let still_there = self
                .store_thumbprint
                .as_ref()
                .is_some_and(|t| certs.iter().any(|c| &c.sha1 == t));
            if !still_there {
                self.store_thumbprint = certs.first().map(|c| c.sha1.clone());
            }
        }
        self.store_certs = Some(list);
    }

    /// 繪製分頁；回傳 true 表示設定有變動、應儲存。
    pub fn ui(&mut self, ui: &mut egui::Ui, t: &Strings) -> bool {
        self.poll();
        let busy = self.is_busy();
        let mut settings_changed = false;

        match file_list::toolbar(ui, t, !busy) {
            ListAction::Add(paths) => self.add_paths(paths),
            ListAction::Clear => {
                self.rows.clear();
                self.notice = None;
            }
            ListAction::None => {}
        }

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_height(180.0);
            egui::ScrollArea::vertical()
                .max_height(220.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    if self.rows.is_empty() {
                        file_list::empty_hint(ui, t);
                        return;
                    }
                    egui::Grid::new("sign_rows")
                        .striped(true)
                        .num_columns(2)
                        .min_col_width(120.0)
                        .show(ui, |ui| {
                            ui.strong(t.col_file);
                            ui.strong(t.col_status);
                            ui.end_row();
                            for row in &self.rows {
                                ui.label(row.path.display().to_string());
                                match &row.state {
                                    RowState::Pending => ui.weak(t.st_pending),
                                    RowState::Running => ui.label(t.st_running),
                                    RowState::Done(Ok(())) => {
                                        ui.colored_label(OK_COLOR, format!("✔ {}", t.st_signed))
                                    }
                                    RowState::Done(Err(e)) => {
                                        ui.colored_label(ERR_COLOR, format!("✘ {}", t.error(e)))
                                    }
                                };
                                ui.end_row();
                            }
                        });
                });
        });

        ui.add_space(8.0);
        ui.add_enabled_ui(!busy, |ui| {
            egui::Grid::new("sign_opts")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label(t.cert_source);
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.use_store, false, t.cert_pfx);
                        if ui
                            .radio_value(&mut self.use_store, true, t.cert_store)
                            .clicked()
                            && self.store_certs.is_none()
                        {
                            self.refresh_store();
                        }
                    });
                    ui.end_row();

                    if self.use_store {
                        ui.label("");
                        ui.horizontal(|ui| {
                            if self.store_certs.is_none() {
                                self.refresh_store();
                            }
                            match &self.store_certs {
                                Some(Ok(certs)) if !certs.is_empty() => {
                                    let label = |c: &CertSummary| {
                                        format!(
                                            "{} ({}…) — {}",
                                            c.subject_cn,
                                            &c.sha1[..8],
                                            crate::i18n::format_time(c.not_after)
                                        )
                                    };
                                    let selected = self
                                        .store_thumbprint
                                        .as_ref()
                                        .and_then(|t| certs.iter().find(|c| &c.sha1 == t))
                                        .map(label)
                                        .unwrap_or_default();
                                    egui::ComboBox::from_id_salt("store_cert")
                                        .width(420.0)
                                        .selected_text(selected)
                                        .show_ui(ui, |ui| {
                                            for c in certs {
                                                ui.selectable_value(
                                                    &mut self.store_thumbprint,
                                                    Some(c.sha1.clone()),
                                                    label(c),
                                                );
                                            }
                                        });
                                }
                                Some(Ok(_)) => {
                                    ui.weak(t.no_store_certs);
                                }
                                Some(Err(e)) => {
                                    ui.colored_label(ERR_COLOR, t.error(e));
                                }
                                None => {}
                            }
                            if ui.button(t.refresh).clicked() {
                                self.refresh_store();
                            }
                        });
                        ui.end_row();
                    } else {
                        ui.label("");
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.pfx_path).desired_width(360.0),
                            );
                            if ui.button(t.browse).clicked() {
                                if let Some(p) = rfd::FileDialog::new()
                                    .add_filter("PFX", &["pfx", "p12"])
                                    .pick_file()
                                {
                                    self.pfx_path = p.display().to_string();
                                }
                            }
                            ui.label(t.password);
                            ui.add(
                                egui::TextEdit::singleline(&mut *self.password)
                                    .password(true)
                                    .desired_width(140.0),
                            );
                        });
                        ui.end_row();
                    }

                    ui.checkbox(&mut self.ts_enabled, t.timestamp);
                    ui.add_enabled(
                        self.ts_enabled,
                        egui::TextEdit::singleline(&mut self.ts_url).desired_width(360.0),
                    );
                    ui.end_row();
                });
        });

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let total = self.rows.len();
            let done = self
                .rows
                .iter()
                .filter(|r| matches!(r.state, RowState::Done(_)))
                .count();
            let fraction = if total == 0 {
                0.0
            } else {
                done as f32 / total as f32
            };
            ui.add(
                egui::ProgressBar::new(fraction)
                    .text(t.progress(done, total))
                    .desired_width(ui.available_width() - 130.0),
            );
            if let Some(w) = &self.worker {
                if ui.button(t.cancel).clicked() {
                    w.cancel.store(true, Ordering::Relaxed);
                }
            } else if ui
                .button(egui::RichText::new(t.start_sign).strong())
                .clicked()
            {
                settings_changed = self.start(ui.ctx());
            }
        });

        match &self.notice {
            Some(Notice::NeedFiles) => {
                ui.colored_label(ERR_COLOR, t.need_files);
            }
            Some(Notice::NeedCert) => {
                ui.colored_label(ERR_COLOR, t.need_cert);
            }
            Some(Notice::Setup(e)) => {
                ui.colored_label(ERR_COLOR, format!("✘ {}", t.error(e)));
            }
            Some(Notice::Summary { total, ok, failed }) => {
                let color = if *failed == 0 { OK_COLOR } else { ERR_COLOR };
                ui.colored_label(color, t.summary(*total, *ok, *failed));
            }
            None => {}
        }
        settings_changed
    }
}
