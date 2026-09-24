//! 驗證分頁：加入檔案後自動在背景驗證。

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};

use eframe::egui;

use super::file_list::{self, ListAction, ERR_COLOR, OK_COLOR, WARN_COLOR};
use crate::core::cert::CertSummary;
use crate::core::verify::{verify_file, VerifyReport, VerifyStatus};
use crate::core::CoreError;
use crate::i18n::{format_time, Strings};

struct Row {
    path: PathBuf,
    result: Option<Result<VerifyReport, CoreError>>,
}

/// (清單世代, 列索引, 結果)。清除清單後世代遞增，舊結果直接丟棄。
type Msg = (u64, usize, Result<VerifyReport, CoreError>);

pub struct VerifyTab {
    rows: Vec<Row>,
    selected: Option<usize>,
    generation: u64,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
}

impl Default for VerifyTab {
    fn default() -> Self {
        let (tx, rx) = channel();
        VerifyTab {
            rows: Vec::new(),
            selected: None,
            generation: 0,
            tx,
            rx,
        }
    }
}

impl VerifyTab {
    pub fn add_paths(&mut self, paths: Vec<PathBuf>, ctx: &egui::Context) {
        let new = file_list::merge_unique(self.rows.iter().map(|r| r.path.clone()), paths);
        if new.is_empty() {
            return;
        }
        let start = self.rows.len();
        self.rows
            .extend(new.iter().cloned().map(|path| Row { path, result: None }));
        let (tx, ctx, generation) = (self.tx.clone(), ctx.clone(), self.generation);
        std::thread::spawn(move || {
            for (offset, path) in new.iter().enumerate() {
                let _ = tx.send((generation, start + offset, verify_file(path)));
                ctx.request_repaint();
            }
        });
    }

    fn poll(&mut self) {
        while let Ok((generation, i, result)) = self.rx.try_recv() {
            if generation == self.generation {
                if let Some(row) = self.rows.get_mut(i) {
                    row.result = Some(result);
                }
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, t: &Strings) {
        self.poll();
        match file_list::toolbar(ui, t, true) {
            ListAction::Add(paths) => self.add_paths(paths, &ui.ctx().clone()),
            ListAction::Clear => {
                self.rows.clear();
                self.selected = None;
                self.generation += 1;
            }
            ListAction::None => {}
        }

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_height(220.0);
            egui::ScrollArea::vertical()
                .max_height(260.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    if self.rows.is_empty() {
                        file_list::empty_hint(ui, t);
                        return;
                    }
                    egui::Grid::new("verify_rows")
                        .striped(true)
                        .num_columns(4)
                        .min_col_width(80.0)
                        .show(ui, |ui| {
                            ui.strong(t.col_file);
                            ui.strong(t.col_status);
                            ui.strong(t.col_signer);
                            ui.strong(t.col_timestamp);
                            ui.end_row();
                            for (i, row) in self.rows.iter().enumerate() {
                                let name = row
                                    .path
                                    .file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_default();
                                if ui
                                    .selectable_label(self.selected == Some(i), name)
                                    .on_hover_text(row.path.display().to_string())
                                    .clicked()
                                {
                                    self.selected = Some(i);
                                }
                                match &row.result {
                                    None => {
                                        ui.weak(t.st_running);
                                        ui.label("");
                                        ui.label("");
                                    }
                                    Some(Err(e)) => {
                                        ui.colored_label(ERR_COLOR, format!("✘ {}", t.error(e)));
                                        ui.label("");
                                        ui.label("");
                                    }
                                    Some(Ok(rep)) => {
                                        let (color, mark) = match rep.status {
                                            VerifyStatus::Valid => (OK_COLOR, "✔"),
                                            VerifyStatus::UntrustedRoot => (WARN_COLOR, "⚠"),
                                            _ => (ERR_COLOR, "✘"),
                                        };
                                        ui.colored_label(
                                            color,
                                            format!("{mark} {}", t.status(&rep.status)),
                                        );
                                        ui.label(
                                            rep.signer
                                                .as_ref()
                                                .map(|s| s.subject_cn.as_str())
                                                .unwrap_or(""),
                                        );
                                        ui.label(
                                            rep.timestamp.map(format_time).unwrap_or_default(),
                                        );
                                    }
                                }
                                ui.end_row();
                            }
                        });
                });
        });

        if let Some(Some(Ok(rep))) = self
            .selected
            .and_then(|i| self.rows.get(i))
            .map(|r| r.result.as_ref())
        {
            ui.add_space(8.0);
            ui.strong(t.details);
            egui::ScrollArea::vertical()
                .id_salt("verify_details")
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("{}:", t.col_timestamp));
                        ui.label(
                            rep.timestamp
                                .map(format_time)
                                .unwrap_or_else(|| t.no_timestamp.into()),
                        );
                    });
                    for (depth, cert) in rep.chain.iter().enumerate() {
                        let title = if depth == 0 {
                            format!("{} — {}", t.col_signer, cert.subject_cn)
                        } else {
                            format!("{} {} — {}", t.chain, depth, cert.subject_cn)
                        };
                        egui::CollapsingHeader::new(title)
                            .id_salt(("chain", depth))
                            .default_open(depth == 0)
                            .show(ui, |ui| {
                                cert_details(ui, t, cert);
                            });
                    }
                });
        }
    }
}

fn cert_details(ui: &mut egui::Ui, t: &Strings, c: &CertSummary) {
    egui::Grid::new(("cert", &c.sha1))
        .num_columns(2)
        .show(ui, |ui| {
            ui.label(t.issuer);
            ui.label(&c.issuer_cn);
            ui.end_row();
            ui.label(t.valid_from);
            ui.label(format_time(c.not_before));
            ui.end_row();
            ui.label(t.valid_to);
            ui.label(format_time(c.not_after));
            ui.end_row();
            ui.label(t.sha1_thumbprint);
            ui.monospace(&c.sha1);
            ui.end_row();
            ui.label(t.sha256_thumbprint);
            ui.monospace(&c.sha256);
            ui.end_row();
        });
}
