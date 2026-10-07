#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use ccitocia::{Progress, Stage, Summary};
use eframe::egui;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

const INITIAL: Progress = Progress {
    stage: Stage::Validating,
    bytes_written: 0,
    total_bytes: 0,
};

struct Job {
    progress: Arc<Mutex<Progress>>,
    result: mpsc::Receiver<Result<Summary, String>>,
}

impl Job {
    fn start(input: PathBuf, output: PathBuf, ctx: egui::Context) -> std::io::Result<Self> {
        let progress = Arc::new(Mutex::new(INITIAL));
        let latest = Arc::clone(&progress);
        let (sender, result) = mpsc::channel();
        std::thread::Builder::new()
            .name("cia-conversion".into())
            .spawn(move || {
                let mut last_repaint = Instant::now();
                let result = ccitocia::convert_with_progress(&input, &output, |update| {
                    *latest.lock().unwrap_or_else(|e| e.into_inner()) = update;
                    if last_repaint.elapsed() >= Duration::from_millis(50) {
                        ctx.request_repaint();
                        last_repaint = Instant::now();
                    }
                })
                .map_err(|error| format!("{error:#}"));
                let _ = sender.send(result);
                ctx.request_repaint();
            })?;
        Ok(Self { progress, result })
    }
}

#[derive(Default)]
struct ConverterApp {
    input: String,
    output: String,
    job: Option<Job>,
    progress: Option<Progress>,
    started: Option<Instant>,
    elapsed: Duration,
    success: Option<Summary>,
    error: Option<String>,
    close_requested: bool,
}

impl ConverterApp {
    fn start(&mut self, ctx: &egui::Context) {
        self.error = None;
        self.success = None;
        self.progress = Some(INITIAL);
        self.elapsed = Duration::ZERO;
        self.close_requested = false;
        match Job::start(
            PathBuf::from(&self.input),
            PathBuf::from(&self.output),
            ctx.clone(),
        ) {
            Ok(job) => {
                self.job = Some(job);
                self.started = Some(Instant::now());
            }
            Err(error) => self.error = Some(format!("Cannot start conversion: {error}")),
        }
    }

    fn poll(&mut self) {
        let Some(job) = &self.job else { return };
        self.progress = Some(*job.progress.lock().unwrap_or_else(|e| e.into_inner()));
        if let Some(started) = self.started {
            self.elapsed = started.elapsed();
        }
        let result = match job.result.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => Err(
                "The conversion worker stopped unexpectedly. Please retry; your input file was not changed.".into()
            ),
        };
        self.job = None;
        self.started = None;
        self.close_requested = false;
        match result {
            Ok(summary) => {
                self.progress = Some(Progress {
                    stage: Stage::Complete,
                    bytes_written: summary.content_bytes,
                    total_bytes: summary.content_bytes,
                });
                self.success = Some(summary);
            }
            Err(error) => self.error = Some(error),
        }
    }

    fn select_input(&mut self, path: PathBuf) {
        self.output = path.with_extension("cia").to_string_lossy().into_owned();
        self.input = path.to_string_lossy().into_owned();
        self.clear_result();
    }

    fn clear_result(&mut self) {
        self.error = None;
        self.success = None;
        self.progress = None;
        self.elapsed = Duration::ZERO;
    }
}

// Reserve the last percent for metadata, flushing and publishing the file.
fn fraction(progress: Option<Progress>, successful: bool) -> f32 {
    if successful {
        return 1.0;
    }
    match progress {
        Some(p) if p.total_bytes > 0 => {
            (p.bytes_written as f64 / p.total_bytes as f64).clamp(0.0, 1.0) as f32 * 0.99
        }
        _ => 0.0,
    }
}

impl eframe::App for ConverterApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        let busy = self.job.is_some();
        if busy {
            ctx.request_repaint_after(Duration::from_millis(100));
            if ctx.input(|i| i.viewport().close_requested()) {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.close_requested = true;
            }
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(&ctx.style()).inner_margin(24))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.heading("CCI to CIA");
                    ui.label("Convert a decrypted 3DS cartridge image.");
                    ui.add_space(18.0);

                    ui.add_enabled_ui(!busy, |ui| {
                        let input_label = ui.label("Input (.cci or .3ds)");
                        ui.horizontal(|ui| {
                            let changed = ui
                                .add_sized(
                                    [ui.available_width() - 90.0, 28.0],
                                    egui::TextEdit::singleline(&mut self.input)
                                        .hint_text("Choose your cartridge image"),
                                )
                                .labelled_by(input_label.id)
                                .changed();
                            if changed {
                                self.output = PathBuf::from(&self.input)
                                    .with_extension("cia")
                                    .to_string_lossy()
                                    .into_owned();
                                self.clear_result();
                            }
                            if ui.button("Browse…").clicked()
                                && let Some(path) = rfd::FileDialog::new()
                                    .set_title("Choose decrypted cartridge image")
                                    .add_filter("3DS cartridge image", &["cci", "3ds"])
                                    .pick_file()
                            {
                                self.select_input(path);
                            }
                        });
                        ui.add_space(10.0);
                        let output_label = ui.label("Output (.cia)");
                        ui.horizontal(|ui| {
                            if ui
                                .add_sized(
                                    [ui.available_width() - 90.0, 28.0],
                                    egui::TextEdit::singleline(&mut self.output)
                                        .hint_text("Choose where to save"),
                                )
                                .labelled_by(output_label.id)
                                .changed()
                            {
                                self.clear_result();
                            }
                            if ui.button("Save as…").clicked() {
                                let path = PathBuf::from(&self.output);
                                let mut dialog = rfd::FileDialog::new()
                                    .set_title("Save CIA (choose a new filename)")
                                    .add_filter("CIA archive", &["cia"]);
                                if let Some(parent) =
                                    path.parent().filter(|p| !p.as_os_str().is_empty())
                                {
                                    dialog = dialog.set_directory(parent);
                                }
                                if let Some(name) = path.file_name() {
                                    dialog = dialog.set_file_name(name.to_string_lossy());
                                }
                                if let Some(mut selected) = dialog.save_file() {
                                    if selected.extension().is_none() {
                                        selected.set_extension("cia");
                                    }
                                    self.output = selected.to_string_lossy().into_owned();
                                    self.clear_result();
                                }
                            }
                        });
                    });
                    ui.add_space(16.0);
                    if ui
                        .add_enabled(
                            !busy
                                && !self.input.trim().is_empty()
                                && !self.output.trim().is_empty(),
                            egui::Button::new(if busy {
                                "Converting…"
                            } else {
                                "Convert to CIA"
                            })
                            .min_size(egui::vec2(150.0, 34.0)),
                        )
                        .clicked()
                    {
                        self.start(ctx);
                    }
                    ui.add_space(18.0);
                    let status = if self.error.is_some() {
                        "Conversion failed"
                    } else if self.success.is_some() {
                        "Conversion complete"
                    } else if busy {
                        match self.progress.map(|p| p.stage) {
                            Some(Stage::Copying) => "Copying and hashing content…",
                            Some(Stage::Finalizing | Stage::Complete) => {
                                "Finalizing and saving CIA…"
                            }
                            _ => "Checking input…",
                        }
                    } else {
                        "Ready"
                    };
                    ui.strong(status);
                    ui.add(
                        egui::ProgressBar::new(fraction(self.progress, self.success.is_some()))
                            .show_percentage()
                            .animate(busy),
                    );
                    if let Some(p) = self.progress {
                        ui.small(format!(
                            "{:.1} / {:.1} MiB   •   {}s elapsed",
                            p.bytes_written as f64 / 1048576.0,
                            p.total_bytes as f64 / 1048576.0,
                            self.elapsed.as_secs()
                        ));
                    }
                    if self.close_requested {
                        ui.label("Please wait for conversion to finish before closing.");
                    }
                    if let Some(error) = &self.error {
                        ui.add_space(8.0);
                        ui.colored_label(egui::Color32::from_rgb(190, 45, 45), error);
                        if ui.button("Copy error details").clicked() {
                            ctx.copy_text(error.clone());
                        }
                    }
                    if let Some(summary) = &self.success {
                        ui.add_space(8.0);
                        ui.label(format!("Saved {}", self.output));
                        ui.small(format!(
                            "Title {:016X} • {} contents",
                            summary.title_id, summary.contents
                        ));
                    }
                    ui.add_space(18.0);
                    ui.separator();
                    ui.small("Decrypted images only. Installation requires custom firmware.");
                    ui.small(
                        "Original files are kept. Existing output files are never overwritten.",
                    );
                });
            });
    }
}

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([640.0, 460.0])
            .with_min_inner_size([480.0, 400.0]),
        ..Default::default()
    };
    if let Err(error) = eframe::run_native(
        "CCI to CIA",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::light());
            Ok(Box::<ConverterApp>::default())
        }),
    ) {
        rfd::MessageDialog::new()
            .set_title("CCI to CIA — startup error")
            .set_description(format!("Unable to open the converter window:\n{error}"))
            .set_level(rfd::MessageLevel::Error)
            .show();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_waits_for_success() {
        let p = Progress {
            stage: Stage::Finalizing,
            bytes_written: 100,
            total_bytes: 100,
        };
        assert!(fraction(Some(p), false) < 1.0);
        assert_eq!(fraction(Some(p), true), 1.0);
        assert_eq!(fraction(Some(INITIAL), false), 0.0);
    }

    #[test]
    fn worker_reports_errors_and_ui_can_retry() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = ConverterApp::default();
        app.select_input(dir.path().join("missing.cci"));
        app.start(&egui::Context::default());
        let deadline = Instant::now() + Duration::from_secs(5);
        while app.job.is_some() && Instant::now() < deadline {
            app.poll();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(app.job.is_none());
        assert!(app.error.as_ref().unwrap().contains("Cannot open input"));
        assert!(app.success.is_none());
        app.select_input(dir.path().join("retry.cci"));
        assert!(app.error.is_none());
        assert!(app.output.ends_with("retry.cia"));
    }

    #[test]
    fn disconnected_worker_is_an_error() {
        let (sender, receiver) = mpsc::channel();
        drop(sender);
        let mut app = ConverterApp {
            job: Some(Job {
                progress: Arc::new(Mutex::new(INITIAL)),
                result: receiver,
            }),
            ..Default::default()
        };
        app.poll();
        assert!(app.job.is_none());
        assert!(app.error.unwrap().contains("stopped unexpectedly"));
    }

    #[test]
    fn success_uses_final_counts_even_if_progress_snapshot_is_stale() {
        let (sender, receiver) = mpsc::channel();
        sender
            .send(Ok(Summary {
                title_id: 123,
                contents: 1,
                content_bytes: 4096,
            }))
            .unwrap();
        let mut app = ConverterApp {
            job: Some(Job {
                progress: Arc::new(Mutex::new(INITIAL)),
                result: receiver,
            }),
            ..Default::default()
        };
        app.poll();
        assert!(app.job.is_none());
        assert!(app.error.is_none());
        assert!(app.success.is_some());
        let p = app.progress.unwrap();
        assert_eq!(p.stage, Stage::Complete);
        assert_eq!(p.bytes_written, 4096);
        assert_eq!(p.total_bytes, 4096);
    }
}
