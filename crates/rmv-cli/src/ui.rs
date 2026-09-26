use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use rmv_core::{EngineEvent, EngineStatus, LogLevel};
use rust_i18n::t;

pub struct CliUi {
    spinner: ProgressBar,
    download_bar: Option<ProgressBar>,
}

impl CliUi {
    pub fn new() -> Self {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("|/-\\")
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        Self {
            spinner,
            download_bar: None,
        }
    }

    pub fn handle_event(&mut self, event: EngineEvent) {
        match event {
            EngineEvent::Step {
                phase,
                index,
                total,
                desc,
            } => {
                let tag = format!("[{}/{}]", index, total).bold().cyan();
                let phase_name = phase.display_name().bold();
                self.spinner.set_message(format!("{} {}: {}", tag, phase_name, desc));
                self.spinner.enable_steady_tick(std::time::Duration::from_millis(80));
            }
            EngineEvent::Log { level, line } => {
                let prefix = match level {
                    LogLevel::Ok => "[ ok ]".green().bold(),
                    LogLevel::Error => "[fail]".red().bold(),
                    LogLevel::Warn => "[warn]".yellow().bold(),
                    LogLevel::Info => "[info]".blue().bold(),
                    LogLevel::Running => "[ .. ]".cyan(),
                };
                self.spinner.suspend(|| println!("{} {}", prefix, line));
            }
            EngineEvent::Progress { text, active } => {
                if active {
                    self.spinner.set_message(text);
                }
            }
            EngineEvent::Download {
                filename,
                downloaded,
                total,
            } => {
                if self.download_bar.is_none() {
                    let pb = ProgressBar::new(total);
                    pb.set_style(
                        ProgressStyle::default_bar()
                            .template("  {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
                            .unwrap()
                            .progress_chars("#>-"),
                    );
                    pb.set_message(filename.clone());
                    self.download_bar = Some(pb);
                }

                if let Some(pb) = &self.download_bar {
                    pb.set_position(downloaded);
                    if downloaded >= total && total > 0 {
                        let done_msg = t!("cli.download_done", filename = filename);
                        pb.finish_with_message(done_msg);
                        self.download_bar = None;
                    }
                }
            }
            EngineEvent::ExploitLive { lines, .. } => {
                if let Some(last_line) = lines.last() {
                    let msg = t!("cli.exploit_running", line = last_line.dimmed().to_string());
                    self.spinner.set_message(msg);
                }
            }
            EngineEvent::Status(status) => match status {
                EngineStatus::Success => {
                    self.spinner.finish_and_clear();
                }
                EngineStatus::Failed => {
                    self.spinner.finish_and_clear();
                }
                _ => {}
            },
            EngineEvent::Completed { success, message } => {
                self.spinner.finish_and_clear();
                if success {
                    println!("{} {}", "[ ok ]".green().bold(), message.green().bold());
                } else {
                    println!("{} {}", "[fail]".red().bold(), message.red().bold());
                }
            }
        }
    }
}
