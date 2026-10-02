use colored::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rmv_core::{EngineEvent, EngineStatus, LogLevel};
use rust_i18n::t;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

static GLOBAL_JSONL_PATH: OnceLock<PathBuf> = OnceLock::new();

pub fn init_global_jsonl(custom_path: Option<PathBuf>) -> &'static PathBuf {
    GLOBAL_JSONL_PATH.get_or_init(|| {
        custom_path.unwrap_or_else(|| {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            PathBuf::from(format!("rmv-events-{}.jsonl", ts))
        })
    })
}
pub struct CliUi {
    spinner: ProgressBar,
    download_bar: Option<ProgressBar>,
    printed_log_lines: std::collections::HashSet<String>,
    jsonl_path: Option<PathBuf>,
    tag_prefix: Option<String>,
    mp: Option<Arc<MultiProgress>>,
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
            printed_log_lines: std::collections::HashSet::new(),
            jsonl_path: GLOBAL_JSONL_PATH.get().cloned(),
            tag_prefix: None,
            mp: None,
        }
    }

    pub fn new_multi(mp: Arc<MultiProgress>, tag_prefix: String) -> Self {
        let spinner = mp.add(ProgressBar::new_spinner());
        spinner.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("|/-\\")
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        Self {
            spinner,
            download_bar: None,
            printed_log_lines: std::collections::HashSet::new(),
            jsonl_path: GLOBAL_JSONL_PATH.get().cloned(),
            tag_prefix: Some(tag_prefix),
            mp: Some(mp),
        }
    }

    #[allow(dead_code)]
    pub fn with_jsonl(mut self, path: PathBuf) -> Self {
        self.jsonl_path = Some(path);
        self
    }

    #[allow(dead_code)]
    pub fn set_jsonl(&mut self, path: PathBuf) {
        self.jsonl_path = Some(path);
    }

    pub fn handle_event(&mut self, event: EngineEvent) {
        if let Some(path) = &self.jsonl_path {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                if let Ok(json) = serde_json::to_string(&event) {
                    let _ = writeln!(file, "{}", json);
                }
            }
        }

        match event {
            EngineEvent::Step {
                phase,
                index,
                total,
                desc,
            } => {
                let tag = format!("[{}/{}]", index, total).bold().cyan();
                let phase_name = phase.display_name().bold();
                let msg = if let Some(pref) = &self.tag_prefix {
                    format!("[{}] {} {}: {}", pref.bold(), tag, phase_name, desc)
                } else {
                    format!("{} {}: {}", tag, phase_name, desc)
                };
                self.spinner.set_message(msg);
                self.spinner
                    .enable_steady_tick(std::time::Duration::from_millis(80));
            }
            EngineEvent::Log { level, line } => {
                let prefix = match level {
                    LogLevel::Ok => "[ ok ]".green().bold(),
                    LogLevel::Error => "[fail]".red().bold(),
                    LogLevel::Warn => "[warn]".yellow().bold(),
                    LogLevel::Info => "[info]".blue().bold(),
                    LogLevel::Running => "[ .. ]".cyan(),
                };
                let log_str = if let Some(pref) = &self.tag_prefix {
                    format!("[{}] {} {}", pref.dimmed(), prefix, line)
                } else {
                    format!("{} {}", prefix, line)
                };
                if let Some(mp) = &self.mp {
                    let _ = mp.println(log_str);
                } else {
                    self.spinner.suspend(|| println!("{}", log_str));
                }
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
                // 新文件或总量变化时重置进度条，避免复用残留实例
                if self.download_bar.is_some() {
                    if let Some(pb) = &self.download_bar {
                        if pb.length() != Some(total) {
                            pb.finish_and_clear();
                            self.download_bar = None;
                        }
                    }
                }

                if self.download_bar.is_none() {
                    let pb = if let Some(mp) = &self.mp {
                        mp.add(ProgressBar::new(total))
                    } else {
                        ProgressBar::new(total)
                    };
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
                for line in &lines {
                    if !self.printed_log_lines.contains(line) {
                        self.printed_log_lines.insert(line.clone());
                        let trimmed = line.trim();
                        if trimmed.starts_with("[+]")
                            || trimmed.starts_with("[-]")
                            || trimmed.starts_with("[*]")
                        {
                            let live_msg = if let Some(pref) = &self.tag_prefix {
                                format!("  [{}] {}", pref.dimmed(), trimmed.dimmed())
                            } else {
                                format!("  {}", trimmed.dimmed())
                            };
                            if let Some(mp) = &self.mp {
                                let _ = mp.println(live_msg);
                            } else {
                                self.spinner.suspend(|| {
                                    println!("{}", live_msg);
                                });
                            }
                        }
                    }
                }
                if let Some(last_line) = lines.last() {
                    let msg = t!("cli.exploit_running", line = last_line.dimmed().to_string());
                    self.spinner.set_message(msg);
                }
            }
            EngineEvent::Status(status) => match status {
                EngineStatus::Success => {
                    self.spinner.finish_and_clear();
                    if let Some(pb) = &self.download_bar {
                        pb.finish_and_clear();
                    }
                    self.download_bar = None;
                }
                EngineStatus::Failed => {
                    self.spinner.finish_and_clear();
                    if let Some(pb) = &self.download_bar {
                        pb.finish_and_clear();
                    }
                    self.download_bar = None;
                }
                _ => {}
            },
            EngineEvent::Completed { success, message } => {
                self.spinner.finish_and_clear();
                if let Some(pb) = &self.download_bar {
                    pb.finish_and_clear();
                }
                self.download_bar = None;
                let final_msg = if let Some(pref) = &self.tag_prefix {
                    format!("[{}] {}", pref.bold(), message)
                } else {
                    message
                };
                if let Some(mp) = &self.mp {
                    if success {
                        let _ = mp.println(format!(
                            "{} {}",
                            "[ ok ]".green().bold(),
                            final_msg.green().bold()
                        ));
                    } else {
                        let _ = mp.println(format!(
                            "{} {}",
                            "[fail]".red().bold(),
                            final_msg.red().bold()
                        ));
                    }
                } else {
                    if success {
                        println!("{} {}", "[ ok ]".green().bold(), final_msg.green().bold());
                    } else {
                        println!("{} {}", "[fail]".red().bold(), final_msg.red().bold());
                    }
                }
            }
        }
    }
}
