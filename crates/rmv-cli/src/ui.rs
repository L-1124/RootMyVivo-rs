use colored::Colorize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rmv_core::{EngineEvent, EngineStatus, LogLevel};
use rust_i18n::t;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};

/// Initialize tracing subscriber with `EnvFilter` directing logs to standard error.
pub fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
static GLOBAL_JSONL_PATH: OnceLock<PathBuf> = OnceLock::new();

pub fn init_global_jsonl(custom_path: Option<PathBuf>) -> &'static PathBuf {
    GLOBAL_JSONL_PATH.get_or_init(|| {
        custom_path.unwrap_or_else(|| {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            PathBuf::from(format!("rmv-events-{ts}.jsonl"))
        })
    })
}
pub struct CliUi {
    spinner: ProgressBar,
    download_bar: Option<ProgressBar>,
    printed_log_lines: std::collections::HashSet<String>,
    jsonl_path: Option<PathBuf>,
    json_writer: Option<BufWriter<File>>,
    tag_prefix: Option<String>,
    mp: Option<Arc<MultiProgress>>,
}

impl CliUi {
    fn clear_bars(&mut self) {
        self.spinner.finish_and_clear();
        if let Some(pb) = &self.download_bar {
            pb.finish_and_clear();
        }
        self.download_bar = None;
    }

    pub fn new() -> Self {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("|/-\\")
                .template("{spinner:.green} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        Self {
            spinner,
            download_bar: None,
            printed_log_lines: std::collections::HashSet::new(),
            jsonl_path: GLOBAL_JSONL_PATH.get().cloned(),
            json_writer: None,
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
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        Self {
            spinner,
            download_bar: None,
            printed_log_lines: std::collections::HashSet::new(),
            jsonl_path: GLOBAL_JSONL_PATH.get().cloned(),
            json_writer: None,
            tag_prefix: Some(tag_prefix),
            mp: Some(mp),
        }
    }

    pub async fn flush(&mut self) {
        if let Some(writer) = &mut self.json_writer {
            let _ = writer.flush().await;
        }
    }

    pub async fn handle_event(&mut self, event: EngineEvent) {
        self.log_event_jsonl(&event).await;

        match event {
            EngineEvent::Step {
                phase,
                index,
                total,
                desc,
            } => {
                self.on_step(phase, index, total, &desc);
            }
            EngineEvent::Log { level, line } => {
                self.on_log(level, &line);
            }
            EngineEvent::Progress { text, active } => {
                self.on_progress(&text, active);
            }
            EngineEvent::Download {
                filename,
                downloaded,
                total,
            } => {
                self.on_download(&filename, downloaded, total);
            }
            EngineEvent::ExploitLive { lines, .. } => {
                self.on_exploit_live(&lines);
            }
            EngineEvent::Status(
                EngineStatus::Success | EngineStatus::Partial | EngineStatus::Failed,
            ) => {
                self.clear_bars();
            }
            EngineEvent::Completed {
                success,
                status,
                message,
            } => {
                self.on_completed(success, status, &message);
            }
            _ => {}
        }
    }

    async fn log_event_jsonl(&mut self, event: &EngineEvent) {
        if let Some(path) = &self.jsonl_path {
            if self.json_writer.is_none() {
                if let Ok(file) = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .await
                {
                    self.json_writer = Some(BufWriter::new(file));
                }
            }
            if let Some(writer) = &mut self.json_writer {
                if let Ok(json) = serde_json::to_string(event) {
                    let _ = writer.write_all(json.as_bytes()).await;
                    let _ = writer.write_all(b"\n").await;
                    let _ = writer.flush().await;
                }
            }
        }
    }

    fn on_step(&mut self, phase: rmv_core::Phase, index: usize, total: usize, desc: &str) {
        let tag = format!("[{index}/{total}]").bold().cyan();
        let phase_name = phase.display_name().bold();
        let msg = if let Some(pref) = &self.tag_prefix {
            format!("[{}] {} {}: {}", pref.bold(), tag, phase_name, desc)
        } else {
            format!("{tag} {phase_name}: {desc}")
        };
        self.spinner.set_message(msg);
        self.spinner
            .enable_steady_tick(std::time::Duration::from_millis(80));
    }

    fn on_log(&mut self, level: LogLevel, line: &str) {
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
            format!("{prefix} {line}")
        };
        if let Some(mp) = &self.mp {
            let _ = mp.println(log_str);
        } else {
            self.spinner.suspend(|| println!("{log_str}"));
        }
    }

    fn on_progress(&mut self, text: &str, active: bool) {
        if active {
            self.spinner.set_message(text.to_string());
        }
    }

    fn on_download(&mut self, filename: &str, downloaded: u64, total: u64) {
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
                    .unwrap_or_else(|_| ProgressStyle::default_bar())
                    .progress_chars("#>-"),
            );
            pb.set_message(filename.to_string());
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

    fn on_exploit_live(&mut self, lines: &[String]) {
        for line in lines {
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
                            println!("{live_msg}");
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

    fn on_completed(&mut self, success: bool, status: Option<EngineStatus>, message: &str) {
        self.clear_bars();
        self.download_bar = None;
        let final_msg = if let Some(pref) = &self.tag_prefix {
            format!("[{}] {}", pref.bold(), message)
        } else {
            message.to_string()
        };

        let effective_status = status.unwrap_or(if success {
            EngineStatus::Success
        } else {
            EngineStatus::Failed
        });

        if let Some(mp) = &self.mp {
            match effective_status {
                EngineStatus::Success => {
                    let _ = mp.println(format!(
                        "{} {}",
                        "[ ok ]".green().bold(),
                        final_msg.green().bold()
                    ));
                }
                EngineStatus::Partial => {
                    let _ = mp.println(format!(
                        "{} {}",
                        "[warn]".yellow().bold(),
                        final_msg.yellow().bold()
                    ));
                }
                _ => {
                    let _ = mp.println(format!(
                        "{} {}",
                        "[fail]".red().bold(),
                        final_msg.red().bold()
                    ));
                }
            }
        } else {
            match effective_status {
                EngineStatus::Success => {
                    println!("{} {}", "[ ok ]".green().bold(), final_msg.green().bold());
                }
                EngineStatus::Partial => {
                    println!("{} {}", "[warn]".yellow().bold(), final_msg.yellow().bold());
                }
                _ => {
                    println!("{} {}", "[fail]".red().bold(), final_msg.red().bold());
                }
            }
        }
    }
}
