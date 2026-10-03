#![allow(clippy::disallowed_types, dead_code)]
// 测试替身需要 Send + Sync 的互斥量，且锁从不跨 await 持有。
use async_trait::async_trait;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rmv_core::transport::{ExecOutput, Transport};
use rmv_core::{Result, RmvError};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Debug, Clone)]
pub struct MockRule {
    pub pattern: String,
    pub output: ExecOutput,
}

impl MockRule {
    pub fn new(pattern: impl Into<String>, output: ExecOutput) -> Self {
        Self {
            pattern: pattern.into(),
            output,
        }
    }

    pub fn success(pattern: impl Into<String>, stdout: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            output: ExecOutput {
                code: Some(0),
                stdout: stdout.into(),
                stderr: String::new(),
            },
        }
    }

    pub fn failure(pattern: impl Into<String>, stderr: impl Into<String>, code: i32) -> Self {
        Self {
            pattern: pattern.into(),
            output: ExecOutput {
                code: Some(code),
                stdout: String::new(),
                stderr: stderr.into(),
            },
        }
    }
}

pub struct MockTransport {
    pub rules: Mutex<Vec<MockRule>>,
    pub fallback: Mutex<ExecOutput>,
    pub executed_commands: Mutex<Vec<String>>,
    pub is_alive_response: Mutex<bool>,
    pub pushed_files: Mutex<Vec<(String, Vec<u8>)>>,
    pub pulled_files: Mutex<Vec<(String, Vec<u8>)>>,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            rules: Mutex::new(Vec::new()),
            fallback: Mutex::new(ExecOutput {
                code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            }),
            executed_commands: Mutex::new(Vec::new()),
            is_alive_response: Mutex::new(true),
            pushed_files: Mutex::new(Vec::new()),
            pulled_files: Mutex::new(Vec::new()),
        }
    }

    pub fn add_rule(&self, rule: MockRule) {
        lock(&self.rules).push(rule);
    }

    pub fn add_success_rule(&self, pattern: impl Into<String>, stdout: impl Into<String>) {
        self.add_rule(MockRule::success(pattern, stdout));
    }

    pub fn set_fallback(&self, output: ExecOutput) {
        *lock(&self.fallback) = output;
    }

    pub fn set_alive(&self, alive: bool) {
        *lock(&self.is_alive_response) = alive;
    }

    pub fn executed(&self) -> Vec<String> {
        lock(&self.executed_commands).clone()
    }

    pub fn pushed(&self) -> Vec<(String, Vec<u8>)> {
        lock(&self.pushed_files).clone()
    }

    pub fn mock_file_pull(&self, remote_path: impl Into<String>, data: Vec<u8>) {
        lock(&self.pulled_files).push((remote_path.into(), data));
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn exec(&self, cmd: &str) -> Result<ExecOutput> {
        lock(&self.executed_commands).push(cmd.to_string());

        let rules = lock(&self.rules);
        for rule in rules.iter() {
            if cmd.contains(&rule.pattern) {
                return Ok(rule.output.clone());
            }
        }

        Ok(lock(&self.fallback).clone())
    }

    async fn push(&self, local_path: &Path, remote_path: &str) -> Result<()> {
        let data = tokio::fs::read(local_path).await.map_err(RmvError::Io)?;
        lock(&self.pushed_files).push((remote_path.to_string(), data));
        Ok(())
    }

    async fn pull(&self, remote_path: &str, local_path: &Path) -> Result<()> {
        let data = {
            let files = lock(&self.pulled_files);
            files
                .iter()
                .find(|(r, _)| r == remote_path)
                .map(|(_, d)| d.clone())
        };
        if let Some(data) = data {
            tokio::fs::write(local_path, data)
                .await
                .map_err(RmvError::Io)?;
            Ok(())
        } else {
            Err(RmvError::Adb {
                message: format!("remote file {remote_path} not found in mock pull table"),
                code: Some(1),
            })
        }
    }

    async fn push_bytes(&self, data: &[u8], remote_path: &str, _mode: u32) -> Result<()> {
        lock(&self.pushed_files).push((remote_path.to_string(), data.to_vec()));
        Ok(())
    }

    async fn pull_bytes(&self, remote_path: &str) -> Result<Vec<u8>> {
        let files = lock(&self.pulled_files);
        if let Some((_, data)) = files.iter().find(|(r, _)| r == remote_path) {
            Ok(data.clone())
        } else {
            Err(RmvError::Adb {
                message: format!("remote file {remote_path} not found in mock pull table"),
                code: Some(1),
            })
        }
    }

    async fn is_alive(&self) -> bool {
        *lock(&self.is_alive_response)
    }
}
