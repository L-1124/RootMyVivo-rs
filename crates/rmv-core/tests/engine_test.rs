//! Engine integration regression tests under paused Tokio time.
#![allow(unused_crate_dependencies, clippy::expect_used, clippy::unwrap_used)]
// 集成测试 target 不使用库的链接期依赖，该 lint 在此语义不成立。
use std::path::PathBuf;
use std::time::SystemTime;
use tokio::sync::mpsc::unbounded_channel;

use rmv_core::device::ROOT_PROBE_CMD;
use rmv_core::engine::{EngineOptions, ExploitEngine};
use rmv_core::error::RmvError;
use rmv_core::event::EngineEvent;
mod common;
use common::{MockRule, MockTransport};

const VULNERABLE_PROC_VERSION: &str =
    "Linux version 6.6.89-android15-8-g1f71897ac249-abogki467805059-4k (build-user@build-host) (clang version 18.0.1) #1 SMP PREEMPT Fri Aug 1 12:00:00 CST 2026";
const PATCHED_PROC_VERSION: &str =
    "Linux version 6.6.140-android15-8-gabcdef123456-abogki999999999-4k (build-user@build-host) #1 SMP";

fn make_temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rmv_engine_test_{tag}_{nanos}"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn setup_base_mock_device(transport: &MockTransport, proc_version: &str) {
    transport.add_success_rule("getprop ro.product.model", "V2408A\n");
    transport.add_success_rule("getprop ro.product.device", "pd2408\n");
    transport.add_success_rule("getprop ro.product.brand", "vivo\n");
    transport.add_success_rule("cat /proc/version", format!("{proc_version}\n"));
    transport.add_success_rule(
        "cat /proc/sys/kernel/random/boot_id",
        "mock-boot-id-12345678\n",
    );
    transport.add_success_rule("getprop sys.boot_completed", "1\n");
}

#[tokio::test(start_paused = true)]
async fn test_gate_rejection_patched() {
    let transport = MockTransport::new();
    setup_base_mock_device(&transport, PATCHED_PROC_VERSION);

    let temp_dir = make_temp_dir("gate_rejection");
    let fake_payload = temp_dir.join("preload.so");
    std::fs::write(&fake_payload, b"mock-payload").expect("payload created");

    let options = EngineOptions {
        custom_payload: Some(fake_payload),
        save_history: false,
        ..Default::default()
    };

    let engine = ExploitEngine::new(&temp_dir);
    let (tx, mut rx) = unbounded_channel();

    let res = engine.run(&transport, options, tx).await;

    assert!(res.is_err(), "Engine should fail on patched kernel");
    match res.unwrap_err() {
        RmvError::UnsupportedKernel { version, .. } => {
            assert_eq!(version, "6.6.140");
        }
        err => panic!("Unexpected error type: {err:?}"),
    }

    let mut got_failed = false;
    while let Ok(evt) = rx.try_recv() {
        if let EngineEvent::Status(status) = evt {
            if status == rmv_core::event::EngineStatus::Failed {
                got_failed = true;
            }
        }
    }
    assert!(got_failed, "Should emit Failed engine status");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test(start_paused = true)]
async fn test_exploit_timeout_aborts() {
    let transport = MockTransport::new();
    setup_base_mock_device(&transport, VULNERABLE_PROC_VERSION);

    transport.add_success_rule(
        ROOT_PROBE_CMD,
        "__RMV_KSU__\n__RMV_SYS_SU__\n__RMV_TMP_SU__\n__RMV_BARE_SU__\n__RMV_MAPS__\n__RMV_DONE__\n__RMV_END__",
    );

    transport.add_success_rule(
        "tail -n 15 /data/local/tmp/rmv/live.log",
        "rmv exploit attempt 1/3\n__RMV_DONE__\n__RMV_ALIVE__\n12345\n__RMV_SU__\nuid=2000(shell)\n__RMV_END__",
    );

    let temp_dir = make_temp_dir("exploit_timeout");
    let fake_payload = temp_dir.join("preload.so");
    std::fs::write(&fake_payload, b"mock-payload").expect("payload created");

    let options = EngineOptions {
        custom_payload: Some(fake_payload),
        timeout_secs: 10,
        attempts: 3,
        save_history: false,
        ..Default::default()
    };

    let engine = ExploitEngine::new(&temp_dir);
    let (tx, _rx) = unbounded_channel();

    let res = engine.run(&transport, options, tx).await;
    assert!(res.is_err(), "Engine should timeout");
    match res.unwrap_err() {
        RmvError::ExploitTimeout { last_attempt, .. } => {
            assert_eq!(last_attempt, Some(1));
        }
        err => panic!("Expected ExploitTimeout, got {err:?}"),
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test(start_paused = true)]
async fn test_exploit_early_exit() {
    let transport = MockTransport::new();
    setup_base_mock_device(&transport, VULNERABLE_PROC_VERSION);

    transport.add_success_rule(
        ROOT_PROBE_CMD,
        "__RMV_KSU__\n__RMV_SYS_SU__\n__RMV_TMP_SU__\n__RMV_BARE_SU__\n__RMV_MAPS__\n__RMV_DONE__\n__RMV_END__",
    );

    transport.add_success_rule(
        "tail -n 15 /data/local/tmp/rmv/live.log",
        "rmv exploit starting...\n__RMV_DONE__\n__RMV_ALIVE__\n\n__RMV_SU__\nuid=2000(shell)\n__RMV_END__",
    );

    let temp_dir = make_temp_dir("early_exit");
    let fake_payload = temp_dir.join("preload.so");
    std::fs::write(&fake_payload, b"mock-payload").expect("payload created");

    let options = EngineOptions {
        custom_payload: Some(fake_payload),
        timeout_secs: 60,
        save_history: false,
        ..Default::default()
    };

    let engine = ExploitEngine::new(&temp_dir);
    let (tx, _rx) = unbounded_channel();

    let res = engine.run(&transport, options, tx).await;
    assert!(res.is_err(), "Early exit should fail");
    match res.unwrap_err() {
        RmvError::ExploitFailed(msg) => {
            assert!(
                msg.contains("exploit_process_exited")
                    || msg.contains("退出")
                    || msg.contains("exited"),
                "Message was: {msg}"
            );
        }
        err => panic!("Expected ExploitFailed, got {err:?}"),
    }

    let cmds = transport.executed();
    assert!(
        cmds.iter().any(|c| c.contains("pkill -9 -x true")),
        "Cleanup commands should be invoked"
    );
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test(start_paused = true)]
async fn test_exploit_success_uid0() {
    let transport = MockTransport::new();
    setup_base_mock_device(&transport, VULNERABLE_PROC_VERSION);

    transport.add_success_rule(
        ROOT_PROBE_CMD,
        "__RMV_KSU__\n__RMV_SYS_SU__\n__RMV_TMP_SU__\n__RMV_BARE_SU__\n__RMV_MAPS__\n__RMV_DONE__\n__RMV_END__",
    );

    transport.add_success_rule(
        "tail -n 15 /data/local/tmp/rmv/live.log",
        "rmv exploit success\n__RMV_DONE__\n1\n__RMV_ALIVE__\n12345\n__RMV_SU__\nuid=0(root) gid=0(root) groups=0(root)\n__RMV_END__",
    );
    transport.add_success_rule(
        "RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c id",
        "uid=0(root) gid=0(root) groups=0(root)\n",
    );

    let temp_dir = make_temp_dir("exploit_success");
    let fake_payload = temp_dir.join("preload.so");
    std::fs::write(&fake_payload, b"mock-payload").expect("payload created");

    let options = EngineOptions {
        custom_payload: Some(fake_payload),
        skip_ksu: true,
        save_history: false,
        ..Default::default()
    };

    let engine = ExploitEngine::new(&temp_dir);
    let (tx, mut rx) = unbounded_channel();

    let res = engine.run(&transport, options, tx).await;
    assert!(
        res.is_ok(),
        "Exploit should succeed with skip_ksu=true: {:?}",
        res.err()
    );

    let mut success_event = false;
    while let Ok(evt) = rx.try_recv() {
        if let EngineEvent::Status(rmv_core::event::EngineStatus::Success) = evt {
            success_event = true;
        }
    }
    assert!(success_event, "EngineStatus::Success should be emitted");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test(start_paused = true)]
async fn test_offline_ksu_partial_success() {
    let transport = MockTransport::new();
    setup_base_mock_device(&transport, VULNERABLE_PROC_VERSION);

    transport.add_success_rule(
        ROOT_PROBE_CMD,
        "__RMV_KSU__\n__RMV_SYS_SU__\n__RMV_TMP_SU__\n__RMV_BARE_SU__\n__RMV_MAPS__\n__RMV_DONE__\n__RMV_END__",
    );

    transport.add_success_rule(
        "tail -n 15 /data/local/tmp/rmv/live.log",
        "rmv exploit success\n__RMV_DONE__\n1\n__RMV_ALIVE__\n12345\n__RMV_SU__\nuid=0(root) gid=0(root) groups=0(root)\n__RMV_END__",
    );
    transport.add_success_rule(
        "RMV_HOME=/data/local/tmp/rmv /data/local/tmp/rmv/su -c id",
        "uid=0(root) gid=0(root) groups=0(root)\n",
    );

    transport.add_success_rule("cat /proc/modules", "\n");
    transport.add_success_rule(
        "pm path android",
        "package:/system/framework/framework-res.apk\n",
    );
    transport.add_rule(MockRule::failure("unzip -p", "error", 1));
    transport.add_rule(MockRule::failure("test -x", "no", 1));

    let temp_dir = make_temp_dir("offline_ksu");
    let fake_payload = temp_dir.join("preload.so");
    std::fs::write(&fake_payload, b"mock-payload").expect("payload created");

    let options = EngineOptions {
        custom_payload: Some(fake_payload),
        skip_ksu: false,
        install_manager: false,
        save_history: false,
        ..Default::default()
    };

    let engine = ExploitEngine::new(&temp_dir);
    let (tx, mut rx) = unbounded_channel();

    let res = engine.run(&transport, options, tx).await;
    assert!(
        res.is_ok(),
        "Engine returns Ok even on Partial status: {:?}",
        res.err()
    );

    let mut got_partial = false;
    while let Ok(evt) = rx.try_recv() {
        if let EngineEvent::Status(rmv_core::event::EngineStatus::Partial) = evt {
            got_partial = true;
        }
    }
    assert!(
        got_partial,
        "EngineStatus::Partial should be emitted on KSU failure"
    );
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test(start_paused = true)]
async fn test_custom_payload_missing() {
    let transport = MockTransport::new();
    setup_base_mock_device(&transport, VULNERABLE_PROC_VERSION);

    let nonexistent_payload = PathBuf::from("nonexistent_payload_12345.so");
    let options = EngineOptions {
        custom_payload: Some(nonexistent_payload),
        save_history: false,
        ..Default::default()
    };

    let temp_dir = make_temp_dir("missing_payload");
    let engine = ExploitEngine::new(&temp_dir);
    let (tx, _rx) = unbounded_channel();

    let res = engine.run(&transport, options, tx).await;
    assert!(res.is_err(), "Missing custom payload must fail");
    match res.unwrap_err() {
        RmvError::ExploitFailed(msg) => {
            assert!(
                msg.contains("nonexistent_payload_12345.so")
                    || msg.contains("not found")
                    || msg.contains("不存在"),
                "Message was: {msg}"
            );
        }
        err => panic!("Expected ExploitFailed, got {err:?}"),
    }

    assert!(transport.pushed().is_empty());
    let _ = std::fs::remove_dir_all(&temp_dir);
}
