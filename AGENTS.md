# Repository Guidelines

## Project Overview

`rootmyvivo-rs` is a cross-platform, pure-Rust toolchain providing unlock-free temporary root and KernelSU/SukiSU LKM late-loading for bootloader-locked vivo/iQOO devices exploiting CVE-2026-43499.
The project completely removes dependencies on Google's external `adb.exe` binary:
- **Desktop (Windows / Linux / macOS)**: Direct hardware communication via pure-Rust USB (`nusb`) and Android 11+ Wireless Debugging (`rustls` TLS 1.3 + mDNS + SPAKE2 pairing).
- **Web (Browser / WebAssembly)**: WebUSB client via `rmv-wasm` compiling to `wasm32-unknown-unknown`.
- **Legacy Fallback**: `AdbCliTransport` for environments retaining standard ADB server daemons.

---

## Architecture & Data Flow

```mermaid
graph TD
    CLI[rmv-cli binary: rmv] --> Engine[rmv-core: ExploitEngine]
    WASM[rmv-wasm: RmvWebBridge] --> Engine

    Engine --> Trait[Transport Trait]

    subgraph Transport Implementations
        Trait --> Usb[AdbUsbTransport: nusb + webadb-rs]
        Trait --> Wifi[AdbWifiTransport: mTLS + mDNS + SPAKE2]
        Trait --> Cli[AdbCliTransport: adb.exe subprocess fallback]
        Trait --> WebUsb[AdbWebUsbTransport: WebUSB in rmv-wasm]
    end

    subgraph Core Pipeline
        Engine --> Stage1[1. Device Gate: DeviceInfo::parse + kernel CVE-2026-43499 check]
        Stage1 --> Stage2[2. Catalog Match: CatalogV5 fingerprint match + SHA-256 verify]
        Stage2 --> Stage3[3. Payload Verify: ELF inspection + target device check]
        Stage3 --> Stage4[4. Injection: push_bytes to /data/local/tmp/rmv + LD_PRELOAD]
        Stage4 --> Stage5[5. Polling Loop: live.log + DONE sentinel + su -c id until uid=0]
        Stage5 --> Stage6[6. KSU Late-Load: KsuOrchestrator ksud + base64 su wrapper repair]
        Stage6 --> Stage7[7. Cleanup & History: Persistence::clean_traces + HistoryManager]
    end
```

### Data Flow Invariants
1. **Device Gate**: `/proc/version` kernel version $\ge$ 6.6.140 is patched; the engine halts immediately (`GateStatus::Patched`).
2. **Payload Selection**: Matched strictly by kernel build fingerprint (`abogki*`), never by consumer device marketing name alone.
3. **KSU Timing**: `ksud late-load` runs *immediately* upon obtaining `uid=0` while exploit daemon pipes survive; su path repair wraps shadowed binaries (`/system/bin/su`, `/apex/com.android.virt/bin/su`) with self-healing base64 scripts.
4. **History Retention**: Real runs record the last 50 execution logs to `~/.rmv/history/<timestamp>_<id>.json`. Dry runs (`--dry-run`) **never** write history.

---

## Key Directories

- `crates/rmv-core/`: Core library housing the exploit pipeline, vulnerability/catalog gates, KernelSU orchestration, and all transport implementations (`usb`, `wifi`, `cli`).
- `crates/rmv-cli/`: Desktop terminal binary (`rmv`) providing command dispatch, argument parsing, and interactive terminal UI.
- `crates/rmv-wasm/`: WebAssembly bridge crate (`cdylib`/`rlib`) exposing browser WebUSB functions via `wasm-bindgen`.

---

## Development Commands

### Building
```bash
# Build desktop CLI binary (debug)
cargo build --bin rmv

# Build optimized release binary
cargo build --release --bin rmv

# Check entire desktop workspace
cargo check --workspace

# Check WebAssembly target (requires wasm32-unknown-unknown)
cargo check -p rmv-wasm --target wasm32-unknown-unknown
```

### Testing
```bash
# Run all workspace unit tests
cargo test --workspace

# Run tests for rmv-core only
cargo test -p rmv-core

# Run specific test by substring filter
cargo test -p rmv-core spake2
cargo test -p rmv-core test_format_epoch_seconds
```

### Running CLI Commands
```bash
# Check connected device status (auto-detects USB, Wi-Fi mDNS, or CLI)
cargo run --bin rmv -- check -t auto

# Direct USB inspection (pure Rust, bypasses adb.exe)
cargo run --bin rmv -- check -t usb

# Pair with Android 11+ Wireless Debugging
cargo run --bin rmv -- pair 192.168.1.50:37123 876543

# Run exploit in simulation mode (no files sent, no history polluted)
cargo run --bin rmv -- run -p /path/to/preload.so --dry-run
```

---

## Code Conventions & Common Patterns

### Status Message Formatting
Terminal messages must use standardized, clean ASCII status prefixes without decorative emojis or full-width punctuation:
- `[ .. ]`: In-progress operation (cyan)
- `[ ok ]`: Successful step (green)
- `[warn]`: Non-fatal warning / degradation (yellow)
- `[fail]`: Failure / error (red)
- `[info]`: Informational detail (cyan/dimmed)

### Error Handling
- **Core Library (`rmv-core`)**: All errors use `rmv_core::RmvError`. Do not use `anyhow` inside `rmv-core`. Implement `Display` by mapping each variant to a `rust_i18n::t!` translation key.
- **CLI Layer (`rmv-cli`)**: Handlers in `commands/mod.rs` return `anyhow::Result<()>`, wrapping core errors with `.context(...)`.

### Async & Trait Patterns
- The `Transport` trait uses conditional async trait bounds:
  ```rust
  #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
  #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
  pub trait Transport: MaybeSend { ... }
  ```
- Any component accepting `<T: Transport>` automatically accepts `Arc<dyn Transport>` via the blanket delegation implemented in `transport/mod.rs`.

### Localization (i18n)
- Every user-facing message must reside in both `crates/rmv-core/locales/en.json` and `crates/rmv-core/locales/zh-CN.json`.
- Access translations using `rust_i18n::t!("key.path", arg = value)`.
- Command-line arguments in `rmv-cli` are dynamically translated via `localize_command` in `main.rs`.

---

## Testing & QA

- **Unit Testing**: 13 unit tests reside in inline `#[cfg(test)] mod tests` blocks within `rmv-core` (`catalog.rs`, `device.rs`, `history.rs`, `ksu.rs`, `payload.rs`, `wifi/pairing.rs`).
- **Regression Gates**:
  - `cargo test --workspace` must pass with 0 failures before any pull request or commit.
  - `cargo check -p rmv-wasm --target wasm32-unknown-unknown` must remain cleanly compiling without pulling in desktop-only networking dependencies (`tokio/net`, `mio`, `nusb`).
