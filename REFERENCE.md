# RootMyVivo 技术架构与免解锁提权全流程规范

本文档针对锁定 Bootloader 的 vivo / iQOO 设备，系统化整理了 `RootMyVivo` 开源生态的系统架构、注入生命周期、KernelSU 加载与开机静默恢复全流程。

---

## 一、 架构与生态拓扑

RootMyVivo 生态由三个核心开源组件解耦构成：

| 组件仓库 | 职责定位 | 关键技术实现 |
|---|---|---|
| **RootMyVivo**<br>*(主宿主 App)* | Android 客户端与编排控制器 | Kotlin + Jetpack Compose；Shizuku Binder 适配；纯 Kotlin 实现的 `AdbWire` 本地 TCP 5555 通信协议栈；KernelSU 编排；`BootRootService` 开机自愈守护。 |
| **RootMyVivo-Payloads**<br>*(载荷元数据与制品库)* | 集中式二进制编目与校验分发 | `catalog/devices.json` (v5 规范)；以内核 GKI Git ID（如 `g1f71897ac249`）为唯一样本索引；SHA-256 校验与 jsDelivr/GitHub 双镜像。 |
| **RootMyVivo-Exploit**<br>*(核心注入载荷)* | 基于 CVE-2026-43499 的稳定性分支 | 针对 upstream（`boxiaolanya2008` 等）裁剪破坏性逻辑；引入 `safety_quiesce` 负载限流与 `cred-guard` 写入前地址规范性拦截。 |

---

## 二、 全生命周期执行流程

```
┌─────────────────────────────────────────────────────────────┐
│ 1. 采集与安全门禁 (Device.kt)                                │
│    读取 ro.product.model、/proc/version 提取 GKI 指纹       │
│    门禁: 内核 >= 6.6.140 / 6.1.145 / 6.12.86 直接拦截中断   │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 2. 载荷编目匹配与下载 (Catalog.kt)                           │
│    拉取 devices.json (v5) -> 精确匹配 GKI 构建串            │
│    下载匹配的 preload.so 并执行 SHA-256 哈希校验             │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 3. 传输层建立 (Transport.kt)                                 │
│    首次运行: 绑定 Shizuku UserService (uid=2000, shell 域)  │
│    后续运行: 内置 AdbWire 直连 127.0.0.1:5555 TCP 通道      │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 4. 载荷部署与后台执行 (ExploitEngine.kt)                    │
│    部署至 /data/local/tmp/rmv/preload.so                    │
│    后台执行: LD_PRELOAD=preload.so /system/bin/true &       │
│    2s 间隔双通道轮询: live.log 解析 + 本地/Transport su 探针 │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 5. 本地 ADB 鉴权固化 (Transport.persistAfterRoot)            │
│    setprop persist.adb.tcp.port 5555                        │
│    写入 App 自带 RSA 公钥到 /data/misc/adb/adb_keys         │
│    pkill -x adbd 触发 init 重载 -> 建立免配对持久控制链路   │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 6. KernelSU Late-Load 与痕迹清理 (KsuInstaller.kt)          │
│    从已装管理器 APK 提取 libksud.so 确保 CLI 版本一致       │
│    ksud late-load 激活内核模块 -> 缓存 .ko 至 /data/adb/rmv │
│    清理 /data/local/tmp 临时日志，权限重置为 2000:2000      │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 7. 开机自动静默恢复 (BootRootService.kt)                     │
│    监听 BOOT_COMPLETED 广播                                 │
│    通过 127.0.0.1:5555 直连通道静默重放注入与 KSU 加载      │
└─────────────────────────────────────────────────────────────┘
```

---

## 三、 关键模块核心机制

### 1. 指纹提取与版本门禁
- **设备代号采集**：读取 `Build.DEVICE`、`Build.MODEL` 与系统属性 `ro.product.model`。
- **GKI 构建识别**：从 `/proc/version` 提取内核编译串（例如 `6.6.89-android15-8-g1f71897ac249-abogki467805059-4k`）。
- **CVE 修补门禁**：
  - Linux 6.6 系列内核 $\ge 6.6.140$ 判定补丁已修合，安全退出；
  - Linux 6.1 系列内核 $\ge 6.1.145$ 安全退出；
  - 避免在已修内核上触发无效利用或内核 Panic。

### 2. 双通道执行传输层（Transport）
传统方案严重依赖 PC 有线连接，RootMyVivo 采用两段式免电脑通信机制：
- **第一阶段（引导期）**：利用用户已配对的 **Shizuku**，通过 Binder 绑定 `IShellService`（运行在 `uid=2000`、`u:r:shell:s0` 域），用于向 `/data/local/tmp` 部署载荷并拉起初始进程。
- **第二阶段（固化期）**：
  在初次取得 Root 权限的瞬间完成环境持久化：
  ```sh
  setprop persist.adb.tcp.port 5555
  echo "<App内嵌生成的RSA公钥> rootmyvivo" >> /data/misc/adb/adb_keys
  pkill -x adbd
  ```
  `adbd` 重新拉起后将监听 `127.0.0.1:5555`，且系统级信任该 App。App 即可通过纯 Kotlin 协议栈 `AdbWire` 直连本机 ADB，彻底脱离 Shizuku。

### 3. 载荷执行与状态捕获（ExploitEngine）
- **非阻塞拉起**：
  ```sh
  cd /data/local/tmp/rmv && (RMV_ATTEMPTS='3' RMV_RETRY_DELAY='8' LD_PRELOAD=/data/local/tmp/rmv/preload.so /system/bin/true > live.log 2>&1 &)
  ```
- **双通道轮询**：
  - 每隔 2 秒探查一次 `live.log` 尾部输出以更新 UI 进度（支持 `RMV-PROOF` HMAC 验证）。
  - 双通道检测 Root 达成：优先调用 App 本地 `suLocal`（直连漏洞暴露的 Unix Domain Socket），同时通过 Transport 运行 `su -c id` 探针检测 `uid=0`。
- **断点挂载（RunAttached）**：
  App 被系统后台杀死或重新打开时，检索 `/proc/[0-9]*/maps` 中是否包含 `rmv/preload.so`，若发现未退出的进程则直接接管状态监听，避免重复并发调用导致内核踩踏。

### 4. 相比早期社区脚本的关键稳定性改进

| 历史方案（Upstream）的问题 | RootMyVivo 的稳定性解决方案 |
|---|---|
| 强制篡改桌面壁纸、强杀 `system_server` 导致系统震荡与软重启。 | **全部剥离**：不改写壁纸，不主动杀死系统服务。 |
| 在 `/apex/com.android.virt` 挂载 tmpfs 放置 su 导致软重启时 Zygote 黑屏卡死。 | **完全移除该 tmpfs 覆盖**：仅在 userspace 维护纯净链接。 |
| 常驻 39555 端口的 io 调试 daemon，占用系统资源且易被感知。 | **彻底删除该守护进程**。 |
| 内核高负载下内存状态未静止，易产生非法地址解引用导致 Panic。 | **引入 `safety_quiesce`**：等待系统 `loadavg < 4` 且稳定后再触发关键路由。 |
| Reclaim 失败后写入野指针破坏内核结构。 | **引入 `cred-guard`**：写入 UID 0 前执行内核指针规范性与对齐校验。 |

### 5. KernelSU Late-Load 与模块适配
- **CLI 严格对齐**：优先解压目标手机已安装管理器（KernelSU / SukiSU / ReSukiSU）的 `lib/arm64-v8a/libksud.so`，防止外部下载的 ksud 与管理界面的 API/IPC 协议不兼容。
- **模块加载**：
  ```sh
  ksud late-load --allow-shell --package-name <manager_pkg>
  ```
- **Vermagic 适配**：对内核 vermagic 长度超出标准的情况，自动分离原始 `.ko`（供 ksud kallsyms 自适应加载）与修补后 `.ko`（用于持久化环境）。

### 6. 开机静默恢复守护（BootRootService）
- 注册开机广播监听 `BOOT_COMPLETED`。
- 手机冷启动重启后，虽然内存中的 LKM 模块与临时 Root 消失，但由于 ADB TCP 5555 与 App 专属密钥已被持久写入，系统开机后 App 即可在后台直接通过 TCP 连入本地 Shell 域。
- 后台唤醒 `/data/local/tmp/rmv/preload.so` 重跑注入，并从 `/data/adb/rmv/` 本地缓存加载 `kernelsu.ko`，无需电脑再次插线或人工交互。
