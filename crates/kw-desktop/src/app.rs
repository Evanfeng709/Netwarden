//! 纯 Rust 桌面客户端主界面（egui / eframe）：1:1 Termius 风格布局与全量业务闭环。

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, CursorIcon, Event, FontData, FontDefinitions,
    FontFamily, FontId, Frame, Id, Key, Layout, Margin, Order, Pos2, Rect, RichText, ScrollArea,
    Sense, Stroke, StrokeKind, Vec2, ViewportCommand,
};
use serde_json::{json, Value};

use kw_core::Secret;
use kw_ffi::ms_sync;
use kw_ffi::MobileEngine;
use kw_keys::localkeys::LocalKeyEntry;
use kw_server::connect::ConnectBody;
use kw_server::routes::bootstrap_hosts;
use kw_ssh::metrics::MonitorSnapshot;
use kw_store::{Host as HostEntry, HostPatch, SettingsPatch};

use crate::desktop::{
    is_system_dark, read_theme, save_bounds, save_theme, save_ui_mode, trim_working_set, Bounds,
};
use crate::icons::{draw_icon, Icon};
use crate::theme::{apply_palette, resolve_palette, Palette, PALETTES, THEME_CHOICES};
use crate::vt::{is_wide_char, VtScreen};

/// 毫秒时间戳 → `MM-DD HH:MM`（东八区）。同步结果卡里的「上次同步」用。
fn fmt_epoch_ms(ms: u64) -> String {
    let stamp = kw_ssh::util::shanghai_stamp(std::time::UNIX_EPOCH + Duration::from_millis(ms));
    if stamp.len() >= 14 {
        format!(
            "{}-{} {}:{}",
            &stamp[4..6],
            &stamp[6..8],
            &stamp[8..10],
            &stamp[10..12]
        )
    } else {
        "—".to_string()
    }
}

/// SSH 登录密码的本机独立存储（host_id -> 密码）。
/// 与 config.json / 云同步 / 导出完全隔离，沿用 proxy-auth.json 的同级安全口径：
/// 只有用户在「添加 / 编辑服务器」里填写才落盘，Windows 依赖用户目录 ACL。
fn login_pw_file(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("login-auth.json")
}

fn read_login_pw(data_dir: &std::path::Path, host_id: &str) -> Option<String> {
    let text = std::fs::read_to_string(login_pw_file(data_dir)).ok()?;
    let map: HashMap<String, String> = serde_json::from_str(&text).ok()?;
    map.get(host_id).cloned().filter(|s| !s.is_empty())
}

fn write_login_pw(data_dir: &std::path::Path, host_id: &str, password: Option<&str>) {
    let path = login_pw_file(data_dir);
    let mut map: HashMap<String, String> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    match password {
        Some(p) if !p.is_empty() => {
            map.insert(host_id.to_string(), p.to_string());
        }
        _ => {
            map.remove(host_id);
        }
    }
    if map.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    if let Ok(text) = serde_json::to_string_pretty(&map) {
        let _ = std::fs::write(&path, text);
    }
}

/// 认证方式的本机独立存储：host_id -> "password" / "key"。
/// 与 config.json / 云同步 / 导出隔离，和 login-auth.json 同级。
fn auth_method_file(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("auth-method.json")
}

fn read_auth_method(data_dir: &std::path::Path, host_id: &str) -> Option<String> {
    let text = std::fs::read_to_string(auth_method_file(data_dir)).ok()?;
    let map: HashMap<String, String> = serde_json::from_str(&text).ok()?;
    map.get(host_id)
        .cloned()
        .filter(|s| s == "password" || s == "key")
}

fn write_auth_method(data_dir: &std::path::Path, host_id: &str, method: Option<&str>) {
    let path = auth_method_file(data_dir);
    let mut map: HashMap<String, String> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    match method {
        Some(m) if m == "password" || m == "key" => {
            map.insert(host_id.to_string(), m.to_string());
        }
        _ => {
            map.remove(host_id);
        }
    }
    if map.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    if let Ok(text) = serde_json::to_string_pretty(&map) {
        let _ = std::fs::write(&path, text);
    }
}

/// 私钥是否真的需要口令。连接时用的 `private_key_openssh` 内部就是
/// `kw_keys::keygen::load_private_key`，所以这个预检不会和后端判定不一致。
fn private_key_needs_passphrase(path: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    match kw_keys::keygen::load_private_key(&text, None) {
        Ok(_) => false,
        Err(e) => e.contains("passphrase") || e.contains("ENCRYPTED"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Keys,
    Term,
    Files,
    Monitor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyFilter {
    All,
    Unmatched,
    Dup,
    Used,
}

#[derive(Debug, Clone)]
struct LogItem {
    time: String,
    text: String,
    kind: LogKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogKind {
    Info,
    Ok,
    Warn,
    Err,
}

#[derive(Debug, Clone)]
enum Drawer {
    None,
    HostEdit {
        id: Option<String>,
        name: String,
        host: String,
        port: String,
        username: String,
        auth_method: String,
        password: String,
        identity_file: String,
        remote_path: String,
        proxy_enabled: bool,
        proxy_expanded: bool,
        proxy_kind: String,
        proxy_host: String,
        proxy_port: String,
        proxy_username: String,
        proxy_password: String,
        remember_proxy_password: bool,
        proxy_pw_saved: bool,
        proxy_testing: bool,
        proxy_test: Option<(bool, String)>,
    },
    ConnectPrompt {
        host: HostEntry,
        target_mode: ViewMode,
        password: String,
        passphrase: String,
        proxy_password: String,
        trust_fp: Option<String>,
        hostkey_warning: Option<(String, String, bool)>,
        proxy_notice: Option<String>,
    },
    AddKey {
        tab: usize,
        algo: String,
        label: String,
        comment: String,
        passphrase: String,
        selected_local_pub: String,
        pasted_pub: String,
    },
    ReplaceKey {
        old_index: i64,
        old_comment: String,
        old_fp: String,
        tab: usize,
        algo: String,
        label: String,
        comment: String,
        passphrase: String,
        selected_priv_path: String,
    },
    EditNote {
        fingerprint: String,
        comment: String,
        note: String,
    },
    ConfirmDelete {
        fingerprints: Vec<String>,
        message: String,
    },
    Backups {
        items: Vec<Value>,
        selected_name: String,
        diff: Option<Value>,
    },
    Sshd {
        info: Value,
    },
    Sync {
        client_id: String,
        passphrase: String,
        remember_key: bool,
        device_prompt: Option<(String, String)>,
        conflicts: Vec<Value>,
    },
    Settings {
        theme_choice: String,
        local_key_dir: String,
        save_dir: String,
        remote_path: String,
    },
    FileNewDir {
        name: String,
    },
    FileRename {
        from: String,
        name: String,
    },
    FileChmod {
        path: String,
        mode: String,
    },
    FileRemove {
        path: String,
        is_dir: bool,
    },
}

enum BgEvent {
    Log(String, LogKind),
    Connected {
        session: Value,
        target_mode: ViewMode,
    },
    DeleteNeedsForce {
        fingerprints: Vec<String>,
        message: String,
    },
    ConnectHostKeyPrompt {
        host: HostEntry,
        target_mode: ViewMode,
        password: String,
        passphrase: String,
        proxy_password: String,
        title: String,
        message: String,
        fingerprint: String,
        danger: bool,
    },
    ConnectProxyAuthPrompt {
        host: HostEntry,
        target_mode: ViewMode,
        password: String,
        passphrase: String,
        trust_fp: Option<String>,
        message: String,
    },
    ProxyTested((bool, String)),
    SessionUpdated(Value),
    Disconnected,
    SshdLoaded {
        info: Value,
        open_drawer: bool,
    },
    BackupsLoaded(Vec<Value>),
    BackupDiffLoaded(String, Value),
    SyncStatus(Value),
    SyncDeviceCode {
        user_code: String,
        verify_uri: String,
    },
    SyncDone {
        report: Value,
        status: Value,
    },
    /// 同步进入下一个阶段。界面靠它把「点了没反应」变成看得见的进度。
    SyncProgress(ms_sync::SyncPhase),
    /// 同步失败。跟 `Log` 分开是因为抽屉要留一张红卡 —— 只写日志等于没反馈。
    SyncFailed(String),
    LocalScanDone(Vec<LocalKeyEntry>),
    TermOpened {
        term_id: String,
        cols: usize,
        rows: usize,
    },
    /// 带上 term_id：多会话时要分得清是哪块 PTY 吐的字。
    TermOutput {
        term_id: String,
        bytes: Vec<u8>,
    },
    TermClosed {
        term_id: String,
        error: Option<String>,
    },
    FilesListed {
        path: String,
        entries: Vec<Value>,
    },
    FilesFailed(String),
    FileOpDone(String),
    TransferStarted(Value),
    TransfersUpdated(Vec<Value>),
    MonitorSnapshot {
        sid: String,
        snap: Value,
    },
    MonitorFailed {
        sid: String,
        message: String,
    },
    LatencyMeasured {
        sid: String,
        ms: u64,
    },
}

/// 一个终端标签的完整状态。
///
/// 设计取舍：没有把 `self.session` / `self.files_*` / `self.mon_*` 改成
/// `self.tabs[i].xxx`（那是 150 多处引用，漏改一处就串台），而是反过来 ——
/// **当前活动标签的状态摊在 `self` 上**，老代码照旧读写；
/// 切换标签时做一次 [`KwDesktopApp::stash_active`] / [`KwDesktopApp::activate_tab`] 搬运。
///
/// 代价是切换时一次 clone（VtScreen 只有几十 KB），换来改动面极小。
#[derive(Clone)]
struct TabState {
    /// 标签上显示的名字（user@host）
    title: String,
    /// 关联的 host.id：从主机页点「打开终端」时用它找已有标签，避免重复开
    host_id: String,

    session: Option<Value>,
    term_id: Option<String>,
    vt: VtScreen,
    term_scroll_offset: usize,
    last_sent_size: (usize, usize),

    files_path: String,
    files_path_input: String,
    files_manual_path: bool,
    files_entries: Vec<Value>,
    files_loaded: bool,
    files_error: Option<String>,
    files_selected: Option<String>,

    mon_snap: Option<MonitorSnapshot>,
    mon_error: Option<String>,
    /// 这个标签自己那条链路的往返耗时，切标签时跟着一起搬
    lat_ms: Option<u64>,
}

const SNIPPETS: [(&str, &str); 5] = [
    ("⚡ tmux", "tmux attach || tmux new\r"),
    (
        "docker ps",
        "docker ps --format \"table {{.Names}}\\t{{.Status}}\\t{{.Ports}}\"\r",
    ),
    ("端口监听", "ss -tulpn\r"),
    ("磁盘/内存", "df -h && free -m\r"),
    ("系统负载", "uptime && top -bn1 | head -n 15\r"),
];

/// 一次同步的结果，画成云同步抽屉里的一张卡。
///
/// 之所以要这张卡：原来同步完只往日志抽屉里塞一行字，而日志抽屉默认是关着的，
/// 用户看到的就是「点了一下，什么都没发生」。
struct SyncOutcome {
    ok: bool,
    title: String,
    lines: Vec<String>,
}

pub struct KwDesktopApp {
    rt: tokio::runtime::Handle,
    engine: Arc<MobileEngine>,
    data_dir: PathBuf,
    tx: Sender<BgEvent>,
    rx: Receiver<BgEvent>,

    theme_choice: String,
    palette: Palette,
    mode: ViewMode,
    show_local_panel: bool,
    show_log_drawer: bool,
    was_minimized: bool,
    startup_frames: u8,
    busy: bool,

    /// 同步正在进行的阶段；`Some` 表示抽屉里该显示进度条，同时驱动逐帧重绘。
    sync_phase: Option<ms_sync::SyncPhase>,
    /// 本次同步的起始时刻，用来算「用时 2.4s」。
    sync_started: Option<Instant>,
    /// 上一次同步的结果卡。存在 App 上而非 Drawer 里：抽屉关掉再打开仍要能看到。
    sync_outcome: Option<SyncOutcome>,
    /// 点击同步那一刻本机的主机数，用来算「7 → 8 台」。
    sync_hosts_before: usize,

    hosts: Vec<HostEntry>,
    key_notes: HashMap<String, String>,
    local_keys: Vec<LocalKeyEntry>,
    vault_search: String,

    session: Option<Value>,
    sshd_info: Option<Value>,
    selected_indices: HashSet<i64>,
    key_search: String,
    key_filter: KeyFilter,

    term_id: Option<String>,
    vt: VtScreen,
    term_scroll_offset: usize,
    term_focused: bool,
    last_sent_size: (usize, usize),
    term_selection: Option<((usize, usize), (usize, usize))>,
    term_drag_start: Option<(usize, usize)>,

    /// 多会话标签。空 = 没有任何终端会话；`active` 指向「状态摊在 self 上」的那个。
    tabs: Vec<TabState>,
    active: usize,

    files_path: String,
    files_path_input: String,
    files_manual_path: bool,
    files_entries: Vec<Value>,
    files_loaded: bool,
    files_loading: bool,
    files_error: Option<String>,
    files_selected: Option<String>,
    files_search: String,
    files_local_dir: Option<PathBuf>,
    show_transfers: bool,
    transfers: Vec<Value>,
    last_transfer_poll: Instant,

    mon_interval_ms: u64,
    mon_paused: bool,
    mon_polling: bool,
    mon_sort_by_mem: bool,
    mon_last_poll: Instant,
    mon_snap: Option<MonitorSnapshot>,
    mon_error: Option<String>,

    /// 最近一次 SSH 往返耗时（毫秒），信息条末尾显示。
    lat_ms: Option<u64>,
    lat_last: Instant,
    mon_stale: bool,
    mon_cpu_hist: VecDeque<f64>,
    mon_mem_hist: VecDeque<f64>,
    mon_load_hist: VecDeque<f64>,
    mon_down_hist: VecDeque<f64>,
    mon_up_hist: VecDeque<f64>,
    mon_peak_down: f64,
    mon_peak_up: f64,
    /// 最近一次成功连接的主机名与地址，断线后仍用于标注保留的快照。
    mon_ident: Option<(String, String)>,

    ms_status: Value,
    drawer: Drawer,
    logs: Vec<LogItem>,
    last_bounds_save: Instant,
}

impl KwDesktopApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        rt: tokio::runtime::Handle,
        data_dir: PathBuf,
    ) -> Self {
        setup_fonts(&cc.egui_ctx);

        let base_dir = data_dir
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| data_dir.clone());
        let engine = Arc::new(MobileEngine::new(&base_dir).expect("初始化核心引擎失败"));
        bootstrap_hosts(engine.state());

        let mut theme_choice = read_theme(&data_dir);
        if theme_choice.is_empty() {
            theme_choice = "obsidian".to_string();
            let _ = save_theme(&data_dir, &theme_choice);
        }
        let sys_dark = is_system_dark();
        let palette = resolve_palette(&theme_choice, sys_dark);
        apply_palette(&cc.egui_ctx, &palette);

        // 开屏固定落在「主机与密钥」：终端 / 文件 / 监控三页都依附当前 SSH 会话，
        // 冷启动必然没有会话，恢复上次停留的页面只会让人一开软件就看到一块空面板，
        // 还容易被误判成「连不上」。ui.json 里的 mode 仍由 switch_mode 继续写，
        // 只是不再回读（见 desktop::read_ui 的说明）。
        let mode = ViewMode::Keys;

        let (tx, rx) = mpsc::channel();
        let hosts = engine.state().store.list_hosts();
        let key_notes = engine
            .state()
            .store
            .list_key_notes()
            .into_iter()
            .map(|(k, v)| (k, v.note))
            .collect();
        let ms_status = engine.ms_status();

        let mut app = Self {
            rt,
            engine,
            data_dir,
            tx,
            rx,
            theme_choice,
            palette,
            mode,
            show_local_panel: false,
            show_log_drawer: false,
            was_minimized: false,
            startup_frames: 0,
            busy: false,
            sync_phase: None,
            sync_started: None,
            sync_outcome: None,
            sync_hosts_before: 0,
            hosts,
            key_notes,
            local_keys: Vec::new(),
            vault_search: String::new(),
            session: None,
            sshd_info: None,
            selected_indices: HashSet::new(),
            key_search: String::new(),
            key_filter: KeyFilter::All,
            term_id: None,
            vt: VtScreen::new(100, 30),
            term_scroll_offset: 0,
            term_focused: false,
            last_sent_size: (100, 30),
            term_selection: None,
            term_drag_start: None,
            tabs: Vec::new(),
            active: 0,
            files_path: String::new(),
            files_path_input: String::new(),
            files_manual_path: false,
            files_entries: Vec::new(),
            files_loaded: false,
            files_loading: false,
            files_error: None,
            files_selected: None,
            files_search: String::new(),
            files_local_dir: None,
            show_transfers: false,
            transfers: Vec::new(),
            last_transfer_poll: Instant::now(),
            mon_interval_ms: 2000,
            mon_paused: false,
            mon_polling: false,
            mon_sort_by_mem: false,
            mon_last_poll: Instant::now(),
            mon_snap: None,
            mon_error: None,
            lat_ms: None,
            lat_last: Instant::now(),
            mon_stale: false,
            mon_cpu_hist: VecDeque::new(),
            mon_mem_hist: VecDeque::new(),
            mon_load_hist: VecDeque::new(),
            mon_down_hist: VecDeque::new(),
            mon_up_hist: VecDeque::new(),
            mon_peak_down: 0.0,
            mon_peak_up: 0.0,
            mon_ident: None,
            ms_status,
            drawer: Drawer::None,
            logs: Vec::new(),
            last_bounds_save: Instant::now(),
        };
        app.push_log(
            "就绪：选择主机卡片即可直连管理密钥或开启 SSH 终端",
            LogKind::Info,
        );
        app.trigger_local_scan(false);
        app
    }

    fn push_log(&mut self, text: impl Into<String>, kind: LogKind) {
        let stamp = kw_ssh::util::shanghai_stamp(std::time::SystemTime::now());
        let time = if stamp.len() >= 14 {
            format!("{}:{}:{}", &stamp[8..10], &stamp[10..12], &stamp[12..14])
        } else {
            "00:00:00".to_string()
        };
        self.logs.push(LogItem {
            time,
            text: text.into(),
            kind,
        });
        if self.logs.len() > 200 {
            self.logs.remove(0);
        }
    }

    /// 把一次同步的返回折成抽屉里那张卡。
    ///
    /// 「双向同步」到底合成了什么，是这个功能最该说清楚的事：只说「同步完成」
    /// 等于没说，所以这里把主机增减、备注 / 私钥条数、是否真的上传、上次同步时间
    /// 全部摊开。数字全为零时也要明说「两处已经一致」，免得用户以为没生效。
    fn build_sync_outcome(
        result: &Value,
        hosts_before: usize,
        hosts_after: usize,
        elapsed: Duration,
    ) -> SyncOutcome {
        let inner = result.get("report");
        let count = |key: &str| {
            inner
                .and_then(|r| r.get(key))
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        };
        let pulled = result
            .get("pulled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let pushed = result
            .get("pushed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let last_sync_at = result
            .get("lastSyncAt")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let conflicts: Vec<&Value> = inner
            .and_then(|r| r.get("knownHostConflicts"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().collect())
            .unwrap_or_default();
        if !conflicts.is_empty() {
            let mut lines = vec![
                if pulled {
                    "云端包已拉取并合并进本机".to_string()
                } else {
                    "没有读到云端包".to_string()
                },
                "本机数据未上传：指纹变化要你先确认，否则等于用旧信任覆盖云端".to_string(),
            ];
            for c in conflicts.iter().take(3) {
                let host = c
                    .get("host")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(未知主机)");
                let port = c.get("port").and_then(|v| v.as_u64()).unwrap_or(22);
                lines.push(format!("· {host}:{port} 指纹与云端不一致"));
            }
            if conflicts.len() > 3 {
                lines.push(format!("· 另有 {} 项", conflicts.len() - 3));
            }
            return SyncOutcome {
                ok: false,
                title: format!("同步中断 · {} 项主机指纹待确认", conflicts.len()),
                lines,
            };
        }

        let mut lines = Vec::new();
        lines.push(if pulled {
            "云端包：已拉取并合并".to_string()
        } else {
            "云端还没有同步包，本次为首次上传".to_string()
        });
        let hosts_now = hosts_after;
        lines.push(if hosts_now == hosts_before {
            format!("本机主机：{hosts_now} 台，无增减")
        } else {
            format!("本机主机：{hosts_before} 台 → {hosts_now} 台")
        });

        let added = count("addedHosts");
        let updated = count("updatedHosts");
        let deleted = count("deletedHosts");
        let notes = count("syncedNotes");
        let keys = count("importedKeys");
        lines.push(if added + updated + deleted + notes + keys == 0 {
            "没有需要写入的变化，两边本来就一致".to_string()
        } else {
            format!("新增 {added} · 更新 {updated} · 删除 {deleted} · 备注 {notes} · 私钥 {keys}")
        });
        if !pushed {
            lines.push("未上传：云端这次保持原样".to_string());
        }
        if last_sync_at > 0 {
            lines.push(format!("上次同步：{}", fmt_epoch_ms(last_sync_at)));
        }

        SyncOutcome {
            ok: true,
            title: format!("同步完成 · 用时 {:.1}s", elapsed.as_secs_f32()),
            lines,
        }
    }

    fn reload_store_data(&mut self) {
        self.hosts = self.engine.state().store.list_hosts();
        self.key_notes = self
            .engine
            .state()
            .store
            .list_key_notes()
            .into_iter()
            .map(|(k, v)| (k, v.note))
            .collect();
        self.ms_status = self.engine.ms_status();
    }

    fn trigger_local_scan(&self, force: bool) {
        let state = Arc::clone(self.engine.state());
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let settings = state.current_settings();
            if settings.local_key_dir.is_empty() {
                let _ = tx.send(BgEvent::LocalScanDone(Vec::new()));
                return;
            }
            let scan = state.scan_local(&settings.local_key_dir, force).await;
            let _ = tx.send(BgEvent::LocalScanDone(scan.entries));
        });
    }

    /* ------------------------------------------------------------------ */
    /* 多会话标签                                                          */
    /* ------------------------------------------------------------------ */

    /// 把「摊在 self 上的活动会话状态」存回 `tabs[active]`。
    fn stash_active(&mut self) {
        let Some(t) = self.tabs.get_mut(self.active) else {
            return;
        };
        t.session = self.session.clone();
        t.term_id = self.term_id.clone();
        t.vt = self.vt.clone();
        t.term_scroll_offset = self.term_scroll_offset;
        t.last_sent_size = self.last_sent_size;
        t.files_path = self.files_path.clone();
        t.files_path_input = self.files_path_input.clone();
        t.files_manual_path = self.files_manual_path;
        t.files_entries = self.files_entries.clone();
        t.files_loaded = self.files_loaded;
        t.files_error = self.files_error.clone();
        t.files_selected = self.files_selected.clone();
        t.mon_snap = self.mon_snap.clone();
        t.mon_error = self.mon_error.clone();
        t.lat_ms = self.lat_ms;
    }

    /// 把 `tabs[idx]` 的状态摊回 self 上的那批字段 —— 之后所有老代码都作用在新会话上。
    fn activate_tab(&mut self, idx: usize) {
        if idx >= self.tabs.len() {
            return;
        }
        if idx != self.active {
            self.stash_active();
        }
        self.term_selection = None;
        self.term_drag_start = None;
        let t = self.tabs[idx].clone();
        self.active = idx;
        self.session = t.session;
        self.term_id = t.term_id;
        self.vt = t.vt;
        self.term_scroll_offset = t.term_scroll_offset;
        self.last_sent_size = t.last_sent_size;
        self.files_path = t.files_path;
        self.files_path_input = t.files_path_input;
        self.files_manual_path = t.files_manual_path;
        self.files_entries = t.files_entries;
        self.files_loaded = t.files_loaded;
        self.files_error = t.files_error;
        self.files_selected = t.files_selected;
        self.mon_snap = t.mon_snap;
        self.mon_error = t.mon_error;
        self.lat_ms = t.lat_ms;
        self.files_loading = false;
        self.term_focused = true;
    }

    /// 新建一个空标签并切过去；`session` 留空，等连接流程填。
    fn push_tab(&mut self, title: String, host_id: String) {
        self.stash_active();
        self.tabs.push(TabState {
            title,
            host_id,
            session: None,
            term_id: None,
            vt: VtScreen::new(100, 30),
            term_scroll_offset: 0,
            last_sent_size: (100, 30),
            files_path: String::new(),
            files_path_input: String::new(),
            files_manual_path: false,
            files_entries: Vec::new(),
            files_loaded: false,
            files_error: None,
            files_selected: None,
            mon_snap: None,
            mon_error: None,
            lat_ms: None,
        });
        self.active = self.tabs.len() - 1;
        self.session = None;
        self.term_id = None;
        self.vt = VtScreen::new(100, 30);
        self.term_scroll_offset = 0;
        self.last_sent_size = (100, 30);
        self.term_selection = None;
        self.term_drag_start = None;
        self.files_path.clear();
        self.files_path_input.clear();
        self.files_manual_path = false;
        self.files_entries.clear();
        self.files_loaded = false;
        self.files_error = None;
        self.files_selected = None;
        self.mon_snap = None;
        self.mon_error = None;
        self.lat_ms = None;
        self.term_focused = true;
    }

    /// 关闭一个标签：先放掉它的 PTY 和 SSH 会话，再从列表移除；关的是当前标签就切到相邻的。
    fn close_tab(&mut self, idx: usize) {
        if idx >= self.tabs.len() {
            return;
        }
        // 取这个标签自己的 sid / termId，不必先切过去
        let (sid, tid) = if idx == self.active {
            (self.current_sid(), self.term_id.clone())
        } else {
            let t = &self.tabs[idx];
            (
                t.session
                    .as_ref()
                    .and_then(|s| s.get("sid"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                t.term_id.clone(),
            )
        };

        if sid.is_some() || tid.is_some() {
            let engine = Arc::clone(&self.engine);
            self.rt.spawn(async move {
                if let Some(tid) = tid {
                    let _ = engine.term_close(&tid).await;
                }
                if let Some(sid) = sid {
                    let _ = engine.disconnect(&sid).await;
                }
            });
        }

        self.tabs.remove(idx);
        if self.tabs.is_empty() {
            self.active = 0;
            self.session = None;
            self.term_id = None;
            self.vt = VtScreen::new(100, 30);
            self.files_entries.clear();
            self.files_loaded = false;
            self.mon_snap = None;
            self.push_log("已关闭最后一个终端标签", LogKind::Info);
            return;
        }

        // 切到剩下的相邻标签（activate_tab 内部会重设 active）
        let keep = idx.min(self.tabs.len() - 1);
        self.activate_tab(keep);
    }

    /// 找某个 host 已经开着的标签，用于「打开终端」时复用。
    fn tab_of_host(&self, host_id: &str) -> Option<usize> {
        if host_id.is_empty() {
            return None;
        }
        self.tabs.iter().position(|t| t.host_id == host_id)
    }

    fn switch_mode(&mut self, next: ViewMode) {
        if self.mode == next {
            return;
        }
        self.mode = next;
        let m_str = match next {
            ViewMode::Keys => "keys",
            ViewMode::Term => "term",
            ViewMode::Files => "files",
            ViewMode::Monitor => "monitor",
        };
        save_ui_mode(&self.data_dir, m_str, 0);

        if next == ViewMode::Term {
            self.show_local_panel = false;
            if self.session.is_some() && self.term_id.is_none() {
                self.open_pty();
            }
            self.term_focused = true;
        } else if next == ViewMode::Keys {
            if let Some(sess) = &self.session {
                if sess.get("keysLoaded").and_then(|v| v.as_bool()) == Some(false) {
                    self.refresh_session();
                }
            }
        } else if next == ViewMode::Files {
            self.show_local_panel = false;
            if self.session.is_some() && !self.files_loaded {
                self.load_files(String::new());
            }
        } else if next == ViewMode::Monitor {
            self.show_local_panel = false;
            if self.session.is_some() {
                self.poll_monitor(true);
            }
        }
    }

    fn reset_monitor(&mut self) {
        self.mon_polling = false;
        self.mon_snap = None;
        self.mon_error = None;
        self.mon_stale = false;
        self.mon_cpu_hist.clear();
        self.mon_mem_hist.clear();
        self.mon_load_hist.clear();
        self.mon_down_hist.clear();
        self.mon_up_hist.clear();
        self.mon_peak_down = 0.0;
        self.mon_peak_up = 0.0;
        self.mon_last_poll = Instant::now();
    }

    /// 每 10 秒量一次 SSH 往返，喂给信息条末尾的延迟。
    ///
    /// 用 `exec("true")` 而不是复用 monitor 的快照 —— 后者要读一堆 /proc，
    /// 量出来的是「采集耗时」而不是链路往返。
    fn poll_latency(&mut self) {
        let Some(sid) = self.current_sid() else {
            return;
        };
        if self.lat_last.elapsed() < Duration::from_secs(10) {
            return;
        }
        self.lat_last = Instant::now();
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            if let Ok(v) = engine.ping(&sid).await {
                if let Some(ms) = v.get("ms").and_then(|x| x.as_u64()) {
                    let _ = tx.send(BgEvent::LatencyMeasured { sid, ms });
                }
            }
        });
    }

    fn poll_monitor(&mut self, force: bool) {
        if self.mon_polling || self.mon_paused {
            return;
        }
        let Some(sid) = self.current_sid() else {
            return;
        };
        if !force && self.mon_last_poll.elapsed() < Duration::from_millis(self.mon_interval_ms) {
            return;
        }
        self.mon_polling = true;
        self.mon_last_poll = Instant::now();
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            match engine.monitor_snapshot(&sid).await {
                Ok(snap) => {
                    let _ = tx.send(BgEvent::MonitorSnapshot { sid, snap });
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::MonitorFailed {
                        sid,
                        message: err_text(&e, "监控采样失败"),
                    });
                }
            }
        });
    }

    fn push_monitor_history(&mut self, m: &MonitorSnapshot) {
        fn push(h: &mut VecDeque<f64>, v: f64) {
            if h.len() >= 60 {
                h.pop_front();
            }
            h.push_back(v);
        }
        let mem_pct = if m.mem.total > 0.0 {
            m.mem.used / m.mem.total * 100.0
        } else {
            0.0
        };
        push(&mut self.mon_cpu_hist, m.cpu.total);
        push(&mut self.mon_mem_hist, mem_pct);
        push(&mut self.mon_load_hist, m.load.one);
        push(&mut self.mon_down_hist, m.net.rx_bytes_per_sec);
        push(&mut self.mon_up_hist, m.net.tx_bytes_per_sec);
        self.mon_peak_down = self.mon_peak_down.max(m.net.rx_bytes_per_sec);
        self.mon_peak_up = self.mon_peak_up.max(m.net.tx_bytes_per_sec);
    }

    fn start_connect_flow(&mut self, host: HostEntry, target_mode: ViewMode) {
        self.switch_mode(target_mode);
        let saved_pw = read_login_pw(&self.data_dir, &host.id).unwrap_or_default();
        let method = read_auth_method(&self.data_dir, &host.id).unwrap_or_default();

        // 密码登录：直接用添加时保存的密码，不再弹窗问「服务器密码是多少」。
        // 同时清空私钥路径，避免后端先拿公钥去试认证。
        if method == "password" {
            let mut h = host.clone();
            h.identity_file.clear();
            self.execute_connect(h, target_mode, saved_pw, String::new(), String::new(), None);
            return;
        }

        // 密钥登录：免密私钥直接连；只有私钥确实加密时才弹窗要 passphrase。
        if method == "key" && !private_key_needs_passphrase(&host.identity_file) {
            self.execute_connect(
                host,
                target_mode,
                String::new(),
                String::new(),
                String::new(),
                None,
            );
            return;
        }

        self.drawer = Drawer::ConnectPrompt {
            host,
            target_mode,
            password: saved_pw,
            passphrase: String::new(),
            proxy_password: String::new(),
            trust_fp: None,
            hostkey_warning: None,
            proxy_notice: None,
        };
    }

    fn execute_connect(
        &mut self,
        host: HostEntry,
        target_mode: ViewMode,
        password: String,
        passphrase: String,
        proxy_password: String,
        trust_fp: Option<String>,
    ) {
        self.busy = true;
        self.drawer = Drawer::None;
        let label = if host.name.is_empty() {
            host.host.clone()
        } else {
            host.name.clone()
        };
        self.push_log(
            format!(
                "正在连接 {} ({}@{}:{})…",
                label, host.username, host.host, host.port
            ),
            LogKind::Info,
        );

        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        let with_keys = target_mode == ViewMode::Keys;
        let pw_clone = password.clone();
        let pp_clone = passphrase.clone();
        let proxy_pw_clone = proxy_password.clone();
        let tfp_clone = trust_fp.clone();
        self.rt.spawn(async move {
            let body = ConnectBody {
                host_id: Some(host.id.clone()),
                name: Some(host.name.clone()),
                host: Some(host.host.clone()),
                port: Some(host.port),
                username: Some(host.username.clone()),
                identity_file: Some(host.identity_file.clone()),
                remote_path: Some(host.remote_path.clone()),
                password: Some(Secret::new(password)),
                passphrase: Some(Secret::new(passphrase)),
                trust_fingerprint: trust_fp,
                with_keys: Some(with_keys),
                proxy: kw_server::connect::ProxyRequest {
                    proxy_password: if proxy_password.is_empty() {
                        None
                    } else {
                        Some(Secret::new(proxy_password))
                    },
                    ..Default::default()
                },
            };
            match engine.connect(body).await {
                Ok(val) => {
                    let _ = tx.send(BgEvent::Connected {
                        session: val,
                        target_mode,
                    });
                }
                Err(err) => {
                    let code = err.get("code").and_then(|v| v.as_str()).unwrap_or("");
                    let msg = err
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("连接失败")
                        .to_string();
                    if code == "HOSTKEY_UNKNOWN" || code == "HOSTKEY_CHANGED" {
                        let fp = err
                            .get("details")
                            .and_then(|d| {
                                d.get("fingerprint")
                                    .or_else(|| d.get("current"))
                                    .and_then(|v| v.as_str())
                            })
                            .unwrap_or("")
                            .to_string();
                        let title = if code == "HOSTKEY_CHANGED" {
                            "警告：远程主机密钥已变化！"
                        } else {
                            "首次连接：请确认服务器指纹"
                        };
                        let _ = tx.send(BgEvent::ConnectHostKeyPrompt {
                            host,
                            target_mode,
                            password: pw_clone,
                            passphrase: pp_clone,
                            proxy_password: proxy_pw_clone,
                            title: title.to_string(),
                            message: msg,
                            fingerprint: fp,
                            danger: code == "HOSTKEY_CHANGED",
                        });
                    } else if msg.contains("代理认证失败") || msg.contains("代理要求认证")
                    {
                        let _ = tx.send(BgEvent::ConnectProxyAuthPrompt {
                            host,
                            target_mode,
                            password: pw_clone,
                            passphrase: pp_clone,
                            trust_fp: tfp_clone,
                            message: msg,
                        });
                    } else {
                        let _ = tx.send(BgEvent::Log(format!("连接失败：{msg}"), LogKind::Err));
                    }
                }
            }
        });
    }

    fn start_proxy_test(
        &mut self,
        host_id: Option<String>,
        kind: String,
        proxy_host: String,
        proxy_port: String,
        proxy_username: String,
        proxy_password: String,
        target_host: String,
        target_port: String,
    ) {
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        let proxy_port = proxy_port.trim().parse::<u16>().unwrap_or(1080);
        let target_port = target_port.trim().parse::<u16>().unwrap_or(22);
        self.rt.spawn(async move {
            let body = kw_server::connect::ProxyProbeBody {
                host_id,
                host: Some(target_host),
                port: Some(target_port),
                proxy: kw_server::connect::ProxyRequest {
                    proxy_kind: Some(kind),
                    proxy_host: Some(proxy_host),
                    proxy_port: Some(proxy_port),
                    proxy_username: Some(proxy_username).filter(|s| !s.trim().is_empty()),
                    proxy_password: if proxy_password.is_empty() {
                        None
                    } else {
                        Some(Secret::new(proxy_password))
                    },
                },
            };
            let result = match engine.proxy_test(body).await {
                Ok(v) => {
                    let ms = v.get("ms").and_then(|x| x.as_u64()).unwrap_or(0);
                    let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("");
                    (true, format!("握手成功 · {ms} ms · {kind}"))
                }
                Err(e) => (false, err_text(&e, "代理测试失败")),
            };
            let _ = tx.send(BgEvent::ProxyTested(result));
        });
    }

    fn refresh_session(&mut self) {
        let Some(sid) = self.current_sid() else {
            return;
        };
        self.busy = true;
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            match engine.refresh(&sid).await {
                Ok(val) => {
                    let _ = tx.send(BgEvent::SessionUpdated(val));
                    let _ = tx.send(BgEvent::Log("已刷新服务器公钥列表".into(), LogKind::Ok));
                }
                Err(e) => {
                    let msg = e
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("刷新失败");
                    let _ = tx.send(BgEvent::Log(msg.to_string(), LogKind::Err));
                }
            }
        });
    }

    fn disconnect_session(&mut self) {
        let Some(sid) = self.current_sid() else {
            return;
        };
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let _ = engine.disconnect(&sid).await;
            let _ = tx.send(BgEvent::Disconnected);
        });
    }

    fn load_sshd(&mut self, open_drawer: bool) {
        let Some(sid) = self.current_sid() else {
            return;
        };
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            if let Ok(info) = engine.sshd_status(&sid).await {
                let _ = tx.send(BgEvent::SshdLoaded { info, open_drawer });
            }
        });
    }

    fn open_pty(&mut self) {
        let Some(sid) = self.current_sid() else {
            return;
        };
        let (cols, rows) = (self.vt.cols(), self.vt.rows());
        self.vt = VtScreen::new(cols, rows);
        self.term_scroll_offset = 0;
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            match engine
                .term_open(json!({ "sid": sid, "cols": cols, "rows": rows }))
                .await
            {
                Ok(v) => {
                    let tid = v
                        .get("termId")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let c = v
                        .get("cols")
                        .and_then(|x| x.as_u64())
                        .unwrap_or(cols as u64) as usize;
                    let r = v
                        .get("rows")
                        .and_then(|x| x.as_u64())
                        .unwrap_or(rows as u64) as usize;
                    let _ = tx.send(BgEvent::TermOpened {
                        term_id: tid.clone(),
                        cols: c,
                        rows: r,
                    });
                    loop {
                        match engine.term_read(&tid, Some(150)).await {
                            Ok(chunk) => {
                                if let Some(b64) = chunk.get("data").and_then(|x| x.as_str()) {
                                    if !b64.is_empty() {
                                        if let Ok(bytes) = B64.decode(b64) {
                                            let _ = tx.send(BgEvent::TermOutput {
                                                term_id: tid.clone(),
                                                bytes,
                                            });
                                        }
                                    }
                                }
                                if chunk.get("closed").and_then(|x| x.as_bool()) == Some(true) {
                                    let _ = tx.send(BgEvent::TermClosed {
                                        term_id: tid.clone(),
                                        error: None,
                                    });
                                    break;
                                }
                            }
                            Err(e) => {
                                let msg = e
                                    .get("error")
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string());
                                let _ = tx.send(BgEvent::TermClosed {
                                    term_id: tid.clone(),
                                    error: msg,
                                });
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    let msg = e
                        .get("error")
                        .and_then(|x| x.as_str())
                        .unwrap_or("打开终端失败")
                        .to_string();
                    // 还没拿到 tid 就失败了，用空串表示「不属于任何已有会话」
                    let _ = tx.send(BgEvent::TermClosed {
                        term_id: String::new(),
                        error: Some(msg),
                    });
                }
            }
        });
    }

    fn send_term_bytes(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let Some(tid) = self.term_id.clone() else {
            return;
        };
        let engine = Arc::clone(&self.engine);
        let data = B64.encode(bytes);
        self.rt.spawn(async move {
            let _ = engine
                .term_write(json!({ "termId": tid, "data": data }))
                .await;
        });
    }

    fn send_term_paste(&self, text: &str) {
        if text.is_empty() {
            return;
        }
        if self.vt.bracketed_paste {
            let mut bytes = Vec::with_capacity(text.len() + 16);
            bytes.extend_from_slice(b"\x1b[200~");
            bytes.extend_from_slice(text.as_bytes());
            bytes.extend_from_slice(b"\x1b[201~");
            self.send_term_bytes(&bytes);
        } else {
            self.send_term_bytes(text.as_bytes());
        }
    }

    /* ------------------------------------------------------------------ */
    /* SFTP 文件浏览与传输                                                  */
    /* ------------------------------------------------------------------ */

    /// 空路径表示先取远端 home，再列目录。
    fn load_files(&mut self, path: String) {
        let Some(sid) = self.current_sid() else {
            return;
        };
        self.files_loading = true;
        self.files_error = None;
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let target = if path.trim().is_empty() {
                match engine.sftp_home(&sid).await {
                    Ok(v) => v
                        .get("path")
                        .and_then(|p| p.as_str())
                        .unwrap_or("/")
                        .to_string(),
                    Err(e) => {
                        let _ = tx.send(BgEvent::FilesFailed(err_text(&e, "读取 home 目录失败")));
                        return;
                    }
                }
            } else {
                path
            };
            match engine.sftp_list(&sid, &target).await {
                Ok(v) => {
                    let entries = v
                        .get("entries")
                        .and_then(|a| a.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let _ = tx.send(BgEvent::FilesListed {
                        path: target,
                        entries,
                    });
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::FilesFailed(err_text(&e, "读取远端目录失败")));
                }
            }
        });
    }

    fn reload_files(&mut self) {
        if self.files_path.is_empty() {
            self.load_files(String::new());
        } else {
            self.load_files(self.files_path.clone());
        }
    }

    fn file_mkdir(&mut self, name: String) {
        let name = name.trim().to_string();
        if name.is_empty() {
            self.push_log("文件夹名不能为空", LogKind::Warn);
            return;
        }
        let Some(sid) = self.current_sid() else {
            return;
        };
        let dir = self.files_path.clone();
        let target = join_remote(&dir, &name);
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            match engine.sftp_mkdir(&sid, &target).await {
                Ok(_) => {
                    list_and_notify(&engine, &tx, &sid, &dir).await;
                    let _ = tx.send(BgEvent::FileOpDone(format!("已创建文件夹 {name}")));
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::Log(err_text(&e, "创建文件夹失败"), LogKind::Err));
                }
            }
        });
    }

    fn file_rename(&mut self, from: String, name: String) {
        let name = name.trim().to_string();
        if name.is_empty() {
            self.push_log("新名称不能为空", LogKind::Warn);
            return;
        }
        let Some(sid) = self.current_sid() else {
            return;
        };
        let dir = self.files_path.clone();
        let target = join_remote(kw_keys::pathutil::posix_dirname(&from), &name);
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            match engine.sftp_rename(&sid, &from, &target).await {
                Ok(_) => {
                    list_and_notify(&engine, &tx, &sid, &dir).await;
                    let _ = tx.send(BgEvent::FileOpDone(format!("已重命名为 {name}")));
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::Log(err_text(&e, "重命名失败"), LogKind::Err));
                }
            }
        });
    }

    fn file_remove(&mut self, path: String) {
        let Some(sid) = self.current_sid() else {
            return;
        };
        let dir = self.files_path.clone();
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            match engine.sftp_remove(&sid, &path).await {
                Ok(_) => {
                    list_and_notify(&engine, &tx, &sid, &dir).await;
                    let _ = tx.send(BgEvent::FileOpDone("已删除".to_string()));
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::Log(
                        err_text(&e, "删除失败（非空目录需先清空）"),
                        LogKind::Err,
                    ));
                }
            }
        });
    }

    fn file_chmod(&mut self, path: String, mode: u32) {
        let Some(sid) = self.current_sid() else {
            return;
        };
        let dir = self.files_path.clone();
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            match engine.sftp_chmod(&sid, &path, mode).await {
                Ok(_) => {
                    list_and_notify(&engine, &tx, &sid, &dir).await;
                    let _ = tx.send(BgEvent::FileOpDone(format!("权限已改为 {mode:o}")));
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::Log(err_text(&e, "修改权限失败"), LogKind::Err));
                }
            }
        });
    }

    fn pick_and_upload(&mut self) {
        if self.files_path.is_empty() {
            self.push_log("请先刷新并进入一个远端目录", LogKind::Warn);
            return;
        }
        let mut dialog = rfd::FileDialog::new();
        if let Some(dir) = &self.files_local_dir {
            dialog = dialog.set_directory(dir);
        }
        let Some(path) = dialog.pick_file() else {
            return;
        };
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            return;
        };
        let Some(sid) = self.current_sid() else {
            return;
        };
        self.files_local_dir = path.parent().map(|p| p.to_path_buf());
        let remote = join_remote(&self.files_path, &name);
        let local = path.display().to_string();
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.show_transfers = true;
        self.rt.spawn(async move {
            match engine.sftp_upload(&sid, &local, &remote).await {
                Ok(v) => {
                    let _ = tx.send(BgEvent::TransferStarted(v));
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::Log(err_text(&e, "上传失败"), LogKind::Err));
                }
            }
        });
    }

    fn pick_and_download(&mut self, remote: String, name: String) {
        let Some(sid) = self.current_sid() else {
            return;
        };
        let mut dialog = rfd::FileDialog::new().set_file_name(&name);
        if let Some(dir) = &self.files_local_dir {
            dialog = dialog.set_directory(dir);
        }
        let Some(local) = dialog.save_file() else {
            return;
        };
        self.files_local_dir = local.parent().map(|p| p.to_path_buf());
        let local = local.display().to_string();
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.show_transfers = true;
        self.rt.spawn(async move {
            match engine.sftp_download(&sid, &remote, &local).await {
                Ok(v) => {
                    let _ = tx.send(BgEvent::TransferStarted(v));
                }
                Err(e) => {
                    let _ = tx.send(BgEvent::Log(err_text(&e, "下载失败"), LogKind::Err));
                }
            }
        });
    }

    fn cancel_transfer(&self, id: String) {
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            match engine.transfer_cancel(&id).await {
                Ok(_) => {}
                Err(e) => {
                    let _ = tx.send(BgEvent::Log(err_text(&e, "取消传输失败"), LogKind::Err));
                }
            }
        });
    }

    fn transfers_running(&self) -> bool {
        self.transfers
            .iter()
            .any(|t| t.get("status").and_then(|v| v.as_str()) == Some("running"))
    }

    fn poll_transfers(&mut self) {
        if !self.show_transfers && !self.transfers_running() {
            return;
        }
        if self.last_transfer_poll.elapsed() < Duration::from_millis(600) {
            return;
        }
        let Some(sid) = self.current_sid() else {
            return;
        };
        self.last_transfer_poll = Instant::now();
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let v = engine.transfer_list().await;
            let items: Vec<Value> = v
                .get("items")
                .and_then(|a| a.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter(|t| t.get("sid").and_then(|x| x.as_str()) == Some(sid.as_str()))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            let _ = tx.send(BgEvent::TransfersUpdated(items));
        });
    }

    fn open_file_remove(&mut self, path: String, is_dir: bool) {
        self.drawer = Drawer::FileRemove { path, is_dir };
    }

    fn current_sid(&self) -> Option<String> {
        self.session
            .as_ref()?
            .get("sid")?
            .as_str()
            .map(|s| s.to_string())
    }

    /// 当前主机可辨识的名字（备注名优先，其次地址），用作私钥文件名前缀。
    fn current_host_label(&self) -> Option<String> {
        self.session
            .as_ref()
            .and_then(|s| s.get("host"))
            .and_then(|h| {
                h.get("name")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .or_else(|| h.get("host").and_then(|v| v.as_str()).map(str::trim))
            })
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    }

    /// 本次登录私钥所在目录，新增/更换密钥默认保存到这里。
    fn current_login_key_dir(&self) -> Option<String> {
        let file = self
            .session
            .as_ref()?
            .get("host")?
            .get("identityFile")?
            .as_str()?
            .trim();
        if file.is_empty() {
            return None;
        }
        std::path::Path::new(file)
            .parent()
            .map(|p| p.display().to_string())
            .filter(|p| !p.is_empty())
    }

    /// 新公钥注释默认值：用户名@服务器名-日期，同一天重复生成时带 -2、-3。
    fn default_new_key_comment(&self) -> Option<String> {
        let session = self.session.as_ref()?;
        let host = session.get("host")?;
        let username = host.get("username")?.as_str()?.trim();
        let server_name = host.get("name")?.as_str()?.trim();
        if username.is_empty() || server_name.is_empty() {
            return None;
        }
        let date: String = kw_ssh::util::shanghai_stamp(SystemTime::now())
            .chars()
            .take(8)
            .collect();
        let existing: Vec<String> = session
            .get("items")
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|i| {
                        i.get("comment")
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(kw_server::keys_ops::default_key_comment(
            username,
            server_name,
            &date,
            &existing,
        ))
    }

    fn copy_to_clipboard(&mut self, text: &str, label: &str) {
        if let Ok(mut cb) = arboard::Clipboard::new() {
            let _ = cb.set_text(text.to_string());
            self.push_log(format!("已复制{label}到剪贴板"), LogKind::Ok);
        }
    }

    fn read_from_clipboard(&self) -> String {
        arboard::Clipboard::new()
            .ok()
            .and_then(|mut cb| cb.get_text().ok())
            .unwrap_or_default()
    }

    fn drain_events(&mut self, ctx: &egui::Context) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                BgEvent::Log(msg, kind) => {
                    self.busy = false;
                    self.push_log(msg, kind);
                }
                BgEvent::Connected {
                    session,
                    target_mode,
                } => {
                    self.busy = false;
                    let endpoint = session
                        .get("host")
                        .map(|h| {
                            format!(
                                "{}@{}:{}",
                                h.get("username").and_then(|v| v.as_str()).unwrap_or("root"),
                                h.get("host").and_then(|v| v.as_str()).unwrap_or(""),
                                h.get("port").and_then(|v| v.as_u64()).unwrap_or(22)
                            )
                        })
                        .unwrap_or_default();
                    let label = session
                        .get("host")
                        .and_then(|h| h.get("name"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .unwrap_or("已连接主机")
                        .to_string();
                    self.mon_ident = Some((label.clone(), endpoint.clone()));

                    // 连接成功即建标签（对齐 Netcatty：连上就有终端标签）。
                    // 顺序要紧：push_tab 会把 self.session 置空，所以必须建完标签再赋值会话。
                    let host_id = session
                        .get("host")
                        .and_then(|h| h.get("id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if !host_id.is_empty() {
                        if let Some(i) = self.tab_of_host(&host_id) {
                            // 重连同一台：切回原标签，不重复开
                            if i != self.active {
                                self.stash_active();
                                self.activate_tab(i);
                            }
                        } else {
                            self.push_tab(label.clone(), host_id);
                        }
                    }

                    self.session = Some(session);
                    // 标签里也存一份，切走再切回来会话还在
                    if let Some(t) = self.tabs.get_mut(self.active) {
                        t.session = self.session.clone();
                        t.title = label;
                    }
                    self.selected_indices.clear();
                    self.sshd_info = None;
                    self.files_path.clear();
                    self.files_path_input.clear();
                    self.files_entries.clear();
                    self.files_loaded = false;
                    self.files_loading = false;
                    self.files_error = None;
                    self.files_selected = None;
                    self.transfers.clear();
                    self.reset_monitor();
                    self.push_log(format!("已连接 {endpoint}"), LogKind::Ok);
                    match target_mode {
                        ViewMode::Term => {
                            self.mode = ViewMode::Term;
                            self.open_pty();
                            self.term_focused = true;
                        }
                        ViewMode::Files => {
                            self.mode = ViewMode::Files;
                            self.load_files(String::new());
                        }
                        ViewMode::Keys => {
                            self.mode = ViewMode::Keys;
                            self.load_sshd(false);
                        }
                        ViewMode::Monitor => {
                            self.mode = ViewMode::Monitor;
                            self.poll_monitor(true);
                        }
                    }
                }
                BgEvent::ConnectHostKeyPrompt {
                    host,
                    target_mode,
                    password,
                    passphrase,
                    proxy_password,
                    title,
                    message,
                    fingerprint,
                    danger,
                } => {
                    self.busy = false;
                    self.drawer = Drawer::ConnectPrompt {
                        host,
                        target_mode,
                        password,
                        passphrase,
                        proxy_password,
                        trust_fp: Some(fingerprint),
                        hostkey_warning: Some((title, message, danger)),
                        proxy_notice: None,
                    };
                }
                BgEvent::ConnectProxyAuthPrompt {
                    host,
                    target_mode,
                    password,
                    passphrase,
                    trust_fp,
                    message,
                } => {
                    self.busy = false;
                    self.drawer = Drawer::ConnectPrompt {
                        host,
                        target_mode,
                        password,
                        passphrase,
                        proxy_password: String::new(),
                        trust_fp,
                        hostkey_warning: None,
                        proxy_notice: Some(message),
                    };
                }
                BgEvent::ProxyTested(result) => {
                    self.busy = false;
                    if let Drawer::HostEdit {
                        proxy_testing,
                        proxy_test,
                        ..
                    } = &mut self.drawer
                    {
                        *proxy_testing = false;
                        *proxy_test = Some(result);
                    }
                }
                BgEvent::SessionUpdated(session) => {
                    self.busy = false;
                    self.session = Some(session);
                    self.selected_indices.clear();
                    self.reload_store_data();
                }
                BgEvent::DeleteNeedsForce {
                    fingerprints,
                    message,
                } => {
                    self.busy = false;
                    self.drawer = Drawer::ConfirmDelete {
                        fingerprints,
                        message,
                    };
                }
                BgEvent::Disconnected => {
                    self.busy = false;
                    self.session = None;
                    self.sshd_info = None;
                    self.term_id = None;
                    self.selected_indices.clear();
                    self.files_path.clear();
                    self.files_path_input.clear();
                    self.files_entries.clear();
                    self.files_loaded = false;
                    self.files_loading = false;
                    self.files_error = None;
                    self.files_selected = None;
                    self.transfers.clear();
                    self.show_transfers = false;
                    self.mon_polling = false;
                    self.mon_stale = self.mon_snap.is_some();
                    self.push_log("已断开 SSH 会话", LogKind::Info);
                }
                BgEvent::SshdLoaded { info, open_drawer } => {
                    self.busy = false;
                    self.sshd_info = Some(info.clone());
                    if open_drawer {
                        self.drawer = Drawer::Sshd { info };
                    }
                }
                BgEvent::BackupsLoaded(items) => {
                    self.busy = false;
                    self.drawer = Drawer::Backups {
                        items,
                        selected_name: String::new(),
                        diff: None,
                    };
                }
                BgEvent::BackupDiffLoaded(name, diff) => {
                    self.busy = false;
                    if let Drawer::Backups {
                        selected_name,
                        diff: d_slot,
                        ..
                    } = &mut self.drawer
                    {
                        *selected_name = name;
                        *d_slot = Some(diff);
                    }
                }
                BgEvent::SyncStatus(st) => {
                    self.busy = false;
                    self.sync_phase = None;
                    self.sync_started = None;
                    // 登录态变了，上一次同步的结果卡不再代表当前账号。
                    self.sync_outcome = None;
                    self.ms_status = st;
                }
                BgEvent::SyncDeviceCode {
                    user_code,
                    verify_uri,
                } => {
                    self.busy = false;
                    self.push_log(
                        format!("请在浏览器输入微软设备码：{user_code}"),
                        LogKind::Info,
                    );
                    if let Drawer::Sync { device_prompt, .. } = &mut self.drawer {
                        *device_prompt = Some((user_code, verify_uri));
                    }
                }
                BgEvent::SyncDone { report, status } => {
                    self.busy = false;
                    let elapsed = self
                        .sync_started
                        .take()
                        .map(|t| t.elapsed())
                        .unwrap_or_default();
                    self.sync_phase = None;
                    self.ms_status = status;
                    self.reload_store_data();

                    // 冲突清单落在抽屉里，供用户逐条确认；结果卡同时保留摘要。
                    let conflicts = report
                        .get("report")
                        .and_then(|r| r.get("knownHostConflicts"))
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    if !conflicts.is_empty() {
                        if let Drawer::Sync {
                            conflicts: c_slot, ..
                        } = &mut self.drawer
                        {
                            *c_slot = conflicts;
                        }
                    }

                    let outcome = Self::build_sync_outcome(
                        &report,
                        self.sync_hosts_before,
                        self.hosts.len(),
                        elapsed,
                    );
                    if outcome.ok {
                        self.push_log(
                            format!("{}（{}）", outcome.title, outcome.lines.join("；")),
                            LogKind::Ok,
                        );
                    } else {
                        self.push_log(outcome.title.clone(), LogKind::Warn);
                    }
                    self.sync_outcome = Some(outcome);
                }
                BgEvent::SyncProgress(phase) => {
                    // 首次回调前界面已经先自己置成 Fetching 了，这里只做推进。
                    self.sync_phase = Some(phase);
                    if self.sync_started.is_none() {
                        self.sync_started = Some(Instant::now());
                    }
                }
                BgEvent::SyncFailed(msg) => {
                    self.busy = false;
                    self.sync_phase = None;
                    self.sync_started = None;
                    self.push_log(format!("云同步失败：{msg}"), LogKind::Err);
                    self.sync_outcome = Some(SyncOutcome {
                        ok: false,
                        title: "同步失败".to_string(),
                        lines: vec![msg],
                    });
                }
                BgEvent::LocalScanDone(entries) => {
                    self.local_keys = entries;
                }
                BgEvent::TermOpened {
                    term_id,
                    cols,
                    rows,
                } => {
                    self.term_id = Some(term_id.clone());
                    self.vt.resize(cols, rows);
                    self.last_sent_size = (cols, rows);
                    // 同步到标签：标签栏的连接圆点靠它判断在线
                    if let Some(t) = self.tabs.get_mut(self.active) {
                        t.term_id = Some(term_id);
                    }
                    self.push_log(format!("SSH 终端已就绪 ({cols}×{rows})"), LogKind::Ok);
                }
                BgEvent::TermOutput { term_id, bytes } => {
                    if self.term_id.as_deref() == Some(term_id.as_str()) {
                        self.vt.feed(&bytes);
                        self.term_scroll_offset = 0;
                        ctx.request_repaint();
                    } else if let Some(t) = self
                        .tabs
                        .iter_mut()
                        .find(|t| t.term_id.as_deref() == Some(term_id.as_str()))
                    {
                        t.vt.feed(&bytes);
                    }
                }
                BgEvent::TermClosed { term_id, error } => {
                    let is_active = term_id.is_empty()
                        || self.term_id.as_deref() == Some(term_id.as_str());
                    if is_active {
                        self.term_id = None;
                        if let Some(t) = self.tabs.get_mut(self.active) {
                            t.term_id = None;
                        }
                        if let Some(msg) = error {
                            self.push_log(format!("终端已关闭：{msg}"), LogKind::Warn);
                        } else {
                            self.push_log("SSH 终端会话已结束", LogKind::Info);
                        }
                    } else if let Some(t) = self
                        .tabs
                        .iter_mut()
                        .find(|t| t.term_id.as_deref() == Some(term_id.as_str()))
                    {
                        t.term_id = None;
                    }
                }
                BgEvent::FilesListed { path, entries } => {
                    self.files_loading = false;
                    self.files_loaded = true;
                    self.files_error = None;
                    self.files_path = path.clone();
                    self.files_path_input = path;
                    self.files_entries = entries;
                    self.files_selected = None;
                }
                BgEvent::FilesFailed(msg) => {
                    self.files_loading = false;
                    self.files_loaded = true;
                    self.files_entries.clear();
                    self.files_error = Some(msg.clone());
                    self.push_log(msg, LogKind::Err);
                }
                BgEvent::FileOpDone(msg) => {
                    self.push_log(msg, LogKind::Ok);
                }
                BgEvent::TransferStarted(snapshot) => {
                    self.show_transfers = true;
                    self.last_transfer_poll = Instant::now();
                    self.transfers.insert(0, snapshot);
                }
                BgEvent::TransfersUpdated(items) => {
                    let was_running: HashSet<String> = self
                        .transfers
                        .iter()
                        .filter(|t| t.get("status").and_then(|v| v.as_str()) == Some("running"))
                        .filter_map(|t| t.get("id").and_then(|v| v.as_str()).map(str::to_string))
                        .collect();
                    let uploaded = items.iter().any(|t| {
                        t.get("status").and_then(|v| v.as_str()) == Some("done")
                            && t.get("direction").and_then(|v| v.as_str()) == Some("upload")
                            && t.get("id")
                                .and_then(|v| v.as_str())
                                .is_some_and(|id| was_running.contains(id))
                    });
                    self.transfers = items;
                    if uploaded {
                        self.reload_files();
                    }
                }
                BgEvent::MonitorSnapshot { sid, snap } => {
                    self.mon_polling = false;
                    let is_current = self.current_sid().as_deref() == Some(sid.as_str());
                    match serde_json::from_value::<MonitorSnapshot>(snap) {
                        Ok(m) => {
                            if is_current {
                                self.push_monitor_history(&m);
                                self.mon_snap = Some(m);
                                self.mon_error = None;
                                self.mon_stale = false;
                            } else if let Some(t) = self.tabs.iter_mut().find(|t| {
                                t.session
                                    .as_ref()
                                    .and_then(|s| s.get("id"))
                                    .and_then(|v| v.as_str())
                                    == Some(sid.as_str())
                            }) {
                                t.mon_snap = Some(m);
                                t.mon_error = None;
                            }
                        }
                        Err(e) => {
                            if is_current {
                                self.mon_error = Some(format!("监控数据解析失败：{e}"));
                            }
                        }
                    }
                }
                BgEvent::MonitorFailed { sid, message } => {
                    self.mon_polling = false;
                    if self.current_sid().as_deref() == Some(sid.as_str()) {
                        self.mon_error = Some(message);
                    } else if let Some(t) = self.tabs.iter_mut().find(|t| {
                        t.session
                            .as_ref()
                            .and_then(|s| s.get("id"))
                            .and_then(|v| v.as_str())
                            == Some(sid.as_str())
                    }) {
                        t.mon_error = Some(message);
                    }
                }
                BgEvent::LatencyMeasured { sid, ms } => {
                    if self.current_sid().as_deref() == Some(sid.as_str()) {
                        self.lat_ms = Some(ms);
                        if let Some(t) = self.tabs.get_mut(self.active) {
                            t.lat_ms = Some(ms);
                        }
                    } else if let Some(t) = self.tabs.iter_mut().find(|t| {
                        t.session
                            .as_ref()
                            .and_then(|s| s.get("id"))
                            .and_then(|v| v.as_str())
                            == Some(sid.as_str())
                    }) {
                        t.lat_ms = Some(ms);
                    }
                }
            }
        }
    }
}

impl eframe::App for KwDesktopApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events(ctx);

        if self.startup_frames < 5 {
            self.startup_frames += 1;
            if self.startup_frames == 1 && std::env::var_os("KW_OPEN_HOST_MANAGER").is_some() {
                self.open_host_edit(self.hosts.first().cloned());
            }
            if self.startup_frames == 3 && std::env::var_os("KW_SCREENSHOT_PATH").is_some() {
                ctx.send_viewport_cmd(ViewportCommand::Screenshot(egui::UserData::default()));
            }
            if self.startup_frames == 4 {
                trim_working_set();
            } else {
                ctx.request_repaint_after(Duration::from_millis(80));
            }
        }

        if let Some(shot_path) = std::env::var_os("KW_SCREENSHOT_PATH") {
            ctx.input(|i| {
                for ev in &i.events {
                    if let Event::Screenshot { image, .. } = ev {
                        let _ = image::save_buffer(
                            &shot_path,
                            image.as_raw(),
                            image.width() as u32,
                            image.height() as u32,
                            image::ColorType::Rgba8,
                        );
                    }
                }
            });
        }

        // 定期请求重绘以便后台任务与终端输出实时刷新
        let live = self.busy
            || self.sync_phase.is_some()
            || self.term_id.is_some()
            || self.files_loading
            || self.transfers_running()
            || (self.mode == ViewMode::Files && self.show_transfers)
            || matches!(
                &self.drawer,
                Drawer::HostEdit {
                    proxy_testing: true,
                    ..
                }
            );
        let monitor_live =
            self.mode == ViewMode::Monitor && self.session.is_some() && !self.mon_paused;
        if live {
            ctx.request_repaint_after(Duration::from_millis(40));
        } else if monitor_live {
            ctx.request_repaint_after(Duration::from_millis(200));
        }

        // 最小化时主动回收物理内存工作集，未最大化时定期持久化窗口坐标尺寸
        let minimized = ctx.input(|i| i.viewport().minimized.unwrap_or(false));
        if minimized && !self.was_minimized {
            trim_working_set();
        }
        self.was_minimized = minimized;

        let maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
        if !minimized && !maximized && self.last_bounds_save.elapsed() > Duration::from_secs(2) {
            self.last_bounds_save = Instant::now();
            ctx.input(|i| {
                let vp = i.viewport();
                if let (Some(outer), Some(inner)) = (vp.outer_rect, vp.inner_rect) {
                    let scale = vp.native_pixels_per_point.unwrap_or(1.0) as f64;
                    save_bounds(
                        &self.data_dir,
                        Bounds {
                            x: (outer.min.x as f64 * scale).round() as i32,
                            y: (outer.min.y as f64 * scale).round() as i32,
                            width: (inner.width() as f64 * scale).round() as u32,
                            height: (inner.height() as f64 * scale).round() as u32,
                            scale,
                        },
                    );
                }
            });
        }

        // 全局键盘快捷键（未打开抽屉且非编辑文本框时生效）
        let has_active_edit = ctx.memory(|m| m.focused().is_some() && !self.term_focused);
        if !has_active_edit && matches!(self.drawer, Drawer::None) {
            // 模式切换：Alt + 1..4
            if ctx.input(|i| i.modifiers.alt && !i.modifiers.ctrl) {
                if ctx.input(|i| i.key_pressed(egui::Key::Num1)) {
                    self.switch_mode(ViewMode::Keys);
                } else if ctx.input(|i| i.key_pressed(egui::Key::Num2)) {
                    self.switch_mode(ViewMode::Term);
                } else if ctx.input(|i| i.key_pressed(egui::Key::Num3)) {
                    self.switch_mode(ViewMode::Files);
                } else if ctx.input(|i| i.key_pressed(egui::Key::Num4)) {
                    self.switch_mode(ViewMode::Monitor);
                }
            }
            // 标签轮换：Ctrl + Tab / Ctrl + Shift + Tab
            if self.tabs.len() > 1 {
                let next_tab = ctx.input(|i| {
                    i.modifiers.ctrl && !i.modifiers.shift && i.key_pressed(egui::Key::Tab)
                });
                let prev_tab = ctx.input(|i| {
                    i.modifiers.ctrl && i.modifiers.shift && i.key_pressed(egui::Key::Tab)
                });
                if next_tab {
                    let next_idx = (self.active + 1) % self.tabs.len();
                    self.activate_tab(next_idx);
                    self.switch_mode(ViewMode::Term);
                } else if prev_tab {
                    let prev_idx = if self.active == 0 {
                        self.tabs.len() - 1
                    } else {
                        self.active - 1
                    };
                    self.activate_tab(prev_idx);
                    self.switch_mode(ViewMode::Term);
                }
            }
        }

        self.render_topbar(ctx, maximized);
        self.render_bottom_bar(ctx);
        self.render_sidebar(ctx);

        if self.show_local_panel && self.mode == ViewMode::Keys {
            self.render_local_panel(ctx);
        }

        if self.mode == ViewMode::Files {
            self.poll_transfers();
            if self.session.is_some() && !self.files_loaded && !self.files_loading {
                self.load_files(String::new());
            }
        }

        // 监控页要画图表，终端页要喂信息条 —— 两边共用同一个节流
        if matches!(self.mode, ViewMode::Monitor | ViewMode::Term) {
            self.poll_monitor(false);
        }
        if self.mode == ViewMode::Term {
            self.poll_latency();
        }

        self.render_conn_bar(ctx);

        egui::CentralPanel::default()
            .frame(
                Frame::NONE
                    .fill(self.palette.bg)
                    .inner_margin(Margin::same(16)),
            )
            .show(ctx, |ui| match self.mode {
                ViewMode::Keys => self.render_keys_canvas(ui),
                ViewMode::Term => self.render_term_canvas(ui, ctx),
                ViewMode::Files => self.render_files_canvas(ui),
                ViewMode::Monitor => self.render_monitor_canvas(ui),
            });

        self.render_drawer(ctx);
    }
}

impl KwDesktopApp {
    /// 顶部多会话标签栏。没有任何会话时整条不出现。
    /// 顶栏里的会话标签（原独立标签栏并入顶栏，省掉一条 34px）。
    fn draw_tabs(&mut self, ui: &mut egui::Ui) {
        let p = self.palette;
        // 无会话时不显示孤立的「＋」按钮；左侧「主机与密钥」导航仍可进入。
        if self.tabs.is_empty() {
            return;
        }
        // 只有在终端视图里，活动标签才算"真活动" —— 否则在主机页看它亮着会误导
        let in_term = self.mode == ViewMode::Term;
        let snap: Vec<(String, bool, bool)> = self
            .tabs
            .iter()
            .enumerate()
            .map(|(i, t)| (t.title.clone(), i == self.active, t.term_id.is_some()))
            .collect();
        let mut switch_to: Option<usize> = None;
        let mut close_at: Option<usize> = None;
        let mut new_tab = false;
        let font = FontId::proportional(11.5);

        for (i, (title, active, connected)) in snap.iter().enumerate() {
            let active = *active && in_term;
            let text_w = ui
                .painter()
                .layout_no_wrap(title.clone(), font.clone(), p.text)
                .size()
                .x;
            let (rect, resp) =
                ui.allocate_exact_size(Vec2::new(text_w + 34.0, 22.0), Sense::click());

            if active {
                ui.painter()
                    .rect_filled(rect, CornerRadius::same(5), p.surface3);
                let line = Rect::from_min_max(
                    Pos2::new(rect.left() + 6.0, rect.bottom() - 2.0),
                    Pos2::new(rect.right() - 6.0, rect.bottom()),
                );
                ui.painter()
                    .rect_filled(line, CornerRadius::same(1), p.accent);
            } else if resp.hovered() {
                ui.painter().rect_filled(
                    rect,
                    CornerRadius::same(5),
                    p.surface3.linear_multiply(0.55),
                );
            }

            ui.painter().circle_filled(
                rect.left_center() + Vec2::new(8.0, 0.0),
                2.5,
                if *connected { p.ok } else { p.faint },
            );
            ui.painter().text(
                rect.left_center() + Vec2::new(16.0, 0.0),
                Align2::LEFT_CENTER,
                title,
                font.clone(),
                if active { p.text } else { p.dim },
            );

            let x_rect = Rect::from_center_size(
                Pos2::new(rect.right() - 10.0, rect.center().y),
                Vec2::splat(12.0),
            );
            let x_resp = ui.interact(x_rect, Id::new(("kw_tab_close", i)), Sense::click());
            let xc = if x_resp.hovered() { p.danger } else { p.faint };
            let c = x_rect.center();
            let r = 3.0;
            ui.painter().line_segment(
                [Pos2::new(c.x - r, c.y - r), Pos2::new(c.x + r, c.y + r)],
                Stroke::new(1.1_f32, xc),
            );
            ui.painter().line_segment(
                [Pos2::new(c.x + r, c.y - r), Pos2::new(c.x - r, c.y + r)],
                Stroke::new(1.1_f32, xc),
            );

            if resp.clicked() {
                switch_to = Some(i);
            }
            if x_resp.clicked() {
                close_at = Some(i);
            }
            if !active {
                resp.on_hover_text(format!("切到 {title}"));
            }
        }

        if Self::tiny_btn(ui, "＋", p.dim) {
            new_tab = true;
        }

        if let Some(i) = switch_to {
            if i != self.active {
                self.stash_active();
                self.activate_tab(i);
            }
            // 关键一步：只切数据不切视图的话，点了看着像没反应
            self.switch_mode(ViewMode::Term);
        }
        if let Some(i) = close_at {
            self.close_tab(i);
        }
        if new_tab {
            self.switch_mode(ViewMode::Keys);
        }
    }

    /// 标签栏下方的连接信息条：连接身份 + 系统指标。
    /// 布局照 Netcatty：左边你是谁，右边这台机器累不累。
    fn render_conn_bar(&mut self, ctx: &egui::Context) {
        if self.session.is_none() || self.tabs.is_empty() {
            return;
        }
        let p = self.palette;

        let endpoint = self
            .session
            .as_ref()
            .and_then(|s| s.get("host"))
            .map(|h| {
                format!(
                    "{}@{}",
                    h.get("username").and_then(|v| v.as_str()).unwrap_or("root"),
                    h.get("host").and_then(|v| v.as_str()).unwrap_or("")
                )
            })
            .unwrap_or_else(|| "SSH".to_string());

        let mut metrics: Vec<String> = Vec::new();
        if let Some(s) = &self.mon_snap {
            metrics.push(format!("CPU {:.0}% ({}C)", s.cpu.total, s.cores));
            metrics.push(format!(
                "内存 {}/{}",
                Self::fmt_bytes(s.mem.used),
                Self::fmt_bytes(s.mem.total)
            ));
            if let Some(d) = s.disks.first() {
                metrics.push(format!(
                    "{} {}/{} ({:.0}%)",
                    d.mount,
                    Self::fmt_bytes(d.used),
                    Self::fmt_bytes(d.total),
                    d.percent
                ));
            }
            metrics.push(format!(
                "↓{} ↑{}",
                Self::fmt_rate(s.net.rx_bytes_per_sec),
                Self::fmt_rate(s.net.tx_bytes_per_sec)
            ));
        }
        if let Some(ms) = self.lat_ms {
            metrics.push(format!("{ms}ms"));
        }

        let mut do_copy = false;
        let mut act: Option<u8> = None;
        let mut snippet: Option<&'static str> = None;

        egui::TopBottomPanel::top("kw_connbar")
            .exact_height(26.0)
            .frame(
                Frame::NONE
                    .fill(p.bg_elev)
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .inner_margin(Margin::symmetric(10, 3)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 7.0;

                    // 在线状态指示点 + 主机端点
                    let (dot, _) = ui.allocate_exact_size(Vec2::splat(6.0), Sense::hover());
                    ui.painter().circle_filled(dot.center(), 3.0, p.ok);
                    ui.label(
                        RichText::new(&endpoint)
                            .size(11.0)
                            .monospace()
                            .strong()
                            .color(p.text),
                    );
                    if ui
                        .add(
                            egui::Button::new(RichText::new("⧉").size(11.0).color(p.faint))
                                .frame(false),
                        )
                        .on_hover_text("复制 user@host")
                        .clicked()
                    {
                        do_copy = true;
                    }

                    ui.label(RichText::new("│").size(11.0).color(p.border));

                    if metrics.is_empty() {
                        ui.label(RichText::new("指标采集中…").size(10.5).color(p.faint));
                    } else {
                        for (i, m) in metrics.iter().enumerate() {
                            if i > 0 {
                                ui.label(RichText::new("·").size(10.5).color(p.border));
                            }
                            ui.label(RichText::new(m).size(10.5).color(p.dim));
                        }
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        if Self::tiny_btn(ui, "断开", p.danger) {
                            act = Some(1);
                        }
                        if Self::tiny_btn(ui, "重连", p.dim) {
                            act = Some(2);
                        }
                        if Self::tiny_btn(ui, "清屏", p.dim) {
                            act = Some(3);
                        }
                        ui.menu_button(RichText::new("⚡ 快捷指令").size(10.5).color(p.dim), |ui| {
                            for (lbl, cmd) in SNIPPETS {
                                if ui.button(lbl).clicked() {
                                    snippet = Some(cmd);
                                    ui.close_menu();
                                }
                            }
                        });
                    });
                });
            });

        if do_copy {
            self.copy_to_clipboard(&endpoint, "连接地址");
        }
        if let Some(cmd) = snippet {
            self.send_term_bytes(cmd.as_bytes());
            self.term_focused = true;
        }
        match act {
            Some(1) => self.disconnect_session(),
            Some(2) => self.open_pty(),
            Some(3) => {
                self.vt.clear_scrollback();
                self.send_term_bytes(b"\x0c");
            }
            Some(4) => {
                let txt = self.read_from_clipboard();
                if !txt.is_empty() {
                    self.send_term_bytes(txt.as_bytes());
                }
            }
            Some(5) => {
                let dump = self.vt.all_text();
                self.copy_to_clipboard(&dump, "终端屏幕内容");
            }
            _ => {}
        }
    }

    /// 信息条上的小号文字按钮（无边框，hover 变色）。
    fn tiny_btn(ui: &mut egui::Ui, label: &str, color: Color32) -> bool {
        ui.add(
            egui::Button::new(RichText::new(label).size(10.5).color(color))
                .fill(Color32::TRANSPARENT)
                .stroke(Stroke::NONE)
                .corner_radius(CornerRadius::same(4)),
        )
        .clicked()
    }

    /// 把字节数压成 1.2G / 340M / 9K 这类短串。
    fn fmt_bytes(v: f64) -> String {
        const K: f64 = 1024.0;
        const M: f64 = K * 1024.0;
        const G: f64 = M * 1024.0;
        const T: f64 = G * 1024.0;
        if !v.is_finite() || v <= 0.0 {
            return "0".to_string();
        }
        if v >= T {
            format!("{:.1}T", v / T)
        } else if v >= G {
            format!("{:.1}G", v / G)
        } else if v >= M {
            format!("{:.0}M", v / M)
        } else if v >= K {
            format!("{:.0}K", v / K)
        } else {
            format!("{:.0}B", v)
        }
    }

    /// 速率（字节/秒）。
    fn fmt_rate(v: f64) -> String {
        if !v.is_finite() || v <= 0.0 {
            "0".to_string()
        } else {
            format!("{}/s", Self::fmt_bytes(v))
        }
    }

    fn render_topbar(&mut self, ctx: &egui::Context, maximized: bool) {
        let p = self.palette;
        egui::TopBottomPanel::top("kw_topbar")
            .exact_height(44.0)
            .frame(
                Frame::NONE
                    .fill(p.bg_elev)
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .inner_margin(Margin::symmetric(12, 0)),
            )
            .show(ctx, |ui| {
                let bar_rect = ui.max_rect();
                ui.horizontal_centered(|ui| {
                    // 品牌矢量钥匙 Logo 与标题
                    let (logo_rect, _) =
                        ui.allocate_exact_size(Vec2::new(26.0, 26.0), Sense::hover());
                    ui.painter()
                        .rect_filled(logo_rect, CornerRadius::same(7), p.accent_soft);
                    ui.painter().rect_stroke(
                        logo_rect,
                        CornerRadius::same(7),
                        Stroke::new(1.0_f32, p.accent.gamma_multiply(0.45)),
                        StrokeKind::Inside,
                    );
                    draw_icon(ui.painter(), logo_rect.center(), 14.0, Icon::Key, p.accent);

                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Netwarden")
                            .size(13.5)
                            .strong()
                            .color(p.text),
                    );
                    ui.add_space(6.0);

                    // 固定高度版本胶囊（避免在 horizontal_centered 下被纵向拉伸）
                    let ver = format!("v{}", env!("CARGO_PKG_VERSION").replace('-', "."));
                    let (ver_rect, _) =
                        ui.allocate_exact_size(Vec2::new(84.0, 20.0), Sense::hover());
                    ui.painter()
                        .rect_filled(ver_rect, CornerRadius::same(10), p.surface3);
                    ui.painter().rect_stroke(
                        ver_rect,
                        CornerRadius::same(10),
                        Stroke::new(1.0_f32, p.border),
                        StrokeKind::Inside,
                    );
                    ui.painter().text(
                        ver_rect.center(),
                        egui::Align2::CENTER_CENTER,
                        ver,
                        FontId::monospace(10.5),
                        p.dim,
                    );

                    // 版本号后不再画竖直分隔条：空态时它旁边只剩一个孤零零的按钮，视觉多余。
                    ui.add_space(8.0);
                    self.draw_tabs(ui);

                    if self.busy {
                        ui.add_space(8.0);
                        ui.spinner();
                    }

                    // 右侧功能按钮与原生窗口控制按钮
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;

                        if Self::win_ctrl_btn(ui, &p, Icon::WinClose, true)
                            .on_hover_text("关闭")
                            .clicked()
                        {
                            ctx.send_viewport_cmd(ViewportCommand::Close);
                        }

                        let max_ico = if maximized {
                            Icon::WinRestore
                        } else {
                            Icon::WinMax
                        };
                        if Self::win_ctrl_btn(ui, &p, max_ico, false)
                            .on_hover_text(if maximized {
                                "向下还原"
                            } else {
                                "最大化"
                            })
                            .clicked()
                        {
                            ctx.send_viewport_cmd(ViewportCommand::Maximized(!maximized));
                        }

                        if Self::win_ctrl_btn(ui, &p, Icon::WinMin, false)
                            .on_hover_text("最小化")
                            .clicked()
                        {
                            ctx.send_viewport_cmd(ViewportCommand::Minimized(true));
                        }

                        // 细分隔竖线
                        let (sep_r, _) =
                            ui.allocate_exact_size(Vec2::new(8.0, 18.0), Sense::hover());
                        ui.painter().line_segment(
                            [
                                Pos2::new(sep_r.center().x, sep_r.min.y),
                                Pos2::new(sep_r.center().x, sep_r.max.y),
                            ],
                            Stroke::new(1.0_f32, p.border),
                        );

                        if Self::top_icon_btn(ui, &p, Some(Icon::Settings), "设置", false, false)
                            .on_hover_text("外观主题与默认路径设置")
                            .clicked()
                        {
                            self.open_settings_drawer();
                        }

                        // 一键切换主题配色按钮（仅保留曜石、亚麻）
                        let theme_short = match self.palette.id {
                            "linen" => "亚麻",
                            _ => "曜石",
                        };
                        if Self::top_icon_btn(ui, &p, Some(Icon::Theme), theme_short, false, false)
                            .on_hover_text("点击切换主题配色（曜石 / 亚麻）")
                            .clicked()
                        {
                            let idx = PALETTES
                                .iter()
                                .position(|x| x.id == self.palette.id)
                                .unwrap_or(0);
                            let next_p = PALETTES[(idx + 1) % PALETTES.len()];
                            self.theme_choice = next_p.id.to_string();
                            self.palette = next_p;
                            apply_palette(ctx, &self.palette);
                            let _ = save_theme(&self.data_dir, &self.theme_choice);
                        }

                        let ms_logged_in = self
                            .ms_status
                            .get("loggedIn")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if Self::top_icon_btn(
                            ui,
                            &p,
                            Some(Icon::Cloud),
                            "同步",
                            ms_logged_in,
                            ms_logged_in,
                        )
                        .on_hover_text("微软账号加密云同步")
                        .clicked()
                        {
                            self.open_sync_drawer();
                        }

                        if Self::top_icon_btn(ui, &p, Some(Icon::Server), "管理主机", false, false)
                            .on_hover_text("新增、编辑或删除服务器配置")
                            .clicked()
                        {
                            self.open_host_edit(self.hosts.first().cloned());
                        }

                        if self.mode == ViewMode::Keys {
                            if Self::top_icon_btn(
                                ui,
                                &p,
                                Some(Icon::Folder),
                                "本机密钥",
                                self.show_local_panel,
                                false,
                            )
                            .on_hover_text("展开/收起右侧本机私钥库对照面板")
                            .clicked()
                            {
                                self.show_local_panel = !self.show_local_panel;
                            }
                        }
                    });
                });

                // 标题栏空白区域支持拖拽与双击最大化
                let pointer_pos = ui.input(|i| i.pointer.interact_pos());
                if let Some(pos) = pointer_pos {
                    if bar_rect.contains(pos) && !ui.ctx().is_using_pointer() {
                        if ui.input(|i| {
                            i.pointer
                                .button_double_clicked(egui::PointerButton::Primary)
                        }) {
                            ctx.send_viewport_cmd(ViewportCommand::Maximized(!maximized));
                        } else if ui
                            .input(|i| i.pointer.button_pressed(egui::PointerButton::Primary))
                        {
                            ctx.send_viewport_cmd(ViewportCommand::StartDrag);
                        }
                    }
                }
            });
    }

    fn win_ctrl_btn(ui: &mut egui::Ui, p: &Palette, icon: Icon, is_close: bool) -> egui::Response {
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(34.0, 28.0), Sense::click());
        let hovered = resp.hovered();
        if hovered {
            let bg = if is_close { p.danger } else { p.surface3 };
            ui.painter().rect_filled(rect, CornerRadius::same(6), bg);
            ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
        }
        let fg = if hovered && is_close {
            Color32::WHITE
        } else if hovered {
            p.text
        } else {
            p.dim
        };
        draw_icon(ui.painter(), rect.center(), 11.0, icon, fg);
        resp
    }

    fn top_icon_btn(
        ui: &mut egui::Ui,
        p: &Palette,
        icon: Option<Icon>,
        text: &str,
        active: bool,
        dot: bool,
    ) -> egui::Response {
        let font_id = FontId::proportional(12.0);
        let text_w = ui.fonts(|f| {
            f.layout_no_wrap(text.to_string(), font_id.clone(), p.text)
                .size()
                .x
        });
        let ico_space = if icon.is_some() { 18.0 } else { 0.0 };
        let dot_space = if dot { 10.0 } else { 0.0 };
        let w = (text_w + ico_space + dot_space + 20.0).max(34.0);
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, 28.0), Sense::click());
        let hovered = resp.hovered();

        let fill = if active {
            p.accent_soft
        } else if hovered {
            p.panel
        } else {
            p.surface3
        };
        let border_col = if active || hovered {
            p.accent
        } else {
            p.border
        };
        let fg = if active { p.accent } else { p.text };

        ui.painter().rect_filled(rect, CornerRadius::same(7), fill);
        ui.painter().rect_stroke(
            rect,
            CornerRadius::same(7),
            Stroke::new(1.0_f32, border_col),
            StrokeKind::Inside,
        );

        let mut cur_x = rect.min.x + 10.0;
        if let Some(ic) = icon {
            draw_icon(
                ui.painter(),
                Pos2::new(cur_x + 6.0, rect.center().y),
                12.5,
                ic,
                if active { p.accent } else { p.dim },
            );
            cur_x += 18.0;
        }
        ui.painter().text(
            Pos2::new(cur_x, rect.center().y),
            egui::Align2::LEFT_CENTER,
            text,
            font_id,
            fg,
        );
        if dot {
            ui.painter()
                .circle_filled(Pos2::new(rect.max.x - 9.0, rect.center().y), 3.0, p.ok);
        }
        if hovered {
            ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
        }
        resp
    }

    fn top_tool_btn(ui: &mut egui::Ui, p: &Palette, text: &str, active: bool) -> egui::Response {
        Self::top_icon_btn(ui, p, None, text, active, false)
    }

    fn render_sidebar(&mut self, ctx: &egui::Context) {
        let p = self.palette;
        egui::SidePanel::left("kw_sidebar")
            .exact_width(172.0)
            .resizable(false)
            .frame(
                Frame::NONE
                    .fill(p.bg_elev)
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .inner_margin(Margin::symmetric(10, 12)),
            )
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing.y = 4.0;
                // 侧栏只保留「主机与密钥」；添加主机与终端入口都在主机与密钥页内
                if Self::nav_item(
                    ui,
                    &p,
                    Icon::Server,
                    "主机与密钥",
                    self.mode == ViewMode::Keys && matches!(self.drawer, Drawer::None),
                )
                .clicked()
                {
                    self.drawer = Drawer::None;
                    self.switch_mode(ViewMode::Keys);
                }

                if Self::nav_item(
                    ui,
                    &p,
                    Icon::Folder,
                    "文件管理",
                    self.mode == ViewMode::Files && matches!(self.drawer, Drawer::None),
                )
                .clicked()
                {
                    self.drawer = Drawer::None;
                    self.switch_mode(ViewMode::Files);
                }

                if Self::nav_item(
                    ui,
                    &p,
                    Icon::Pulse,
                    "状态监控",
                    self.mode == ViewMode::Monitor && matches!(self.drawer, Drawer::None),
                )
                .clicked()
                {
                    self.drawer = Drawer::None;
                    self.switch_mode(ViewMode::Monitor);
                }

                ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    if Self::nav_item(
                        ui,
                        &p,
                        Icon::Settings,
                        "全局设置",
                        matches!(self.drawer, Drawer::Settings { .. }),
                    )
                    .clicked()
                    {
                        self.open_settings_drawer();
                    }

                    if Self::nav_item(
                        ui,
                        &p,
                        Icon::Cloud,
                        "云端同步",
                        matches!(self.drawer, Drawer::Sync { .. }),
                    )
                    .clicked()
                    {
                        self.open_sync_drawer();
                    }
                });
            });
    }

    fn nav_item(
        ui: &mut egui::Ui,
        p: &Palette,
        icon: Icon,
        label: &str,
        active: bool,
    ) -> egui::Response {
        let desired = Vec2::new(ui.available_width(), 36.0);
        let (rect, resp) = ui.allocate_exact_size(desired, Sense::click());
        let hovered = resp.hovered();
        if active {
            ui.painter()
                .rect_filled(rect, CornerRadius::same(8), p.accent_soft);
            ui.painter().rect_stroke(
                rect,
                CornerRadius::same(8),
                Stroke::new(1.0_f32, p.accent.gamma_multiply(0.35)),
                StrokeKind::Inside,
            );
            let bar = Rect::from_min_size(
                Pos2::new(rect.min.x, rect.center().y - 9.0),
                Vec2::new(3.0, 18.0),
            );
            ui.painter()
                .rect_filled(bar, CornerRadius::same(2), p.accent);
        } else if hovered {
            ui.painter()
                .rect_filled(rect, CornerRadius::same(8), p.surface3);
        }
        let fg = if active || hovered { p.text } else { p.dim };
        let ico_fg = if active { p.accent } else { fg };
        draw_icon(
            ui.painter(),
            Pos2::new(rect.min.x + 18.0, rect.center().y),
            14.0,
            icon,
            ico_fg,
        );
        ui.painter().text(
            Pos2::new(rect.min.x + 36.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            label,
            FontId::proportional(13.0),
            fg,
        );
        if hovered {
            ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
        }
        resp
    }

    fn render_bottom_bar(&mut self, ctx: &egui::Context) {
        let p = self.palette;
        let height = if self.show_log_drawer { 145.0 } else { 30.0 };
        egui::TopBottomPanel::bottom("kw_logbar")
            .exact_height(height)
            .frame(
                Frame::NONE
                    .fill(p.bg_elev)
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .inner_margin(Margin::symmetric(12, 4)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let connected = self.session.is_some();
                    let dot_color = if connected { p.ok } else { p.faint };
                    let (dot_rect, _) = ui.allocate_exact_size(Vec2::new(8.0, 8.0), Sense::hover());
                    ui.painter()
                        .circle_filled(dot_rect.center(), 3.5, dot_color);

                    let conn_str = if let Some(sess) = &self.session {
                        let h = sess.get("host");
                        format!(
                            "已连接 {}@{}:{}",
                            h.and_then(|x| x.get("username"))
                                .and_then(|x| x.as_str())
                                .unwrap_or("root"),
                            h.and_then(|x| x.get("host"))
                                .and_then(|x| x.as_str())
                                .unwrap_or(""),
                            h.and_then(|x| x.get("port"))
                                .and_then(|x| x.as_u64())
                                .unwrap_or(22)
                        )
                    } else {
                        "未连接".to_string()
                    };
                    ui.label(
                        RichText::new(conn_str)
                            .size(11.5)
                            .strong()
                            .color(if connected { p.ok } else { p.dim }),
                    );
                    // 底栏不再常驻显示最近一条日志；要看日志点右侧「展开日志」。
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let toggle_lbl = if self.show_log_drawer {
                            "▼ 收起日志"
                        } else {
                            "▲ 展开日志"
                        };
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(toggle_lbl).size(11.0).color(p.dim),
                                )
                                .fill(Color32::TRANSPARENT)
                                .stroke(Stroke::NONE),
                            )
                            .clicked()
                        {
                            self.show_log_drawer = !self.show_log_drawer;
                        }
                        if self.show_log_drawer
                            && ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("清空").size(11.0).color(p.dim),
                                    )
                                    .fill(Color32::TRANSPARENT)
                                    .stroke(Stroke::NONE),
                                )
                                .clicked()
                        {
                            self.logs.clear();
                        }
                    });
                });

                if self.show_log_drawer {
                    ui.separator();
                    ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for item in &self.logs {
                                let col = match item.kind {
                                    LogKind::Info => p.dim,
                                    LogKind::Ok => p.ok,
                                    LogKind::Warn => p.warn,
                                    LogKind::Err => p.danger,
                                };
                                ui.label(
                                    RichText::new(format!("[{}] {}", item.time, item.text))
                                        .size(11.5)
                                        .monospace()
                                        .color(col),
                                );
                            }
                        });
                }
            });
    }

    fn render_keys_canvas(&mut self, ui: &mut egui::Ui) {
        let p = self.palette;
        let connected = self.session.is_some();

        if !connected {
            // 页头不显示标题；添加入口在服务器保险库工具栏
            self.render_vault_grid(ui, true);
            return;
        }

        // 已连接：路径与 SSHD 状态 + 远端密钥操作
        Frame::NONE
            .fill(p.panel)
            .stroke(Stroke::new(1.0_f32, p.border))
            .corner_radius(CornerRadius::same(11))
            .inner_margin(Margin::symmetric(14, 10))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    if let Some(sess) = &self.session {
                        let path = sess
                            .get("remotePath")
                            .and_then(|v| v.as_str())
                            .unwrap_or("~/.ssh/authorized_keys");
                        ui.label(RichText::new(path).size(11.5).monospace().color(p.dim));
                    }
                    if let Some(sshd) = &self.sshd_info {
                        let key_only = sshd
                            .get("keyOnly")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let (badge_txt, badge_col) = if key_only {
                            ("SSHD: 仅密钥登录", p.ok)
                        } else {
                            ("SSHD: 密码登录已开启", p.warn)
                        };
                        Frame::NONE
                            .fill(badge_col.gamma_multiply(0.14))
                            .stroke(Stroke::new(1.0_f32, badge_col.gamma_multiply(0.45)))
                            .corner_radius(CornerRadius::same(99))
                            .inner_margin(Margin::symmetric(8, 2))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(badge_txt)
                                        .size(11.0)
                                        .strong()
                                        .color(badge_col),
                                );
                            });
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if Self::action_btn(ui, &p, "断开", false, true).clicked() {
                            self.disconnect_session();
                        }
                        if Self::action_btn(ui, &p, "＋ 添加公钥", true, false).clicked() {
                            self.drawer = Drawer::AddKey {
                                tab: 0,
                                algo: "ed25519".to_string(),
                                label: self
                                    .current_host_label()
                                    .unwrap_or_else(|| "key".to_string()),
                                comment: self.default_new_key_comment().unwrap_or_default(),
                                passphrase: String::new(),
                                selected_local_pub: String::new(),
                                pasted_pub: String::new(),
                            };
                        }
                        // 「打开终端」按钮已移除：连接成功即建标签（见 BgEvent::Connected）
                        if Self::action_btn(ui, &p, "文件管理", false, false).clicked() {
                            self.switch_mode(ViewMode::Files);
                        }
                        if Self::action_btn(ui, &p, "SSHD 安全", false, false).clicked() {
                            self.load_sshd(true);
                        }
                        if Self::action_btn(ui, &p, "历史备份", false, false).clicked() {
                            self.open_backups_drawer();
                        }
                        if Self::action_btn(ui, &p, "↻ 刷新", false, false).clicked() {
                            self.refresh_session();
                        }
                    });
                });
            });

        ui.add_space(10.0);

        // 已连接：渲染搜索栏、筛选按钮与远端密钥列表
        // 服务端 sessionPayload 的字段名是 items / usedKeyFp
        let keys_arr = self
            .session
            .as_ref()
            .and_then(|s| s.get("items"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let active_fp = self
            .session
            .as_ref()
            .and_then(|s| s.get("usedKeyFp"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let mut fp_counts: HashMap<String, usize> = HashMap::new();
        for k in &keys_arr {
            if let Some(fp) = k.get("fingerprint").and_then(|v| v.as_str()) {
                if !fp.is_empty() {
                    *fp_counts.entry(fp.to_string()).or_insert(0) += 1;
                }
            }
        }

        let local_fps: HashSet<String> = self
            .local_keys
            .iter()
            .filter(|lk| !lk.fingerprint.is_empty())
            .map(|lk| lk.fingerprint.clone())
            .collect();

        ui.horizontal(|ui| {
            let (s_rect, _) = ui.allocate_exact_size(Vec2::new(18.0, 18.0), Sense::hover());
            draw_icon(ui.painter(), s_rect.center(), 13.0, Icon::Search, p.dim);
            ui.add(
                egui::TextEdit::singleline(&mut self.key_search)
                    .hint_text("搜索注释、指纹、类型或备注…")
                    .desired_width(280.0),
            );
            ui.add_space(6.0);
            for (kf, lbl) in [
                (KeyFilter::All, "全部"),
                (KeyFilter::Unmatched, "本机无匹配"),
                (KeyFilter::Dup, "重复指纹"),
                (KeyFilter::Used, "当前会话"),
            ] {
                if Self::top_tool_btn(ui, &p, lbl, self.key_filter == kf).clicked() {
                    self.key_filter = kf;
                }
            }

            ui.separator();
            ui.label(
                RichText::new(format!(
                    "共 {} 把公钥 · 已选 {} 项",
                    keys_arr.len(),
                    self.selected_indices.len()
                ))
                .size(12.0)
                .color(p.dim),
            );

            if !self.selected_indices.is_empty() {
                if Self::action_btn(ui, &p, "批量删除所选", false, true).clicked() {
                    self.delete_selected_keys();
                }
                if ui
                    .button(RichText::new("取消全选").size(11.5).color(p.dim))
                    .clicked()
                {
                    self.selected_indices.clear();
                }
            }
        });

        ui.add_space(8.0);

        let q = self.key_search.trim().to_lowercase();
        let kf = self.key_filter;
        let filtered: Vec<Value> = keys_arr
            .into_iter()
            .filter(|k| {
                let fp = k.get("fingerprint").and_then(|v| v.as_str()).unwrap_or("");
                let matched = !fp.is_empty() && local_fps.contains(fp);
                let is_dup = fp_counts.get(fp).copied().unwrap_or(0) > 1;
                let is_used = !active_fp.is_empty() && fp == active_fp;

                match kf {
                    KeyFilter::All => {}
                    KeyFilter::Unmatched => {
                        if matched {
                            return false;
                        }
                    }
                    KeyFilter::Dup => {
                        if !is_dup {
                            return false;
                        }
                    }
                    KeyFilter::Used => {
                        if !is_used {
                            return false;
                        }
                    }
                }

                if q.is_empty() {
                    return true;
                }
                let note = self.key_notes.get(fp).map(|s| s.as_str()).unwrap_or("");
                let hay = format!(
                    "{} {} {} {}",
                    k.get("type").and_then(|v| v.as_str()).unwrap_or(""),
                    fp,
                    k.get("comment").and_then(|v| v.as_str()).unwrap_or(""),
                    note
                )
                .to_lowercase();
                hay.contains(&q)
            })
            .collect();

        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if filtered.is_empty() {
                    Frame::NONE
                        .fill(p.panel)
                        .stroke(Stroke::new(1.0_f32, p.border))
                        .corner_radius(CornerRadius::same(10))
                        .inner_margin(Margin::symmetric(20, 28))
                        .show(ui, |ui| {
                            ui.vertical_centered(|ui| {
                                ui.label(
                                    RichText::new("没有匹配的远端公钥条目")
                                        .size(13.5)
                                        .strong()
                                        .color(p.dim),
                                );
                            });
                        });
                    return;
                }

                for k in filtered {
                    let idx = k.get("index").and_then(|v| v.as_i64()).unwrap_or(0);
                    let key_type = k
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("ssh-key")
                        .to_string();
                    let fp = k
                        .get("fingerprint")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let comment = k
                        .get("comment")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let note = self.key_notes.get(&fp).cloned().unwrap_or_default();
                    let is_used = !active_fp.is_empty() && fp == active_fp;
                    let is_dup = fp_counts.get(&fp).copied().unwrap_or(0) > 1;
                    let local_match_name = self
                        .local_keys
                        .iter()
                        .find(|lk| !fp.is_empty() && lk.fingerprint == fp)
                        .map(|lk| lk.name.clone());

                    let is_selected = self.selected_indices.contains(&idx);
                    let stroke_col = if is_selected { p.accent } else { p.border };

                    Frame::NONE
                        .fill(p.panel)
                        .stroke(Stroke::new(1.0_f32, stroke_col))
                        .corner_radius(CornerRadius::same(10))
                        .inner_margin(Margin::symmetric(12, 10))
                        .show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                let mut checked = is_selected;
                                if ui.checkbox(&mut checked, "").changed() {
                                    if checked {
                                        self.selected_indices.insert(idx);
                                    } else {
                                        self.selected_indices.remove(&idx);
                                    }
                                }

                                ui.label(
                                    RichText::new(format!("#{}", idx + 1))
                                        .size(11.5)
                                        .monospace()
                                        .color(p.faint),
                                );

                                let badge_col = if key_type.contains("ed25519") {
                                    p.ok
                                } else if key_type.contains("rsa") {
                                    p.accent
                                } else {
                                    p.warn
                                };
                                Frame::NONE
                                    .fill(badge_col.gamma_multiply(0.14))
                                    .stroke(Stroke::new(1.0_f32, badge_col.gamma_multiply(0.4)))
                                    .corner_radius(CornerRadius::same(6))
                                    .inner_margin(Margin::symmetric(7, 2))
                                    .show(ui, |ui| {
                                        ui.label(
                                            RichText::new(&key_type)
                                                .size(11.0)
                                                .monospace()
                                                .strong()
                                                .color(badge_col),
                                        );
                                    });

                                if is_used {
                                    Frame::NONE
                                        .fill(p.ok.gamma_multiply(0.15))
                                        .stroke(Stroke::new(1.0_f32, p.ok.gamma_multiply(0.45)))
                                        .corner_radius(CornerRadius::same(6))
                                        .inner_margin(Margin::symmetric(7, 2))
                                        .show(ui, |ui| {
                                            ui.label(
                                                RichText::new("● 当前会话")
                                                    .size(11.0)
                                                    .strong()
                                                    .color(p.ok),
                                            );
                                        });
                                }

                                if is_dup {
                                    Frame::NONE
                                        .fill(p.warn.gamma_multiply(0.15))
                                        .stroke(Stroke::new(1.0_f32, p.warn.gamma_multiply(0.45)))
                                        .corner_radius(CornerRadius::same(6))
                                        .inner_margin(Margin::symmetric(7, 2))
                                        .show(ui, |ui| {
                                            ui.label(
                                                RichText::new("⚠ 重复")
                                                    .size(11.0)
                                                    .strong()
                                                    .color(p.warn),
                                            );
                                        });
                                }

                                if let Some(lname) = &local_match_name {
                                    Frame::NONE
                                        .fill(p.accent_soft)
                                        .stroke(Stroke::new(1.0_f32, p.accent.gamma_multiply(0.4)))
                                        .corner_radius(CornerRadius::same(6))
                                        .inner_margin(Margin::symmetric(7, 2))
                                        .show(ui, |ui| {
                                            ui.label(
                                                RichText::new(format!("本机: {lname}"))
                                                    .size(11.0)
                                                    .color(p.accent),
                                            );
                                        });
                                }

                                if !comment.is_empty() {
                                    ui.label(
                                        RichText::new(&comment).size(13.0).strong().color(p.text),
                                    );
                                } else {
                                    ui.label(RichText::new("(无注释)").size(12.5).color(p.faint));
                                }

                                if !note.is_empty() {
                                    Frame::NONE
                                        .fill(p.surface3)
                                        .corner_radius(CornerRadius::same(5))
                                        .inner_margin(Margin::symmetric(6, 2))
                                        .show(ui, |ui| {
                                            ui.label(
                                                RichText::new(format!("备注: {note}"))
                                                    .size(11.5)
                                                    .color(p.dim),
                                            );
                                        });
                                }

                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if Self::action_btn(ui, &p, "删除", false, true).clicked() {
                                        self.selected_indices.clear();
                                        self.selected_indices.insert(idx);
                                        self.delete_selected_keys();
                                    }
                                    if Self::action_btn(ui, &p, "更换密钥", false, false).clicked()
                                    {
                                        self.drawer = Drawer::ReplaceKey {
                                            old_index: idx,
                                            old_comment: comment.clone(),
                                            old_fp: fp.clone(),
                                            tab: 0,
                                            algo: "ed25519".to_string(),
                                            label: self.current_host_label().unwrap_or_else(|| {
                                                if comment.is_empty() {
                                                    "replaced".to_string()
                                                } else {
                                                    comment.clone()
                                                }
                                            }),
                                            comment: self
                                                .default_new_key_comment()
                                                .unwrap_or_else(|| comment.clone()),
                                            passphrase: String::new(),
                                            selected_priv_path: String::new(),
                                        };
                                    }
                                    if Self::action_btn(ui, &p, "备注", false, false).clicked() {
                                        self.drawer = Drawer::EditNote {
                                            fingerprint: fp.clone(),
                                            comment: comment.clone(),
                                            note: note.clone(),
                                        };
                                    }
                                });
                            });

                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new(format!("复制指纹: {fp}"))
                                                .size(11.5)
                                                .monospace()
                                                .color(p.dim),
                                        )
                                        .fill(p.surface2)
                                        .stroke(Stroke::NONE)
                                        .corner_radius(CornerRadius::same(5)),
                                    )
                                    .on_hover_text("点击复制指纹")
                                    .clicked()
                                {
                                    self.copy_to_clipboard(&fp, "公钥指纹");
                                }
                            });
                        });
                    ui.add_space(6.0);
                }
            });
    }

    fn render_files_canvas(&mut self, ui: &mut egui::Ui) {
        let p = self.palette;
        if self.session.is_none() {
            self.render_vault_grid(ui, false);
            return;
        }

        let endpoint = self
            .session
            .as_ref()
            .and_then(|s| s.get("host"))
            .map(|h| {
                format!(
                    "{}@{}:{}",
                    h.get("username").and_then(|v| v.as_str()).unwrap_or("root"),
                    h.get("host").and_then(|v| v.as_str()).unwrap_or(""),
                    h.get("port").and_then(|v| v.as_u64()).unwrap_or(22)
                )
            })
            .unwrap_or_else(|| "SFTP".to_string());
        let running = self
            .transfers
            .iter()
            .filter(|t| t.get("status").and_then(|v| v.as_str()) == Some("running"))
            .count();

        Frame::NONE
            .fill(p.panel)
            .stroke(Stroke::new(1.0_f32, p.border))
            .corner_radius(CornerRadius::same(11))
            .inner_margin(Margin::symmetric(14, 10))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let (dot_rect, _) = ui.allocate_exact_size(Vec2::new(8.0, 8.0), Sense::hover());
                    ui.painter().circle_filled(dot_rect.center(), 4.0, p.ok);
                    ui.label(
                        RichText::new(&endpoint)
                            .size(13.0)
                            .monospace()
                            .strong()
                            .color(p.text),
                    );
                    ui.separator();
                    ui.label(RichText::new("SFTP 文件管理").size(11.5).color(p.dim));

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if Self::action_btn(ui, &p, "断开", false, true).clicked() {
                            self.disconnect_session();
                        }
                        if Self::action_btn(ui, &p, "上传文件", false, false).clicked() {
                            self.pick_and_upload();
                        }
                        if Self::action_btn(ui, &p, "＋ 新建文件夹", false, false).clicked() {
                            self.drawer = Drawer::FileNewDir {
                                name: String::new(),
                            };
                        }
                        if Self::action_btn(ui, &p, "↻ 刷新", false, false).clicked() {
                            self.reload_files();
                        }
                        let transfer_label = if running > 0 {
                            format!("传输 {running} 进行中")
                        } else {
                            "传输记录".to_string()
                        };
                        if Self::top_tool_btn(ui, &p, &transfer_label, self.show_transfers)
                            .clicked()
                        {
                            self.show_transfers = !self.show_transfers;
                            if self.show_transfers {
                                self.last_transfer_poll = Instant::now() - Duration::from_secs(1);
                            }
                        }
                    });
                });
            });

        ui.add_space(8.0);

        ui.horizontal(|ui| {
            let parent = kw_keys::pathutil::posix_dirname(&self.files_path).to_string();
            if Self::mini_btn(ui, &p, "↑ 上级", false).clicked()
                && !self.files_path.is_empty()
                && parent != self.files_path
            {
                self.load_files(parent);
            }

            if self.files_manual_path {
                let (s_rect, _) = ui.allocate_exact_size(Vec2::new(18.0, 18.0), Sense::hover());
                draw_icon(ui.painter(), s_rect.center(), 13.0, Icon::Folder, p.dim);
                let path_edit = ui.add(
                    egui::TextEdit::singleline(&mut self.files_path_input)
                        .hint_text("/home/user")
                        .font(FontId::monospace(12.0))
                        .desired_width(320.0),
                );
                let jump_clicked = Self::action_btn(ui, &p, "跳转", false, false).clicked();
                let enter_pressed = path_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if jump_clicked || enter_pressed {
                    let target = self.files_path_input.trim().to_string();
                    if !target.is_empty() {
                        self.load_files(target);
                        self.files_manual_path = false;
                    }
                }
                if Self::mini_btn(ui, &p, "✕", false).clicked() {
                    self.files_manual_path = false;
                }
            } else {
                // 面包屑分段式导航（Netcatty 风格）
                let mut navigate_to: Option<String> = None;
                Frame::NONE
                    .fill(p.surface2)
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .corner_radius(CornerRadius::same(7))
                    .inner_margin(Margin::symmetric(8, 4))
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        let (s_rect, _) = ui.allocate_exact_size(Vec2::new(16.0, 16.0), Sense::hover());
                        draw_icon(ui.painter(), s_rect.center(), 12.0, Icon::Folder, p.accent);

                        if ui.add(egui::Label::new(RichText::new("/").size(12.0).strong().monospace().color(p.text)).sense(Sense::click()))
                            .on_hover_text("根目录 /")
                            .clicked()
                        {
                            navigate_to = Some("/".to_string());
                        }

                        let parts: Vec<&str> = self.files_path.split('/').filter(|s| !s.is_empty()).collect();
                        let mut accum = String::new();
                        for (idx, part) in parts.iter().enumerate() {
                            accum.push('/');
                            accum.push_str(part);
                            let target_path = accum.clone();
                            ui.label(RichText::new("›").size(11.0).color(p.faint));
                            let is_last = idx == parts.len() - 1;
                            let text_color = if is_last { p.accent } else { p.text };
                            let resp = ui.add(
                                egui::Label::new(
                                    RichText::new(*part)
                                        .size(12.0)
                                        .strong()
                                        .monospace()
                                        .color(text_color)
                                )
                                .sense(Sense::click())
                            )
                            .on_hover_text(format!("进入 {target_path}"));
                            if resp.clicked() && !is_last {
                                navigate_to = Some(target_path);
                            }
                        }

                        if ui.add(egui::Label::new(RichText::new(" ✏ ").size(10.0).color(p.faint)).sense(Sense::click()))
                            .on_hover_text("点击切换为手动输入路径")
                            .clicked()
                        {
                            self.files_manual_path = true;
                            self.files_path_input = self.files_path.clone();
                        }
                    });

                if let Some(target) = navigate_to {
                    self.load_files(target);
                }
            }

            ui.separator();
            let (s_rect, _) = ui.allocate_exact_size(Vec2::new(18.0, 18.0), Sense::hover());
            draw_icon(ui.painter(), s_rect.center(), 13.0, Icon::Search, p.dim);
            ui.add(
                egui::TextEdit::singleline(&mut self.files_search)
                    .hint_text("筛选当前目录…")
                    .desired_width(180.0),
            );
            if self.files_loading {
                ui.spinner();
            }
        });

        ui.add_space(8.0);

        let q = self.files_search.trim().to_lowercase();
        let entries: Vec<Value> = self
            .files_entries
            .iter()
            .filter(|e| {
                q.is_empty()
                    || e.get("name")
                        .and_then(|v| v.as_str())
                        .map(|n| n.to_lowercase().contains(&q))
                        .unwrap_or(false)
            })
            .cloned()
            .collect();
        let transfers_h = if self.show_transfers { 148.0 } else { 0.0 };
        let list_h = (ui.available_height() - transfers_h - 10.0).max(120.0);

        ScrollArea::vertical()
            .id_salt("files_list")
            .max_height(list_h)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if entries.is_empty() {
                    let hint = if self.files_loading {
                        "正在读取远端目录…"
                    } else if let Some(err) = &self.files_error {
                        err.as_str()
                    } else if self.files_entries.is_empty() {
                        "这个目录是空的"
                    } else {
                        "没有匹配的文件名"
                    };
                    Frame::NONE
                        .fill(p.panel)
                        .stroke(Stroke::new(1.0_f32, p.border))
                        .corner_radius(CornerRadius::same(10))
                        .inner_margin(Margin::symmetric(20, 26))
                        .show(ui, |ui| {
                            ui.vertical_centered(|ui| {
                                ui.label(RichText::new(hint).size(13.0).strong().color(p.dim));
                            });
                        });
                    return;
                }
                for entry in &entries {
                    self.render_file_row(ui, entry);
                }
            });

        if self.show_transfers {
            ui.add_space(8.0);
            self.render_transfers(ui);
        }
    }

    fn render_file_row(&mut self, ui: &mut egui::Ui, entry: &Value) {
        let p = self.palette;
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let path = entry
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let kind = entry
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("other")
            .to_string();
        let is_dir = kind == "dir";
        let size = entry.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        let perms = entry
            .get("permissions")
            .and_then(|v| v.as_u64())
            .map(|m| format!("{:03o}", m & 0o7777))
            .unwrap_or_else(|| "—".to_string());
        let mode_text = entry
            .get("permissions")
            .and_then(|v| v.as_u64())
            .map(|m| format!("{:o}", m & 0o7777))
            .unwrap_or_else(|| "644".to_string());
        let mtime = entry
            .get("mtime")
            .and_then(|v| v.as_u64())
            .map(format_unix_time)
            .unwrap_or_else(|| "—".to_string());
        let selected = self.files_selected.as_deref() == Some(path.as_str());

        let mut do_download: Option<(String, String)> = None;
        let mut do_load_dir: Option<String> = None;
        let mut do_rename: Option<(String, String)> = None;
        let mut do_chmod: Option<(String, String)> = None;
        let mut do_copy_path: Option<String> = None;
        let mut do_delete: Option<(String, bool)> = None;

        let row_h = 30.0;
        let (row_rect, row_resp) = ui.allocate_exact_size(
            Vec2::new(ui.available_width(), row_h),
            Sense::click(),
        );

        let hovered = row_resp.hovered();
        let fill_bg = if selected {
            p.accent_soft
        } else if hovered {
            p.surface3
        } else {
            p.panel
        };
        let border_col = if selected {
            p.accent
        } else if hovered {
            p.border
        } else {
            p.border.gamma_multiply(0.4)
        };

        ui.painter().rect_filled(row_rect, CornerRadius::same(6), fill_bg);
        ui.painter().rect_stroke(
            row_rect,
            CornerRadius::same(6),
            Stroke::new(1.0_f32, border_col),
            StrokeKind::Inside,
        );

        if hovered {
            ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
        }
        if row_resp.clicked() {
            self.files_selected = Some(path.clone());
        }
        if row_resp.double_clicked() {
            if is_dir {
                do_load_dir = Some(path.clone());
            } else {
                do_download = Some((path.clone(), name.clone()));
            }
        }

        // 右键上下文菜单（彻底对齐 Netcatty 现代文件管理器交互）
        row_resp.context_menu(|ui| {
            ui.set_min_width(140.0);
            if is_dir {
                if ui.button("📂 进入文件夹").clicked() {
                    do_load_dir = Some(path.clone());
                    ui.close_menu();
                }
            } else {
                if ui.button("📥 下载文件").clicked() {
                    do_download = Some((path.clone(), name.clone()));
                    ui.close_menu();
                }
            }
            if ui.button("✏️ 重命名").clicked() {
                do_rename = Some((path.clone(), name.clone()));
                ui.close_menu();
            }
            if ui.button("🔒 修改权限 (chmod)").clicked() {
                do_chmod = Some((path.clone(), mode_text.clone()));
                ui.close_menu();
            }
            if ui.button("📋 复制绝对路径").clicked() {
                do_copy_path = Some(path.clone());
                ui.close_menu();
            }
            ui.separator();
            if ui.button(RichText::new("🗑️ 删除").color(p.danger)).clicked() {
                do_delete = Some((path.clone(), is_dir));
                ui.close_menu();
            }
        });

        // 绘制行内元素：左侧图标 + 文件名，右侧大小 + 权限 + 时间
        let icon = if is_dir {
            Icon::Folder
        } else if kind == "symlink" {
            Icon::Link
        } else {
            Icon::File
        };
        let ico_pos = Pos2::new(row_rect.min.x + 16.0, row_rect.center().y);
        draw_icon(
            ui.painter(),
            ico_pos,
            13.0,
            icon,
            if is_dir { p.warn } else if kind == "symlink" { p.accent } else { p.dim },
        );

        let text_left = row_rect.min.x + 32.0;
        let right_info_w = 260.0;
        let name_clip = Rect::from_min_max(
            Pos2::new(text_left, row_rect.min.y),
            Pos2::new((row_rect.max.x - right_info_w - 8.0).max(text_left + 40.0), row_rect.max.y),
        );
        let name_painter = ui.painter().with_clip_rect(name_clip);
        name_painter.text(
            Pos2::new(text_left, row_rect.center().y),
            egui::Align2::LEFT_CENTER,
            &name,
            FontId::proportional(12.5),
            if selected { p.accent } else { p.text },
        );

        // 右侧指标列：大小 (70px) · 权限 (50px) · 修改时间 (130px)
        let size_text = if is_dir { "—".to_string() } else { human_size(size) };
        let right_x = row_rect.max.x - 12.0;
        ui.painter().text(
            Pos2::new(right_x, row_rect.center().y),
            egui::Align2::RIGHT_CENTER,
            &mtime,
            FontId::monospace(10.5),
            p.faint,
        );
        ui.painter().text(
            Pos2::new(right_x - 130.0, row_rect.center().y),
            egui::Align2::RIGHT_CENTER,
            &perms,
            FontId::monospace(10.5),
            p.faint,
        );
        ui.painter().text(
            Pos2::new(right_x - 190.0, row_rect.center().y),
            egui::Align2::RIGHT_CENTER,
            size_text,
            FontId::monospace(10.5),
            p.dim,
        );

        ui.add_space(3.0);

        if let Some(target) = do_load_dir {
            self.load_files(target);
        }
        if let Some((p, n)) = do_download {
            self.pick_and_download(p, n);
        }
        if let Some((from, name)) = do_rename {
            self.drawer = Drawer::FileRename { from, name };
        }
        if let Some((path, mode)) = do_chmod {
            self.drawer = Drawer::FileChmod { path, mode };
        }
        if let Some(cp) = do_copy_path {
            self.copy_to_clipboard(&cp, "文件路径");
        }
        if let Some((del_path, del_is_dir)) = do_delete {
            self.open_file_remove(del_path, del_is_dir);
        }
    }

    fn render_transfers(&mut self, ui: &mut egui::Ui) {
        let p = self.palette;
        Frame::NONE
            .fill(p.panel)
            .stroke(Stroke::new(1.0_f32, p.border))
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::symmetric(12, 8))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("传输任务").size(12.0).strong().color(p.dim));
                    ui.label(
                        RichText::new(format!("({})", self.transfers.len()))
                            .size(11.5)
                            .monospace()
                            .color(p.faint),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if Self::mini_btn(ui, &p, "收起", false).clicked() {
                            self.show_transfers = false;
                        }
                    });
                });
                ui.add_space(4.0);
                ScrollArea::vertical()
                    .id_salt("transfer_list")
                    .max_height(96.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        if self.transfers.is_empty() {
                            ui.label(RichText::new("暂无传输任务").size(11.5).color(p.faint));
                            return;
                        }
                        let items = self.transfers.clone();
                        for item in &items {
                            self.render_transfer_row(ui, item);
                        }
                    });
            });
    }

    fn render_transfer_row(&mut self, ui: &mut egui::Ui, item: &Value) {
        let p = self.palette;
        let id = item
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let direction = item
            .get("direction")
            .and_then(|v| v.as_str())
            .unwrap_or("upload");
        let remote = item
            .get("remotePath")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let local = item.get("localPath").and_then(|v| v.as_str()).unwrap_or("");
        let status = item
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("running");
        let done = item.get("done").and_then(|v| v.as_u64()).unwrap_or(0);
        let total = item.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
        let running = status == "running";
        let frac = if total > 0 {
            (done as f32 / total as f32).clamp(0.0, 1.0)
        } else {
            0.0
        };

        Frame::NONE
            .fill(p.surface2)
            .corner_radius(CornerRadius::same(7))
            .inner_margin(Margin::symmetric(9, 5))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (dir_txt, dir_col) = if direction == "upload" {
                        ("↑ 上传", p.accent)
                    } else {
                        ("↓ 下载", p.ok)
                    };
                    ui.label(RichText::new(dir_txt).size(10.5).strong().color(dir_col));
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .desired_width(150.0)
                            .desired_height(14.0)
                            .corner_radius(CornerRadius::same(7))
                            .fill(if running { p.accent } else { p.ok })
                            .text(
                                RichText::new(format!("{}%", (frac * 100.0).round() as u32))
                                    .size(9.5)
                                    .color(Color32::WHITE),
                            ),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{} / {}",
                            human_size(done),
                            if total > 0 {
                                human_size(total)
                            } else {
                                "?".to_string()
                            }
                        ))
                        .size(10.5)
                        .monospace()
                        .color(p.dim),
                    );
                    let shown = if direction == "upload" { remote } else { local };
                    ui.add(
                        egui::Label::new(RichText::new(shown).size(11.0).monospace().color(p.text))
                            .truncate(),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if running {
                            if Self::mini_btn(ui, &p, "取消", true).clicked() {
                                self.cancel_transfer(id.clone());
                            }
                        }
                        let (text, color) = match status {
                            "running" => ("传输中".to_string(), p.accent),
                            "done" => ("完成".to_string(), p.ok),
                            "canceled" => ("已取消".to_string(), p.warn),
                            _ => (
                                format!(
                                    "失败：{}",
                                    item.get("error")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("未知错误")
                                ),
                                p.danger,
                            ),
                        };
                        ui.label(RichText::new(text).size(10.5).color(color));
                    });
                });
            });
        ui.add_space(3.0);
    }

    fn mini_btn(ui: &mut egui::Ui, p: &Palette, label: &str, danger: bool) -> egui::Response {
        let fg = if danger { p.danger } else { p.dim };
        let stroke = if danger {
            p.danger.gamma_multiply(0.35)
        } else {
            p.border
        };
        ui.add(
            egui::Button::new(RichText::new(label).size(10.5).color(fg))
                .fill(Color32::TRANSPARENT)
                .stroke(Stroke::new(1.0_f32, stroke))
                .corner_radius(CornerRadius::same(5))
                .min_size(Vec2::new(0.0, 20.0)),
        )
    }

    fn delete_selected_keys(&mut self) {
        if self.selected_indices.is_empty() {
            return;
        }
        let items: Vec<Value> = self
            .session
            .as_ref()
            .and_then(|s| s.get("items"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut indices: Vec<i64> = self.selected_indices.iter().copied().collect();
        indices.sort_unstable();

        // 服务端按指纹删除，先把选中的行号映射成指纹
        let mut fps: Vec<String> = Vec::new();
        for idx in indices {
            let fp = items
                .iter()
                .find(|k| k.get("index").and_then(|v| v.as_i64()) == Some(idx))
                .and_then(|k| k.get("fingerprint"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !fp.is_empty() && !fps.iter().any(|x| x == fp) {
                fps.push(fp.to_string());
            }
        }
        if fps.is_empty() {
            self.push_log("未找到所选公钥的指纹，请先刷新列表", LogKind::Err);
            return;
        }
        self.delete_keys_by_fingerprints(fps, false);
    }

    fn delete_keys_by_fingerprints(&mut self, fingerprints: Vec<String>, force: bool) {
        let Some(sid) = self.current_sid() else {
            return;
        };
        self.busy = true;
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let mut body = json!({
                "sid": sid,
                "fingerprints": fingerprints.clone(),
            });
            if force {
                body["force"] = json!(true);
            }
            match engine.delete_keys(body).await {
                Ok(val) => {
                    let changed = val
                        .get("changed")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let needs_force = val
                        .get("needsForce")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if changed {
                        if let Some(sess) = val.get("session") {
                            let _ = tx.send(BgEvent::SessionUpdated(sess.clone()));
                        }
                        let _ = tx.send(BgEvent::Log("已删除所选远端公钥".into(), LogKind::Ok));
                    } else if needs_force {
                        let message = val
                            .get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let _ = tx.send(BgEvent::DeleteNeedsForce {
                            fingerprints,
                            message,
                        });
                    } else {
                        let message = val
                            .get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("删除未生效");
                        let _ = tx.send(BgEvent::Log(message.to_string(), LogKind::Warn));
                    }
                }
                Err(e) => {
                    let msg = e
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("删除公钥失败");
                    let _ = tx.send(BgEvent::Log(msg.to_string(), LogKind::Err));
                }
            }
        });
    }

    fn render_monitor_empty(&mut self, ui: &mut egui::Ui) {
        let p = self.palette;
        let h = ui.available_height();
        ui.add_space((h * 0.22).clamp(32.0, 180.0));
        let mut go_keys = false;
        ui.vertical_centered(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(54.0), Sense::hover());
            ui.painter()
                .rect_filled(rect, CornerRadius::same(16), p.surface3);
            ui.painter().rect_stroke(
                rect,
                CornerRadius::same(16),
                Stroke::new(1.0_f32, p.border),
                StrokeKind::Inside,
            );
            draw_icon(ui.painter(), rect.center(), 24.0, Icon::Pulse, p.faint);
            ui.add_space(12.0);
            ui.label(
                RichText::new("还没有连接服务器")
                    .size(14.0)
                    .strong()
                    .color(p.text),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "状态监控依附于当前 SSH 会话。请先在「主机与密钥」里选择一台 Linux 服务器打开终端，监控会随连接自动开始。",
                )
                .size(11.5)
                .color(p.faint),
            );
            ui.add_space(12.0);
            if Self::action_btn(ui, &p, "前往主机与密钥", true, false).clicked() {
                go_keys = true;
            }
        });
        if go_keys {
            self.switch_mode(ViewMode::Keys);
        }
    }

    fn render_monitor_canvas(&mut self, ui: &mut egui::Ui) {
        let p = self.palette;
        let connected = self.session.is_some();
        if !connected && self.mon_snap.is_none() {
            self.render_monitor_empty(ui);
            return;
        }

        let snap = self.mon_snap.clone();
        let err = self.mon_error.clone();
        let stale = self.mon_stale || !connected;
        let paused = self.mon_paused;
        let interval = self.mon_interval_ms;
        let cpu_hist = self.mon_cpu_hist.clone();
        let mem_hist = self.mon_mem_hist.clone();
        let load_hist = self.mon_load_hist.clone();
        let down_hist = self.mon_down_hist.clone();
        let up_hist = self.mon_up_hist.clone();
        let peak_down = self.mon_peak_down;
        let peak_up = self.mon_peak_up;
        let host = self.session.as_ref().and_then(|s| s.get("host")).cloned();
        let addr = host
            .as_ref()
            .map(|h| {
                format!(
                    "{}@{}:{}",
                    h.get("username").and_then(|v| v.as_str()).unwrap_or("root"),
                    h.get("host").and_then(|v| v.as_str()).unwrap_or(""),
                    h.get("port").and_then(|v| v.as_u64()).unwrap_or(22)
                )
            })
            .unwrap_or_default();
        let host_name = host
            .as_ref()
            .and_then(|h| h.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let host_name = if host_name.is_empty() {
            self.mon_ident
                .as_ref()
                .map(|(name, _)| name.clone())
                .unwrap_or_else(|| "已连接主机".to_string())
        } else {
            host_name
        };
        let addr = if addr.is_empty() {
            self.mon_ident
                .as_ref()
                .map(|(_, addr)| addr.clone())
                .unwrap_or_default()
        } else {
            addr
        };
        let os_tag = snap
            .as_ref()
            .map(|s| format!("Linux · {}", s.os))
            .unwrap_or_else(|| "Linux".to_string());

        let mut set_interval: Option<u64> = None;
        let mut toggle_pause = false;
        let mut retry = false;

        let wide = ui.available_width() > 980.0;
        let roomy = ui.available_width() > 640.0;
        let with_os = ui.available_width() > 560.0;
        Frame::NONE
            .fill(p.panel)
            .stroke(Stroke::new(1.0_f32, p.border))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::symmetric(14, 0))
            .show(ui, |ui| {
                ui.set_height(52.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    let (dot, _) = ui.allocate_exact_size(Vec2::splat(7.0), Sense::hover());
                    let dot_col = if stale {
                        p.faint
                    } else if paused {
                        p.warn
                    } else {
                        p.ok
                    };
                    ui.painter().circle_filled(dot.center(), 3.5, dot_col);
                    ui.label(RichText::new(&host_name).size(13.0).color(p.text));
                    if wide && !addr.is_empty() {
                        ui.label(RichText::new(&addr).size(12.0).monospace().color(p.dim));
                    }
                    ui.add_space(2.0);
                    if with_os {
                        mon_tag(ui, &p, "", &os_tag);
                    }
                    if let Some(s) = &snap {
                        if wide {
                            mon_tag(
                                ui,
                                &p,
                                "",
                                &format!(
                                    "{} 核 · {:.0} GiB",
                                    s.cores,
                                    s.mem.total / (1024.0 * 1024.0 * 1024.0)
                                ),
                            );
                        }
                        if roomy {
                            mon_tag(ui, &p, "已运行", &mon_uptime(s.uptime_secs));
                        }
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if connected {
                            let pause_label = if paused { "继续" } else { "暂停" };
                            if mon_small_btn(ui, &p, pause_label, !paused).clicked() {
                                toggle_pause = true;
                            }
                            if let Some(iv) = mon_seg(ui, &p, interval) {
                                set_interval = Some(iv);
                            }
                            ui.label(RichText::new("刷新").size(11.0).color(p.faint));
                        } else {
                            ui.label(RichText::new("连接已断开").size(11.5).color(p.warn));
                        }
                    });
                });
            });

        if let Some(iv) = set_interval {
            if iv != self.mon_interval_ms {
                self.mon_interval_ms = iv;
                self.mon_last_poll = Instant::now()
                    .checked_sub(Duration::from_millis(iv))
                    .unwrap_or_else(Instant::now);
                self.poll_monitor(true);
            }
        }
        if toggle_pause {
            self.mon_paused = !self.mon_paused;
            if !self.mon_paused {
                self.mon_last_poll = Instant::now()
                    .checked_sub(Duration::from_millis(self.mon_interval_ms))
                    .unwrap_or_else(Instant::now);
                self.poll_monitor(true);
            }
        }

        ui.add_space(12.0);
        if let Some(message) = &err {
            Frame::NONE
                .fill(p.warn_soft)
                .stroke(Stroke::new(1.0_f32, p.warn.gamma_multiply(0.35)))
                .corner_radius(CornerRadius::same(10))
                .inner_margin(Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        ui.label(RichText::new("采样失败").size(11.5).strong().color(p.warn));
                        ui.label(RichText::new(message).size(11.0).color(p.dim));
                    });
                });
            ui.add_space(10.0);
        }
        if stale {
            let text = if snap.is_some() {
                "连接已断开 · 保留最后一次快照，重连后自动恢复"
            } else {
                "连接已断开 · 等待重新连接"
            };
            Frame::NONE
                .fill(p.surface2)
                .stroke(Stroke::new(1.0_f32, p.border))
                .corner_radius(CornerRadius::same(10))
                .inner_margin(Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    ui.label(RichText::new(text).size(11.0).color(p.dim));
                });
            ui.add_space(10.0);
        }

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let Some(s) = snap.as_ref() else {
                    ui.add_space(14.0);
                    mon_card(ui, &p, ui.available_width(), |ui| {
                        ui.add_space(24.0);
                        ui.vertical_centered(|ui| {
                            ui.add(egui::Spinner::new().size(22.0).color(p.accent));
                            ui.add_space(10.0);
                            ui.label(
                                RichText::new(if connected {
                                    "正在采集第一份快照…"
                                } else {
                                    "等待重新连接…"
                                })
                                .size(11.5)
                                .color(p.dim),
                            );
                        });
                        ui.add_space(20.0);
                        if err.is_some() && connected {
                            ui.vertical_centered(|ui| {
                                if Self::action_btn(ui, &p, "重试", false, false).clicked() {
                                    retry = true;
                                }
                            });
                            ui.add_space(12.0);
                        }
                    });
                    return;
                };

                let avail = ui.available_width();
                ui.add_space(14.0);
                let kpi_gap = 12.0;
                if avail >= 860.0 {
                    let kpi_w = ((avail - kpi_gap * 3.0) / 4.0).max(120.0);
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = kpi_gap;
                        mon_kpi_cpu(ui, &p, kpi_w, s, &cpu_hist);
                        mon_kpi_mem(ui, &p, kpi_w, s, &mem_hist);
                        mon_kpi_load(ui, &p, kpi_w, s, &load_hist);
                        mon_kpi_net(ui, &p, kpi_w, s, &down_hist);
                    });
                } else {
                    let kpi_w = ((avail - kpi_gap) / 2.0).max(120.0);
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = kpi_gap;
                        mon_kpi_cpu(ui, &p, kpi_w, s, &cpu_hist);
                        mon_kpi_mem(ui, &p, kpi_w, s, &mem_hist);
                    });
                    ui.add_space(kpi_gap);
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = kpi_gap;
                        mon_kpi_load(ui, &p, kpi_w, s, &load_hist);
                        mon_kpi_net(ui, &p, kpi_w, s, &down_hist);
                    });
                }

                ui.add_space(14.0);
                let row_gap = 14.0;
                let left_w = (avail - row_gap) * 1.18 / 2.18;
                let right_w = avail - row_gap - left_w;
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = row_gap;
                    mon_cores_card(ui, &p, left_w, s, interval, paused);
                    mon_disks_card(ui, &p, right_w, s);
                });

                ui.add_space(14.0);
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = row_gap;
                    mon_net_card(ui, &p, left_w, s, &down_hist, &up_hist, peak_down, peak_up);
                    mon_procs_card(ui, &p, right_w, s, &mut self.mon_sort_by_mem);
                });

                ui.add_space(10.0);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    ui.label(RichText::new("仅 Linux").size(10.5).strong().color(p.dim));
                    ui.label(
                        RichText::new(
                            "通过 SSH 执行只读采集（/proc/stat、/proc/meminfo、/proc/net/dev、df、ps），不写任何远端文件。",
                        )
                        .size(10.5)
                        .color(p.faint),
                    );
                    ui.label(RichText::new("|").size(10.5).color(p.border));
                    ui.label(RichText::new("断线即停").size(10.5).strong().color(p.dim));
                    ui.label(
                        RichText::new("连接中断时保留最后一次快照并标灰，重连后自动恢复。")
                            .size(10.5)
                            .color(p.faint),
                    );
                });

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 7.0;
                    let (dot, _) = ui.allocate_exact_size(Vec2::splat(7.0), Sense::hover());
                    let (text, col): (String, Color32) = if stale {
                        ("连接已断开 · 保留最后一次快照".to_string(), p.faint)
                    } else if paused {
                        ("已暂停采样 · 曲线保留".to_string(), p.warn)
                    } else {
                        (
                            format!(
                                "监控采样中 · {} 秒/次 · {} 个进程",
                                (interval / 1000).max(1),
                                s.load.processes
                            ),
                            p.ok,
                        )
                    };
                    ui.painter().circle_filled(dot.center(), 3.5, col);
                    ui.label(RichText::new(text).size(10.5).color(p.faint));
                });
                ui.add_space(10.0);
            });

        if retry {
            self.poll_monitor(true);
        }
    }

    fn render_vault_grid(&mut self, ui: &mut egui::Ui, allow_add_card: bool) {
        let p = self.palette;
        let avail_w = (ui.available_width() - 4.0).max(260.0);

        let mut add_clicked = false;
        ui.horizontal(|ui| {
            ui.set_width(avail_w);
            ui.label(
                RichText::new("服务器保险库 (HOSTS)")
                    .size(12.0)
                    .strong()
                    .color(p.dim),
            );
            ui.label(
                RichText::new(format!("({})", self.hosts.len()))
                    .size(12.0)
                    .monospace()
                    .color(p.faint),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if !self.hosts.is_empty() {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vault_search)
                            .hint_text("筛选主机名称、IP 或用户名…")
                            .desired_width(240.0),
                    );
                    let (s_rect, _) = ui.allocate_exact_size(Vec2::new(18.0, 18.0), Sense::hover());
                    draw_icon(ui.painter(), s_rect.center(), 13.0, Icon::Search, p.dim);
                }
                if allow_add_card && Self::action_btn(ui, &p, "＋ 添加主机", true, false).clicked()
                {
                    add_clicked = true;
                }
            });
        });
        if add_clicked {
            self.open_host_edit(None);
        }

        ui.add_space(10.0);

        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                self.render_host_grid(ui, allow_add_card);
            });
    }

    fn render_host_grid(&mut self, ui: &mut egui::Ui, allow_add_card: bool) {
        let p = self.palette;
        let avail_w = (ui.available_width() - 4.0).max(260.0);

        let q = self.vault_search.trim().to_lowercase();
        let filtered: Vec<HostEntry> = self
            .hosts
            .iter()
            .filter(|h| {
                if q.is_empty() {
                    return true;
                }
                let hay = format!("{} {} {}", h.name, h.host, h.username).to_lowercase();
                hay.contains(&q)
            })
            .cloned()
            .collect();

        let gap = 14.0;
        let cols = ((avail_w + gap) / (286.0 + gap)).floor().clamp(1.0, 4.0) as usize;
        let card_w = ((avail_w - (cols.saturating_sub(1) as f32) * gap) / (cols as f32))
            .floor()
            .max(220.0);
        let card_h = 116.0;

        let total_items = filtered.len();
        if total_items == 0 {
            if allow_add_card && self.hosts.is_empty() {
                // 空库：全宽添加卡
                let (add_rect, add_resp) =
                    ui.allocate_exact_size(Vec2::new(avail_w, 108.0), Sense::click());
                let hovered = add_resp.hovered();
                let border_col = if hovered {
                    p.accent
                } else {
                    p.accent.gamma_multiply(0.45)
                };
                let fill_col = if hovered { p.accent_soft } else { p.panel };
                ui.painter()
                    .rect_filled(add_rect, CornerRadius::same(11), fill_col);
                ui.painter().rect_stroke(
                    add_rect,
                    CornerRadius::same(11),
                    Stroke::new(1.0_f32, border_col),
                    StrokeKind::Inside,
                );
                let plus_circle = Pos2::new(add_rect.center().x - 42.0, add_rect.center().y - 10.0);
                ui.painter()
                    .circle_filled(plus_circle, 13.0, p.accent.gamma_multiply(0.18));
                draw_icon(ui.painter(), plus_circle, 13.0, Icon::Plus, p.accent);
                ui.painter().text(
                    Pos2::new(add_rect.center().x - 22.0, add_rect.center().y - 10.0),
                    egui::Align2::LEFT_CENTER,
                    "添加服务器",
                    FontId::proportional(14.0),
                    p.accent,
                );
                ui.painter().text(
                    Pos2::new(add_rect.center().x, add_rect.center().y + 18.0),
                    egui::Align2::CENTER_CENTER,
                    "保存 IP、端口与私钥路径",
                    FontId::proportional(11.5),
                    p.dim,
                );
                if hovered {
                    ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
                }
                if add_resp.clicked() {
                    self.open_host_edit(None);
                }
                return;
            }
            let (empty_rect, _) = ui.allocate_exact_size(Vec2::new(avail_w, 96.0), Sense::hover());
            ui.painter()
                .rect_filled(empty_rect, CornerRadius::same(11), p.panel);
            ui.painter().rect_stroke(
                empty_rect,
                CornerRadius::same(11),
                Stroke::new(1.0_f32, p.border),
                StrokeKind::Inside,
            );
            ui.painter().text(
                Pos2::new(empty_rect.center().x, empty_rect.center().y - 10.0),
                egui::Align2::CENTER_CENTER,
                "暂无匹配的服务器卡片",
                FontId::proportional(13.5),
                p.dim,
            );
            let hint = if self.hosts.is_empty() {
                "切换到「主机与密钥」页，点击「＋ 添加主机」新增服务器配置"
            } else {
                "试试清空筛选条件"
            };
            ui.painter().text(
                Pos2::new(empty_rect.center().x, empty_rect.center().y + 12.0),
                egui::Align2::CENTER_CENTER,
                hint,
                FontId::proportional(12.0),
                p.faint,
            );
            return;
        }

        let mut pending_edit: Option<Option<HostEntry>> = None;
        let mut pending_connect: Option<(HostEntry, ViewMode)> = None;
        let mut copy_text: Option<(String, &'static str)> = None;

        let mut row_idx = 0;
        while row_idx * cols < total_items {
            let (row_rect, _) = ui.allocate_exact_size(Vec2::new(avail_w, card_h), Sense::hover());

            for c in 0..cols {
                let item_i = row_idx * cols + c;
                if item_i >= total_items {
                    break;
                }
                let x0 = row_rect.min.x + (c as f32) * (card_w + gap);
                let card_rect =
                    Rect::from_min_size(Pos2::new(x0, row_rect.min.y), Vec2::new(card_w, card_h));

                if item_i < filtered.len() {
                    let h = filtered[item_i].clone();
                    let name = if h.name.trim().is_empty() {
                        h.host.clone()
                    } else {
                        h.name.clone()
                    };
                    let first_ch = name
                        .chars()
                        .next()
                        .unwrap_or('S')
                        .to_uppercase()
                        .to_string();

                    // 整卡可交互响应（单击/双击直连终端，右键弹出完整菜单，Netcatty 风格）
                    let card_resp = ui.interact(
                        card_rect,
                        ui.id().with(("card_main", item_i)),
                        Sense::click(),
                    );
                    let card_hovered = card_resp.hovered();

                    let h_menu = h.clone();
                    card_resp.context_menu(|ui| {
                        ui.set_min_width(150.0);
                        if ui.button("⚡ 连接终端 (SSH)").clicked() {
                            pending_connect = Some((h_menu.clone(), ViewMode::Term));
                            ui.close_menu();
                        }
                        if ui.button("📁 打开文件 (SFTP)").clicked() {
                            pending_connect = Some((h_menu.clone(), ViewMode::Files));
                            ui.close_menu();
                        }
                        if ui.button("📊 打开状态监控").clicked() {
                            pending_connect = Some((h_menu.clone(), ViewMode::Monitor));
                            ui.close_menu();
                        }
                        if ui.button("🔑 管理 authorized_keys").clicked() {
                            pending_connect = Some((h_menu.clone(), ViewMode::Keys));
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("📋 复制 SSH 连接命令").clicked() {
                            let cmd = format!("ssh -p {} {}@{}", h_menu.port, h_menu.username, h_menu.host);
                            copy_text = Some((cmd, "SSH 命令"));
                            ui.close_menu();
                        }
                        if ui.button("✏️ 编辑服务器配置").clicked() {
                            pending_edit = Some(Some(h_menu.clone()));
                            ui.close_menu();
                        }
                    });

                    // 方案 A 现代极简卡片布局
                    let av_rect = Rect::from_min_size(
                        Pos2::new(card_rect.min.x + 13.0, card_rect.min.y + 13.0),
                        Vec2::new(38.0, 38.0),
                    );
                    let edit_rect = Rect::from_min_size(
                        Pos2::new(card_rect.max.x - 36.0, card_rect.min.y + 13.0),
                        Vec2::new(24.0, 24.0),
                    );

                    let compact_btns = card_w < 335.0;
                    let term_w = if compact_btns { 52.0 } else { 58.0 };
                    let aux_w = if compact_btns { 32.0 } else { 54.0 };
                    let btn_gap = 5.0;

                    let term_rect = Rect::from_min_size(
                        Pos2::new(card_rect.max.x - 13.0 - term_w, card_rect.max.y - 35.0),
                        Vec2::new(term_w, 24.0),
                    );
                    let mon_rect = Rect::from_min_size(
                        Pos2::new(term_rect.min.x - btn_gap - aux_w, card_rect.max.y - 35.0),
                        Vec2::new(aux_w, 24.0),
                    );
                    let files_rect = Rect::from_min_size(
                        Pos2::new(mon_rect.min.x - btn_gap - aux_w, card_rect.max.y - 35.0),
                        Vec2::new(aux_w, 24.0),
                    );

                    let ep_str = format!("{}@{}:{}", h.username, h.host, h.port);
                    let ep_rect = Rect::from_min_size(
                        Pos2::new(av_rect.max.x + 10.0, card_rect.min.y + 36.0),
                        Vec2::new((card_rect.width() - 80.0).max(60.0), 18.0),
                    );

                    let edit_resp = ui
                        .interact(
                            edit_rect,
                            ui.id().with(("card_edit", item_i)),
                            Sense::click(),
                        )
                        .on_hover_text("编辑此服务器配置");
                    let ep_resp = ui
                        .interact(
                            ep_rect,
                            ui.id().with(("card_ep", item_i)),
                            Sense::click(),
                        )
                        .on_hover_text(format!("点击复制端点地址：{ep_str}"));
                    let term_resp = ui
                        .interact(
                            term_rect,
                            ui.id().with(("card_term", item_i)),
                            Sense::click(),
                        )
                        .on_hover_text("直连打开交互式 SSH 终端");
                    let mon_resp = ui
                        .interact(
                            mon_rect,
                            ui.id().with(("card_mon", item_i)),
                            Sense::click(),
                        )
                        .on_hover_text("连接并查看服务器资源监控");
                    let files_resp = ui
                        .interact(
                            files_rect,
                            ui.id().with(("card_files", item_i)),
                            Sense::click(),
                        )
                        .on_hover_text("连接并浏览远端文件 (SFTP)");

                    let border_col = if card_hovered {
                        p.accent
                    } else {
                        p.border
                    };
                    let card_bg = if card_hovered {
                        p.surface3
                    } else {
                        p.panel
                    };

                    // 1. 卡片背景与边框
                    ui.painter()
                        .rect_filled(card_rect, CornerRadius::same(11), card_bg);
                    ui.painter().rect_stroke(
                        card_rect,
                        CornerRadius::same(11),
                        Stroke::new(1.0_f32, border_col),
                        StrokeKind::Inside,
                    );

                    // 2. 左侧首字母/NAS 图标头像方块（带呼吸绿点）
                    ui.painter()
                        .rect_filled(av_rect, CornerRadius::same(10), p.accent_soft);
                    ui.painter().rect_stroke(
                        av_rect,
                        CornerRadius::same(10),
                        Stroke::new(1.0_f32, p.accent.gamma_multiply(0.35)),
                        StrokeKind::Inside,
                    );
                    let is_nas = h.name.to_lowercase().contains("nas") || h.name.to_lowercase().contains("fnos");
                    if is_nas {
                        draw_icon(ui.painter(), av_rect.center(), 18.0, Icon::Server, p.accent);
                    } else {
                        ui.painter().text(
                            av_rect.center(),
                            egui::Align2::CENTER_CENTER,
                            &first_ch,
                            FontId::proportional(15.5),
                            p.accent,
                        );
                    }
                    let status_dot = Pos2::new(av_rect.max.x - 3.5, av_rect.min.y + 3.5);
                    ui.painter().circle_filled(status_dot, 3.5, p.bg);
                    ui.painter().circle_filled(status_dot, 2.5, Color32::from_rgb(0x10, 0xB9, 0x81));

                    // 3. 业务微标签识别
                    let tag: Option<&'static str> = if h.host.starts_with("192.168.")
                        || h.host.starts_with("10.")
                        || h.host.starts_with("127.")
                        || h.host.starts_with("172.16.")
                    {
                        Some("局域网")
                    } else if h.name.to_lowercase().contains("nas") || h.name.to_lowercase().contains("fnos") {
                        Some("NAS")
                    } else if h.name.to_lowercase().contains("singapore") || h.name.to_lowercase().contains("sg") {
                        Some("新加坡")
                    } else if h.name.to_lowercase().contains("hk") {
                        Some("香港")
                    } else if h.name.to_lowercase().contains("jp") || h.name.to_lowercase().contains("tokyo") {
                        Some("日本")
                    } else {
                        None
                    };

                    // 主机名称与 user@host:port
                    let text_clip = Rect::from_min_max(
                        Pos2::new(av_rect.max.x + 10.0, card_rect.min.y + 10.0),
                        Pos2::new(edit_rect.min.x - 4.0, card_rect.min.y + 58.0),
                    );
                    let text_painter = ui.painter().with_clip_rect(text_clip);
                    let name_col = if card_hovered { p.accent } else { p.text };
                    text_painter.text(
                        Pos2::new(av_rect.max.x + 10.0, card_rect.min.y + 22.0),
                        egui::Align2::LEFT_CENTER,
                        &name,
                        FontId::proportional(13.5),
                        name_col,
                    );

                    // 业务微标签（若存在）
                    if let Some(tag_str) = tag {
                        let name_len_est = (name.len() as f32).min(12.0) * 8.5;
                        let tag_x = av_rect.max.x + 10.0 + name_len_est + 8.0;
                        if tag_x + 38.0 < edit_rect.min.x {
                            let tag_rect = Rect::from_min_size(
                                Pos2::new(tag_x, card_rect.min.y + 14.0),
                                Vec2::new(38.0, 16.0),
                            );
                            ui.painter().rect_filled(tag_rect, CornerRadius::same(4), p.surface2);
                            ui.painter().rect_stroke(
                                tag_rect,
                                CornerRadius::same(4),
                                Stroke::new(1.0_f32, p.border),
                                StrokeKind::Inside,
                            );
                            ui.painter().text(
                                tag_rect.center(),
                                egui::Align2::CENTER_CENTER,
                                tag_str,
                                FontId::proportional(9.5),
                                p.dim,
                            );
                        }
                    }

                    // 端点地址展示（悬停高亮）
                    let ep_fg = if ep_resp.hovered() { p.accent } else { p.dim };
                    text_painter.text(
                        Pos2::new(av_rect.max.x + 10.0, card_rect.min.y + 42.0),
                        egui::Align2::LEFT_CENTER,
                        &ep_str,
                        FontId::monospace(11.0),
                        ep_fg,
                    );

                    // 4. 右上角「编辑」轻量图标按钮
                    if edit_resp.hovered() {
                        ui.painter().rect_filled(edit_rect, CornerRadius::same(6), p.surface2);
                        ui.painter().rect_stroke(
                            edit_rect,
                            CornerRadius::same(6),
                            Stroke::new(1.0_f32, p.border),
                            StrokeKind::Inside,
                        );
                    }
                    draw_icon(
                        ui.painter(),
                        edit_rect.center(),
                        12.5,
                        Icon::Edit,
                        if edit_resp.hovered() { p.accent } else { p.faint },
                    );

                    // 5. 卡片内部分隔细线
                    let div_y = card_rect.min.y + 64.0;
                    ui.painter().line_segment(
                        [
                            Pos2::new(card_rect.min.x + 13.0, div_y),
                            Pos2::new(card_rect.max.x - 13.0, div_y),
                        ],
                        Stroke::new(1.0_f32, p.border.gamma_multiply(0.45)),
                    );

                    // 6. 左下角认证方式徽章
                    let has_key = !h.identity_file.trim().is_empty()
                        || !h.identity_fingerprint.trim().is_empty();
                    let badge_rect = Rect::from_min_size(
                        Pos2::new(card_rect.min.x + 13.0, card_rect.max.y - 34.0),
                        Vec2::new(56.0, 22.0),
                    );
                    ui.painter()
                        .rect_filled(badge_rect, CornerRadius::same(6), p.surface2);
                    ui.painter().rect_stroke(
                        badge_rect,
                        CornerRadius::same(6),
                        Stroke::new(1.0_f32, p.border),
                        StrokeKind::Inside,
                    );
                    draw_icon(
                        ui.painter(),
                        Pos2::new(badge_rect.min.x + 11.5, badge_rect.center().y),
                        11.0,
                        if has_key { Icon::Key } else { Icon::Lock },
                        if has_key { p.accent } else { p.dim },
                    );
                    ui.painter().text(
                        Pos2::new(badge_rect.min.x + 22.0, badge_rect.center().y),
                        egui::Align2::LEFT_CENTER,
                        if has_key { "密钥" } else { "密码" },
                        FontId::proportional(10.5),
                        p.dim,
                    );

                    if h.proxy_enabled() {
                        let kind = if h.proxy_kind == "http" {
                            "HTTP"
                        } else {
                            "SOCKS5"
                        };
                        let chip_w = if kind == "HTTP" { 42.0 } else { 52.0 };
                        let proxy_rect = Rect::from_min_size(
                            Pos2::new(badge_rect.max.x + 5.0, badge_rect.min.y),
                            Vec2::new(chip_w, 22.0),
                        );
                        ui.painter()
                            .rect_filled(proxy_rect, CornerRadius::same(6), p.accent_soft);
                        ui.painter().rect_stroke(
                            proxy_rect,
                            CornerRadius::same(6),
                            Stroke::new(1.0_f32, p.accent.gamma_multiply(0.35)),
                            StrokeKind::Inside,
                        );
                        ui.painter().text(
                            proxy_rect.center(),
                            egui::Align2::CENTER_CENTER,
                            kind,
                            FontId::proportional(9.5),
                            p.accent,
                        );
                    }

                    // 7. 右下角动作按钮组：文件(SFTP) + 监控(Monitor) + 终端(SSH)
                    // 7.1 文件按钮
                    let files_bg = if files_resp.hovered() {
                        p.accent_soft
                    } else {
                        p.surface2
                    };
                    let files_border = if files_resp.hovered() {
                        p.accent
                    } else {
                        p.border
                    };
                    ui.painter()
                        .rect_filled(files_rect, CornerRadius::same(6), files_bg);
                    ui.painter().rect_stroke(
                        files_rect,
                        CornerRadius::same(6),
                        Stroke::new(1.0_f32, files_border),
                        StrokeKind::Inside,
                    );
                    if compact_btns {
                        draw_icon(
                            ui.painter(),
                            files_rect.center(),
                            11.5,
                            Icon::Folder,
                            if files_resp.hovered() { p.accent } else { p.dim },
                        );
                    } else {
                        draw_icon(
                            ui.painter(),
                            Pos2::new(files_rect.min.x + 12.0, files_rect.center().y),
                            11.5,
                            Icon::Folder,
                            if files_resp.hovered() { p.accent } else { p.dim },
                        );
                        ui.painter().text(
                            Pos2::new(files_rect.min.x + 22.5, files_rect.center().y),
                            egui::Align2::LEFT_CENTER,
                            "文件",
                            FontId::proportional(11.0),
                            if files_resp.hovered() { p.accent } else { p.text },
                        );
                    }

                    // 7.2 监控按钮
                    let mon_bg = if mon_resp.hovered() {
                        p.accent_soft
                    } else {
                        p.surface2
                    };
                    let mon_border = if mon_resp.hovered() {
                        p.accent
                    } else {
                        p.border
                    };
                    ui.painter()
                        .rect_filled(mon_rect, CornerRadius::same(6), mon_bg);
                    ui.painter().rect_stroke(
                        mon_rect,
                        CornerRadius::same(6),
                        Stroke::new(1.0_f32, mon_border),
                        StrokeKind::Inside,
                    );
                    if compact_btns {
                        draw_icon(
                            ui.painter(),
                            mon_rect.center(),
                            11.5,
                            Icon::Pulse,
                            if mon_resp.hovered() { p.accent } else { p.dim },
                        );
                    } else {
                        draw_icon(
                            ui.painter(),
                            Pos2::new(mon_rect.min.x + 12.0, mon_rect.center().y),
                            11.5,
                            Icon::Pulse,
                            if mon_resp.hovered() { p.accent } else { p.dim },
                        );
                        ui.painter().text(
                            Pos2::new(mon_rect.min.x + 22.5, mon_rect.center().y),
                            egui::Align2::LEFT_CENTER,
                            "监控",
                            FontId::proportional(11.0),
                            if mon_resp.hovered() { p.accent } else { p.text },
                        );
                    }

                    // 7.3 终端主按钮
                    let term_bg = if term_resp.hovered() {
                        p.accent.gamma_multiply(0.88)
                    } else {
                        p.accent
                    };
                    ui.painter()
                        .rect_filled(term_rect, CornerRadius::same(6), term_bg);
                    draw_icon(
                        ui.painter(),
                        Pos2::new(term_rect.min.x + 13.0, term_rect.center().y),
                        11.5,
                        Icon::Terminal,
                        Color32::WHITE,
                    );
                    ui.painter().text(
                        Pos2::new(term_rect.min.x + 23.5, term_rect.center().y),
                        egui::Align2::LEFT_CENTER,
                        "终端",
                        FontId::proportional(11.5),
                        Color32::WHITE,
                    );

                    if card_hovered
                        || edit_resp.hovered()
                        || ep_resp.hovered()
                        || files_resp.hovered()
                        || mon_resp.hovered()
                        || term_resp.hovered()
                    {
                        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
                    }

                    if edit_resp.clicked() {
                        pending_edit = Some(Some(h));
                    } else if ep_resp.clicked() {
                        copy_text = Some((ep_str, "端点地址"));
                    } else if term_resp.clicked() {
                        pending_connect = Some((h, ViewMode::Term));
                    } else if mon_resp.clicked() {
                        pending_connect = Some((h, ViewMode::Monitor));
                    } else if files_resp.clicked() {
                        pending_connect = Some((h, ViewMode::Files));
                    } else if card_resp.clicked() {
                        // Netcatty 体验：点击卡片任意非按钮区域直接连接终端
                        pending_connect = Some((h, ViewMode::Term));
                    }
                }
            }

            ui.add_space(gap);
            row_idx += 1;
        }

        if let Some((txt, label)) = copy_text {
            self.copy_to_clipboard(&txt, label);
        }
        if let Some(ed) = pending_edit {
            self.open_host_edit(ed);
        }
        if let Some((h, m)) = pending_connect {
            self.start_connect_flow(h, m);
        }
    }

    fn render_term_canvas(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = self.palette;

        // 未连接服务器时：不显示引导横幅与添加卡，直接展示主机网格
        if self.session.is_none() {
            self.render_vault_grid(ui, false);
            return;
        }

        let term_active = self.term_id.is_some();
        // 连接身份与操作按钮都移到顶部信息条（render_conn_bar）了
        ui.add_space(8.0);

        let avail = ui.available_size();
        let pad_x = 12.0;
        let pad_y = 10.0;
        let font_id = FontId::monospace(13.5);
        let char_w = ui.fonts(|f| f.glyph_width(&font_id, 'M')).max(7.2);
        let line_h = 19.0;

        let inner_w = (avail.x - pad_x * 2.0).max(160.0);
        let inner_h = (avail.y - pad_y * 2.0).max(100.0);
        let new_cols = (inner_w / char_w).floor().clamp(20.0, 300.0) as usize;
        let new_rows = (inner_h / line_h).floor().clamp(6.0, 150.0) as usize;

        if new_cols != self.vt.cols() || new_rows != self.vt.rows() {
            self.vt.resize(new_cols, new_rows);
            if let Some(tid) = self.term_id.clone() {
                if self.last_sent_size != (new_cols, new_rows) {
                    self.last_sent_size = (new_cols, new_rows);
                    let engine = Arc::clone(&self.engine);
                    self.rt.spawn(async move {
                        let _ = engine
                            .term_resize(json!({
                                "termId": tid,
                                "cols": new_cols,
                                "rows": new_rows,
                            }))
                            .await;
                    });
                }
            }
        }

        // 终端画布配色（跟随主题色自由变化：曜石深色 / 亚麻浅色；无边框聚焦）
        let (term_bg_col, term_fg_col) = (p.surface2, p.text);

        let (term_rect, term_resp) = ui.allocate_exact_size(avail, Sense::click_and_drag());

        ui.painter()
            .rect_filled(term_rect, CornerRadius::same(10), term_bg_col);

        let origin = Pos2::new(term_rect.min.x + pad_x, term_rect.min.y + pad_y);
        let hist_len = self.vt.history().len();
        let grid_len = self.vt.grid().len();
        let rows = self.vt.rows();
        let cols = self.vt.cols();
        let total_lines = hist_len + grid_len;
        let start_line = total_lines
            .saturating_sub(rows)
            .saturating_sub(self.term_scroll_offset.min(hist_len));

        if term_resp.clicked() && !term_resp.dragged() {
            self.term_focused = true;
            term_resp.request_focus();
            self.term_selection = None;
            self.term_drag_start = None;
        } else if ui.input(|i| i.pointer.any_pressed()) && !term_resp.hovered() {
            self.term_focused = false;
        }

        // 鼠标拖拽划选终端文本
        if let Some(pos) = ui.input(|i| i.pointer.interact_pos()) {
            if term_rect.contains(pos) {
                let vis_r = ((pos.y - origin.y) / line_h).floor() as isize;
                let c_idx = ((pos.x - origin.x) / char_w).floor() as isize;
                if vis_r >= 0 && vis_r < rows as isize && c_idx >= 0 {
                    let abs_line = (start_line as isize + vis_r)
                        .clamp(0, total_lines.saturating_sub(1) as isize) as usize;
                    let abs_col = (c_idx as usize).min(cols.saturating_sub(1));
                    if term_resp.drag_started() {
                        self.term_drag_start = Some((abs_line, abs_col));
                        self.term_selection = Some(((abs_line, abs_col), (abs_line, abs_col)));
                    } else if term_resp.dragged() {
                        if let Some(start) = self.term_drag_start {
                            self.term_selection = Some((start, (abs_line, abs_col)));
                        }
                    }
                }
            }
        }

        // 右键：有选区则复制选中文本，无选区则粘贴剪贴板
        if term_resp.secondary_clicked() {
            if let Some((p1, p2)) = self.term_selection.take() {
                if p1 != p2 {
                    let txt = self.vt.text_in_range(p1, p2);
                    if !txt.is_empty() {
                        self.copy_to_clipboard(&txt, "选中文本");
                    }
                }
            } else {
                let txt = self.read_from_clipboard();
                if !txt.is_empty() {
                    self.send_term_paste(&txt);
                }
            }
        }

        if term_resp.hovered() {
            let scroll_y = ui.input(|i| i.smooth_scroll_delta.y);
            if scroll_y.abs() > 1.0 {
                let lines = (scroll_y / 18.0).round() as isize;
                let max_hist = self.vt.history().len() as isize;
                let next = (self.term_scroll_offset as isize + lines).clamp(0, max_hist);
                self.term_scroll_offset = next as usize;
            }
        }

        if self.term_focused && term_active && matches!(self.drawer, Drawer::None) {
            ctx.memory_mut(|m| {
                m.set_focus_lock_filter(
                    term_resp.id,
                    egui::EventFilter {
                        tab: true,
                        horizontal_arrows: true,
                        vertical_arrows: true,
                        escape: true,
                    },
                );
            });

            let mut to_send: Vec<u8> = Vec::new();
            let mut copy_selection = false;
            let mut do_paste = false;
            let mut paste_text: Option<String> = None;
            ui.input(|input| {
                for ev in &input.events {
                    match ev {
                        Event::Paste(s) => {
                            paste_text = Some(s.clone());
                        }
                        Event::Text(s) => {
                            if !input.modifiers.ctrl && !input.modifiers.command && !input.modifiers.alt {
                                to_send.extend_from_slice(s.as_bytes());
                            }
                        }
                        Event::Key {
                            key,
                            pressed: true,
                            modifiers,
                            ..
                        } => {
                            // Ctrl + Shift + C -> 复制选区
                            if modifiers.ctrl && modifiers.shift && *key == Key::C {
                                copy_selection = true;
                            } else if (modifiers.ctrl && modifiers.shift && *key == Key::V)
                                || (modifiers.shift && *key == Key::Insert)
                            {
                                do_paste = true;
                            } else if modifiers.ctrl && !modifiers.shift {
                                match key {
                                    Key::A => to_send.push(0x01),
                                    Key::B => to_send.push(0x02),
                                    Key::C => to_send.push(0x03),
                                    Key::D => to_send.push(0x04),
                                    Key::E => to_send.push(0x05),
                                    Key::F => to_send.push(0x06),
                                    Key::G => to_send.push(0x07),
                                    Key::H => to_send.push(0x08),
                                    Key::I => to_send.push(0x09),
                                    Key::J => to_send.push(0x0a),
                                    Key::K => to_send.push(0x0b),
                                    Key::L => to_send.push(0x0c),
                                    Key::M => to_send.push(0x0d),
                                    Key::N => to_send.push(0x0e),
                                    Key::O => to_send.push(0x0f),
                                    Key::P => to_send.push(0x10),
                                    Key::Q => to_send.push(0x11),
                                    Key::R => to_send.push(0x12),
                                    Key::S => to_send.push(0x13),
                                    Key::T => to_send.push(0x14),
                                    Key::U => to_send.push(0x15),
                                    Key::V => to_send.push(0x16),
                                    Key::W => to_send.push(0x17),
                                    Key::X => to_send.push(0x18),
                                    Key::Y => to_send.push(0x19),
                                    Key::Z => to_send.push(0x1a),
                                    Key::OpenBracket => to_send.push(0x1b),
                                    Key::Backslash => to_send.push(0x1c),
                                    Key::CloseBracket => to_send.push(0x1d),
                                    Key::Space => to_send.push(0x00),
                                    _ => {}
                                }
                            } else if modifiers.alt && !modifiers.ctrl {
                                match key {
                                    Key::B => to_send.extend_from_slice(b"\x1bb"),
                                    Key::F => to_send.extend_from_slice(b"\x1bf"),
                                    Key::D => to_send.extend_from_slice(b"\x1bd"),
                                    Key::Backspace => to_send.extend_from_slice(b"\x1b\x7f"),
                                    _ => {}
                                }
                            } else {
                                match key {
                                    Key::Enter => to_send.push(b'\r'),
                                    Key::Backspace => to_send.push(0x7f),
                                    Key::Tab => to_send.push(b'\t'),
                                    Key::Escape => to_send.push(0x1b),
                                    Key::ArrowUp => {
                                        if self.vt.app_cursor {
                                            to_send.extend_from_slice(b"\x1bOA");
                                        } else {
                                            to_send.extend_from_slice(b"\x1b[A");
                                        }
                                    }
                                    Key::ArrowDown => {
                                        if self.vt.app_cursor {
                                            to_send.extend_from_slice(b"\x1bOB");
                                        } else {
                                            to_send.extend_from_slice(b"\x1b[B");
                                        }
                                    }
                                    Key::ArrowRight => {
                                        if self.vt.app_cursor {
                                            to_send.extend_from_slice(b"\x1bOC");
                                        } else {
                                            to_send.extend_from_slice(b"\x1b[C");
                                        }
                                    }
                                    Key::ArrowLeft => {
                                        if self.vt.app_cursor {
                                            to_send.extend_from_slice(b"\x1bOD");
                                        } else {
                                            to_send.extend_from_slice(b"\x1b[D");
                                        }
                                    }
                                    Key::Home => {
                                        if self.vt.app_cursor {
                                            to_send.extend_from_slice(b"\x1bOH");
                                        } else {
                                            to_send.extend_from_slice(b"\x1b[H");
                                        }
                                    }
                                    Key::End => {
                                        if self.vt.app_cursor {
                                            to_send.extend_from_slice(b"\x1bOF");
                                        } else {
                                            to_send.extend_from_slice(b"\x1b[F");
                                        }
                                    }
                                    Key::Insert => to_send.extend_from_slice(b"\x1b[2~"),
                                    Key::Delete => to_send.extend_from_slice(b"\x1b[3~"),
                                    Key::PageUp => to_send.extend_from_slice(b"\x1b[5~"),
                                    Key::PageDown => to_send.extend_from_slice(b"\x1b[6~"),
                                    Key::F1 => to_send.extend_from_slice(b"\x1bOP"),
                                    Key::F2 => to_send.extend_from_slice(b"\x1bOQ"),
                                    Key::F3 => to_send.extend_from_slice(b"\x1bOR"),
                                    Key::F4 => to_send.extend_from_slice(b"\x1bOS"),
                                    Key::F5 => to_send.extend_from_slice(b"\x1b[15~"),
                                    Key::F6 => to_send.extend_from_slice(b"\x1b[17~"),
                                    Key::F7 => to_send.extend_from_slice(b"\x1b[18~"),
                                    Key::F8 => to_send.extend_from_slice(b"\x1b[19~"),
                                    Key::F9 => to_send.extend_from_slice(b"\x1b[20~"),
                                    Key::F10 => to_send.extend_from_slice(b"\x1b[21~"),
                                    Key::F11 => to_send.extend_from_slice(b"\x1b[23~"),
                                    Key::F12 => to_send.extend_from_slice(b"\x1b[24~"),
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
            });

            if !to_send.is_empty() {
                self.term_scroll_offset = 0;
                self.send_term_bytes(&to_send);
            }
            if let Some(s) = paste_text {
                self.send_term_paste(&s);
            }
            if copy_selection {
                if let Some((p1, p2)) = self.term_selection {
                    let txt = self.vt.text_in_range(p1, p2);
                    if !txt.is_empty() {
                        self.copy_to_clipboard(&txt, "选中文本");
                    }
                }
            }
            if do_paste {
                let txt = self.read_from_clipboard();
                if !txt.is_empty() {
                    self.send_term_paste(&txt);
                }
            }
        }

        let hist = self.vt.history();
        let grid = self.vt.grid();
        let painter = ui.painter().with_clip_rect(term_rect.shrink(4.0));

        for vis_r in 0..rows {
            let line_idx = start_line + vis_r;
            let row_slice = if line_idx < hist.len() {
                hist.get(line_idx).map(|v| v.as_slice())
            } else {
                grid.get(line_idx - hist.len()).map(|v| v.as_slice())
            };
            let Some(cells) = row_slice else {
                continue;
            };
            let y = origin.y + (vis_r as f32) * line_h;

            for (c_idx, cell) in cells.iter().enumerate().take(cols) {
                if cell.continuation {
                    continue;
                }
                let x = origin.x + (c_idx as f32) * char_w;
                let w = if is_wide_char(cell.ch) {
                    char_w * 2.0
                } else {
                    char_w
                };
                let (mut fg, mut bg) = (
                    cell.pen.fg.unwrap_or(term_fg_col),
                    cell.pen.bg.unwrap_or(Color32::TRANSPARENT),
                );
                if cell.pen.inverse {
                    std::mem::swap(&mut fg, &mut bg);
                    if fg == Color32::TRANSPARENT {
                        fg = term_bg_col;
                    }
                }
                if let Some((p1, p2)) = self.term_selection {
                    let (min_p, max_p) = if p1 <= p2 { (p1, p2) } else { (p2, p1) };
                    let in_sel = (line_idx > min_p.0
                        || (line_idx == min_p.0 && c_idx >= min_p.1))
                        && (line_idx < max_p.0
                            || (line_idx == max_p.0 && c_idx <= max_p.1));
                    if in_sel {
                        bg = p.accent.gamma_multiply(0.45);
                        fg = Color32::WHITE;
                    }
                }
                if bg != Color32::TRANSPARENT {
                    painter.rect_filled(
                        Rect::from_min_size(Pos2::new(x, y), Vec2::new(w + 0.5, line_h)),
                        CornerRadius::ZERO,
                        bg,
                    );
                }
                if cell.ch != ' ' && cell.ch != '\0' {
                    let mut buf = [0u8; 4];
                    let s = cell.ch.encode_utf8(&mut buf);
                    painter.text(
                        Pos2::new(x, y + line_h * 0.5),
                        egui::Align2::LEFT_CENTER,
                        s,
                        font_id.clone(),
                        fg,
                    );
                }
            }
        }

        if self.term_scroll_offset == 0 && self.vt.cursor_visible {
            let (cx, cy) = self.vt.cursor();
            if cx < cols && cy < rows {
                let cur_rect = Rect::from_min_size(
                    Pos2::new(
                        origin.x + (cx as f32) * char_w,
                        origin.y + (cy as f32) * line_h + 1.0,
                    ),
                    Vec2::new(char_w, line_h - 2.0),
                );
                if self.term_focused {
                    painter.rect_filled(
                        cur_rect,
                        CornerRadius::same(2),
                        p.accent.gamma_multiply(0.65),
                    );
                } else {
                    painter.rect_stroke(
                        cur_rect,
                        CornerRadius::same(2),
                        Stroke::new(1.0_f32, p.accent),
                        StrokeKind::Inside,
                    );
                }
            }
        }
    }

    fn render_local_panel(&mut self, ctx: &egui::Context) {
        let p = self.palette;
        egui::SidePanel::right("kw_local_panel")
            .exact_width(275.0)
            .resizable(true)
            .frame(
                Frame::NONE
                    .fill(p.bg_elev)
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .inner_margin(Margin::symmetric(12, 12)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (f_rect, _) = ui.allocate_exact_size(Vec2::new(16.0, 16.0), Sense::hover());
                    draw_icon(ui.painter(), f_rect.center(), 13.0, Icon::Folder, p.accent);
                    ui.label(
                        RichText::new("本机私钥库对照")
                            .size(13.0)
                            .strong()
                            .color(p.text),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add(
                                egui::Button::new(RichText::new("✕").size(11.5).color(p.dim))
                                    .fill(Color32::TRANSPARENT)
                                    .stroke(Stroke::NONE),
                            )
                            .clicked()
                        {
                            self.show_local_panel = false;
                        }
                        if ui
                            .add(
                                egui::Button::new(RichText::new("↻").size(12.0).color(p.dim))
                                    .fill(Color32::TRANSPARENT)
                                    .stroke(Stroke::NONE),
                            )
                            .on_hover_text("强制重新扫描本机密钥目录")
                            .clicked()
                        {
                            self.trigger_local_scan(true);
                        }
                    });
                });

                let dir = self.engine.state().current_settings().local_key_dir;
                ui.label(RichText::new(dir).size(11.0).monospace().color(p.faint));
                ui.separator();

                let remote_fps: HashSet<String> = self
                    .session
                    .as_ref()
                    .and_then(|s| s.get("items"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|e| e.get("fingerprint").and_then(|v| v.as_str()))
                            .map(String::from)
                            .collect()
                    })
                    .unwrap_or_default();

                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if self.local_keys.is_empty() {
                            ui.label(
                                RichText::new("未扫描到本机密钥文件")
                                    .size(12.0)
                                    .color(p.dim),
                            );
                            return;
                        }

                        for lk in &self.local_keys {
                            let matched =
                                !lk.fingerprint.is_empty() && remote_fps.contains(&lk.fingerprint);
                            Frame::NONE
                                .fill(p.panel)
                                .stroke(Stroke::new(
                                    1.0_f32,
                                    if matched {
                                        p.ok.gamma_multiply(0.5)
                                    } else {
                                        p.border
                                    },
                                ))
                                .corner_radius(CornerRadius::same(8))
                                .inner_margin(Margin::symmetric(10, 8))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(&lk.name)
                                                .size(12.5)
                                                .strong()
                                                .color(p.text),
                                        );
                                        ui.with_layout(
                                            Layout::right_to_left(Align::Center),
                                            |ui| {
                                                if matched {
                                                    ui.label(
                                                        RichText::new("● 已授权")
                                                            .size(11.0)
                                                            .strong()
                                                            .color(p.ok),
                                                    );
                                                } else {
                                                    ui.label(
                                                        RichText::new(&lk.key_type)
                                                            .size(10.5)
                                                            .monospace()
                                                            .color(p.dim),
                                                    );
                                                }
                                            },
                                        );
                                    });
                                    if !lk.fingerprint.is_empty() {
                                        ui.label(
                                            RichText::new(&lk.fingerprint)
                                                .size(10.5)
                                                .monospace()
                                                .color(p.faint),
                                        );
                                    }
                                });
                            ui.add_space(6.0);
                        }
                    });
            });
    }

    fn open_host_edit(&mut self, entry: Option<HostEntry>) {
        if let Some(h) = entry {
            let login_pw = read_login_pw(&self.data_dir, &h.id);
            let auth_method = read_auth_method(&self.data_dir, &h.id).unwrap_or_else(|| {
                if h.identity_file.trim().is_empty() {
                    "password".to_string()
                } else {
                    "key".to_string()
                }
            });
            let pw_saved = self.engine.proxy_password_saved(&h.id);
            let proxy_on = h.proxy_enabled();
            let proxy_port = h.proxy_port_or_default();
            self.drawer = Drawer::HostEdit {
                id: Some(h.id),
                name: h.name,
                host: h.host,
                port: h.port.to_string(),
                username: h.username,
                auth_method,
                password: login_pw.unwrap_or_default(),
                identity_file: h.identity_file,
                remote_path: h.remote_path,
                proxy_enabled: proxy_on,
                proxy_expanded: proxy_on,
                proxy_kind: if h.proxy_kind.is_empty() {
                    "socks5".to_string()
                } else {
                    h.proxy_kind
                },
                proxy_host: h.proxy_host,
                proxy_port: proxy_port.to_string(),
                proxy_username: h.proxy_username,
                proxy_password: String::new(),
                remember_proxy_password: pw_saved,
                proxy_pw_saved: pw_saved,
                proxy_testing: false,
                proxy_test: None,
            };
        } else {
            let def_path = self.engine.state().current_settings().remote_path;
            self.drawer = Drawer::HostEdit {
                id: None,
                name: String::new(),
                host: String::new(),
                port: "22".to_string(),
                username: "root".to_string(),
                auth_method: "password".to_string(),
                password: String::new(),
                identity_file: String::new(),
                remote_path: def_path,
                proxy_enabled: false,
                proxy_expanded: false,
                proxy_kind: "socks5".to_string(),
                proxy_host: String::new(),
                proxy_port: "1080".to_string(),
                proxy_username: String::new(),
                proxy_password: String::new(),
                remember_proxy_password: true,
                proxy_pw_saved: false,
                proxy_testing: false,
                proxy_test: None,
            };
        }
    }

    fn open_settings_drawer(&mut self) {
        let s = self.engine.state().current_settings();
        self.drawer = Drawer::Settings {
            theme_choice: self.theme_choice.clone(),
            local_key_dir: s.local_key_dir,
            save_dir: s.save_dir,
            remote_path: s.remote_path,
        };
    }

    fn open_sync_drawer(&mut self) {
        self.ms_status = self.engine.ms_status();
        let cid = self
            .ms_status
            .get("clientId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let remembered = self
            .ms_status
            .get("hasSyncKey")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        self.drawer = Drawer::Sync {
            client_id: cid,
            passphrase: String::new(),
            remember_key: remembered,
            device_prompt: None,
            conflicts: Vec::new(),
        };
    }

    fn open_backups_drawer(&mut self) {
        let Some(sid) = self.current_sid() else {
            return;
        };
        self.busy = true;
        let engine = Arc::clone(&self.engine);
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            match engine.backups(&sid).await {
                Ok(v) => {
                    let list = v
                        .get("backups")
                        .and_then(|x| x.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let _ = tx.send(BgEvent::BackupsLoaded(list));
                }
                Err(e) => {
                    let msg = e
                        .get("error")
                        .and_then(|x| x.as_str())
                        .unwrap_or("获取历史备份失败");
                    let _ = tx.send(BgEvent::Log(msg.to_string(), LogKind::Err));
                }
            }
        });
    }

    fn render_drawer(&mut self, ctx: &egui::Context) {
        if matches!(self.drawer, Drawer::None) {
            return;
        }
        let p = self.palette;
        let mut close_drawer = false;

        egui::Area::new(Id::new("kw_modal_backdrop"))
            .order(Order::Foreground)
            .fixed_pos(Pos2::ZERO)
            .show(ctx, |ui| {
                let screen = ctx.screen_rect();
                let (rect, resp) = ui.allocate_exact_size(screen.size(), Sense::click());
                ui.painter()
                    .rect_filled(rect, CornerRadius::ZERO, Color32::from_black_alpha(135));
                if resp.clicked() {
                    close_drawer = true;
                }
            });

        let is_host_modal = matches!(self.drawer, Drawer::HostEdit { .. });
        let modal_w = if is_host_modal { 720.0 } else { 540.0 };

        egui::Window::new("kw_drawer_modal")
            .title_bar(false)
            .collapsible(false)
            .resizable(false)
            .order(Order::Tooltip)
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .default_width(modal_w)
            .min_width(modal_w)
            .max_width(modal_w)
            .frame(
                Frame::NONE
                    .fill(p.bg_elev)
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .corner_radius(CornerRadius::same(13))
                    .inner_margin(Margin::symmetric(20, 18)),
            )
            .show(ctx, |ui| {
                ui.set_width(modal_w);
                let mut current = std::mem::replace(&mut self.drawer, Drawer::None);
                match &mut current {
                    Drawer::None => {}

                    Drawer::HostEdit {
                        id,
                        name,
                        host,
                        port,
                        username,
                        auth_method,
                        password,
                        identity_file,
                        remote_path,
                        proxy_enabled,
                        proxy_expanded,
                        proxy_kind,
                        proxy_host,
                        proxy_port,
                        proxy_username,
                        proxy_password,
                        remember_proxy_password,
                        proxy_pw_saved,
                        proxy_testing,
                        proxy_test,
                    } => {
                        // 顶部标题栏：图标 + 标题 + 数量徽章 + 右侧「＋ 新建服务器」「关闭」
                        ui.horizontal(|ui| {
                            let (ico_r, _) =
                                ui.allocate_exact_size(Vec2::new(26.0, 26.0), Sense::hover());
                            ui.painter()
                                .rect_filled(ico_r, CornerRadius::same(7), p.accent_soft);
                            draw_icon(ui.painter(), ico_r.center(), 14.0, Icon::Server, p.accent);
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new("服务器管理")
                                    .size(15.5)
                                    .strong()
                                    .color(p.text),
                            );
                            let (cnt_r, _) =
                                ui.allocate_exact_size(Vec2::new(56.0, 20.0), Sense::hover());
                            ui.painter()
                                .rect_filled(cnt_r, CornerRadius::same(10), p.surface3);
                            ui.painter().text(
                                cnt_r.center(),
                                egui::Align2::CENTER_CENTER,
                                format!("共 {} 台", self.hosts.len()),
                                FontId::proportional(11.0),
                                p.dim,
                            );

                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if Self::action_btn(ui, &p, "关闭", false, false).clicked() {
                                    close_drawer = true;
                                }
                                if Self::action_btn(ui, &p, "＋ 新建服务器", id.is_none(), false)
                                    .clicked()
                                {
                                    let def_path =
                                        self.engine.state().current_settings().remote_path;
                                    *id = None;
                                    name.clear();
                                    host.clear();
                                    *port = "22".to_string();
                                    *username = "root".to_string();
                                    *auth_method = "password".to_string();
                                    password.clear();
                                    identity_file.clear();
                                    *remote_path = def_path;
                                    *proxy_enabled = false;
                                    *proxy_expanded = false;
                                    *proxy_kind = "socks5".to_string();
                                    proxy_host.clear();
                                    *proxy_port = "1080".to_string();
                                    proxy_username.clear();
                                    proxy_password.clear();
                                    *remember_proxy_password = true;
                                    *proxy_pw_saved = false;
                                    *proxy_testing = false;
                                    *proxy_test = None;
                                }
                            });
                        });
                        ui.add_space(6.0);
                        ui.separator();
                        ui.add_space(6.0);

                        // 左右双栏布局：左侧服务器列表 + 右侧配置表单（注意：在 horizontal 内必须显式开启 vertical 布局）
                        let mut switch_to: Option<HostEntry> = None;
                        ui.horizontal_top(|ui| {
                            // 左侧列表容器
                            Frame::NONE
                                .fill(p.surface2)
                                .stroke(Stroke::new(1.0_f32, p.border))
                                .corner_radius(CornerRadius::same(10))
                                .inner_margin(Margin::symmetric(8, 8))
                                .show(ui, |ui| {
                                    ui.vertical(|ui| {
                                        ui.set_width(210.0);
                                        ScrollArea::vertical()
                                            .id_salt("host_mgr_left_scroll")
                                            .max_height(310.0)
                                            .auto_shrink([false, false])
                                            .show(ui, |ui| {
                                                if self.hosts.is_empty() {
                                                    ui.add_space(24.0);
                                                    ui.vertical_centered(|ui| {
                                                        ui.label(
                                                            RichText::new("暂无保存的服务器")
                                                                .size(12.0)
                                                                .color(p.dim),
                                                        );
                                                    });
                                                }
                                                for (idx, h) in self.hosts.iter().enumerate() {
                                                    let selected =
                                                        id.as_deref() == Some(h.id.as_str());
                                                    let nm = if h.name.trim().is_empty() {
                                                        &h.host
                                                    } else {
                                                        &h.name
                                                    };
                                                    let first_ch = nm
                                                        .chars()
                                                        .next()
                                                        .unwrap_or('S')
                                                        .to_uppercase()
                                                        .to_string();

                                                    let (row_r, row_resp) = ui.allocate_exact_size(
                                                        Vec2::new(198.0, 50.0),
                                                        Sense::click(),
                                                    );
                                                    let hovered = row_resp.hovered();
                                                    let bg = if selected {
                                                        p.accent_soft
                                                    } else if hovered {
                                                        p.surface3
                                                    } else {
                                                        p.panel
                                                    };
                                                    let stroke_c = if selected {
                                                        p.accent
                                                    } else if hovered {
                                                        p.accent.gamma_multiply(0.45)
                                                    } else {
                                                        p.border
                                                    };
                                                    ui.painter().rect_filled(
                                                        row_r,
                                                        CornerRadius::same(8),
                                                        bg,
                                                    );
                                                    ui.painter().rect_stroke(
                                                        row_r,
                                                        CornerRadius::same(8),
                                                        Stroke::new(1.0_f32, stroke_c),
                                                        StrokeKind::Inside,
                                                    );
                                                    if selected {
                                                        let bar = Rect::from_min_size(
                                                            Pos2::new(
                                                                row_r.min.x,
                                                                row_r.center().y - 10.0,
                                                            ),
                                                            Vec2::new(3.0, 20.0),
                                                        );
                                                        ui.painter().rect_filled(
                                                            bar,
                                                            CornerRadius::same(2),
                                                            p.accent,
                                                        );
                                                    }

                                                    let av = Rect::from_min_size(
                                                        Pos2::new(
                                                            row_r.min.x + 10.0,
                                                            row_r.min.y + 10.0,
                                                        ),
                                                        Vec2::new(30.0, 30.0),
                                                    );
                                                    ui.painter().rect_filled(
                                                        av,
                                                        CornerRadius::same(7),
                                                        if selected {
                                                            p.accent
                                                        } else {
                                                            p.surface3
                                                        },
                                                    );
                                                    ui.painter().text(
                                                        av.center(),
                                                        egui::Align2::CENTER_CENTER,
                                                        &first_ch,
                                                        FontId::proportional(13.0),
                                                        if selected {
                                                            Color32::WHITE
                                                        } else {
                                                            p.accent
                                                        },
                                                    );

                                                    let proxied = h.proxy_enabled();
                                                    let clip = Rect::from_min_max(
                                                        Pos2::new(av.max.x + 8.0, row_r.min.y + 4.0),
                                                        Pos2::new(
                                                            if proxied {
                                                                row_r.max.x - 58.0
                                                            } else {
                                                                row_r.max.x - 8.0
                                                            },
                                                            row_r.max.y - 4.0,
                                                        ),
                                                    );
                                                    let tp = ui.painter().with_clip_rect(clip);
                                                    tp.text(
                                                        Pos2::new(
                                                            av.max.x + 8.0,
                                                            row_r.min.y + 17.0,
                                                        ),
                                                        egui::Align2::LEFT_CENTER,
                                                        nm,
                                                        FontId::proportional(12.5),
                                                        p.text,
                                                    );
                                                    tp.text(
                                                        Pos2::new(
                                                            av.max.x + 8.0,
                                                            row_r.min.y + 34.0,
                                                        ),
                                                        egui::Align2::LEFT_CENTER,
                                                        format!(
                                                            "{}@{}:{}",
                                                            h.username, h.host, h.port
                                                        ),
                                                        FontId::monospace(10.5),
                                                        p.dim,
                                                    );

                                                    if proxied {
                                                        let kind = if h.proxy_kind == "http" {
                                                            "HTTP"
                                                        } else {
                                                            "SOCKS5"
                                                        };
                                                        let chip = Rect::from_min_size(
                                                            Pos2::new(
                                                                row_r.max.x - 8.0 - 46.0,
                                                                row_r.min.y + 9.0,
                                                            ),
                                                            Vec2::new(46.0, 17.0),
                                                        );
                                                        ui.painter().rect_filled(
                                                            chip,
                                                            CornerRadius::same(8),
                                                            p.accent_soft,
                                                        );
                                                        ui.painter().text(
                                                            chip.center(),
                                                            egui::Align2::CENTER_CENTER,
                                                            kind,
                                                            FontId::proportional(9.0),
                                                            p.accent,
                                                        );
                                                    }

                                                    if hovered {
                                                        ui.ctx().set_cursor_icon(
                                                            CursorIcon::PointingHand,
                                                        );
                                                    }
                                                    if row_resp.clicked() {
                                                        switch_to = Some(h.clone());
                                                    }
                                                    if idx + 1 < self.hosts.len() {
                                                        ui.add_space(5.0);
                                                    }
                                                }
                                            });
                                    });
                                });

                            ui.add_space(10.0);

                            // 右侧编辑/新建表单容器
                            Frame::NONE
                                .fill(p.panel)
                                .stroke(Stroke::new(1.0_f32, p.border))
                                .corner_radius(CornerRadius::same(10))
                                .inner_margin(Margin::symmetric(16, 14))
                                .show(ui, |ui| {
                                    ui.vertical(|ui| {
                                        ui.set_width(446.0);
                                        let is_edit = id.is_some();
                                        ui.horizontal(|ui| {
                                            let (ic_r, _) = ui.allocate_exact_size(
                                                Vec2::new(18.0, 18.0),
                                                Sense::hover(),
                                            );
                                            draw_icon(
                                                ui.painter(),
                                                ic_r.center(),
                                                13.0,
                                                if is_edit { Icon::Edit } else { Icon::Plus },
                                                p.accent,
                                            );
                                            ui.label(
                                                RichText::new(if is_edit {
                                                    format!(
                                                        "编辑服务器：{}",
                                                        if name.trim().is_empty() {
                                                            host.as_str()
                                                        } else {
                                                            name.as_str()
                                                        }
                                                    )
                                                } else {
                                                    "新建服务器配置".to_string()
                                                })
                                                .size(13.5)
                                                .strong()
                                                .color(p.text),
                                            );
                                        });
                                        ui.add_space(4.0);
                                        ui.separator();
                                        ui.add_space(8.0);

                                        egui::Grid::new("host_edit_grid")
                                            .num_columns(2)
                                            .spacing([14.0, 12.0])
                                            .min_col_width(82.0)
                                            .show(ui, |ui| {
                                                ui.label(RichText::new("备注名称").color(p.dim));
                                                ui.add(
                                                    egui::TextEdit::singleline(name)
                                                        .hint_text("例如：生产服务器 HK-01")
                                                        .desired_width(336.0),
                                                );
                                                ui.end_row();

                                                ui.label(RichText::new("主机地址 *").color(p.dim));
                                                ui.horizontal(|ui| {
                                                    ui.add(
                                                        egui::TextEdit::singleline(host)
                                                            .hint_text("IP 或域名，如 203.0.113.10")
                                                            .desired_width(230.0),
                                                    );
                                                    ui.label(RichText::new("端口").color(p.dim));
                                                    ui.add(
                                                        egui::TextEdit::singleline(port)
                                                            .desired_width(58.0),
                                                    );
                                                });
                                                ui.end_row();

                                                ui.label(RichText::new("登录用户 *").color(p.dim));
                                                ui.add(
                                                    egui::TextEdit::singleline(username)
                                                        .hint_text("root / ubuntu")
                                                        .desired_width(336.0),
                                                );
                                                ui.end_row();

                                                ui.label(RichText::new("认证方式").color(p.dim));
                                                ui.horizontal(|ui| {
                                                    ui.radio_value(auth_method, "password".to_string(), "密码登录");
                                                    ui.radio_value(auth_method, "key".to_string(), "密钥登录");
                                                });
                                                ui.end_row();

                                                if auth_method.as_str() == "password" {
                                                    ui.label(RichText::new("登录密码 *").color(p.dim));
                                                    ui.vertical(|ui| {
                                                        ui.add(
                                                            egui::TextEdit::singleline(&mut *password)
                                                                .password(true)
                                                                .hint_text("密码登录时使用；连接时自动带入，不再询问")
                                                                .desired_width(336.0),
                                                        );
                                                        ui.label(
                                                            RichText::new("仅存本机独立文件，不写入配置、不参与同步与导出")
                                                                .size(10.0)
                                                                .color(p.faint),
                                                        );
                                                    });
                                                    ui.end_row();
                                                }

                                                if auth_method.as_str() == "key" {
                                                    ui.label(RichText::new("私钥路径 *").color(p.dim));
                                                    ui.horizontal(|ui| {
                                                        ui.add(
                                                            egui::TextEdit::singleline(identity_file)
                                                                .hint_text("选择私钥文件；免密私钥连接时不再弹窗")
                                                                .desired_width(272.0),
                                                        );
                                                        if ui.button("浏览…").clicked() {
                                                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                                                *identity_file = path.to_string_lossy().to_string();
                                                            }
                                                        }
                                                    });
                                                    ui.end_row();
                                                }

                                                ui.label(RichText::new("远端路径").color(p.dim));
                                                ui.add(
                                                    egui::TextEdit::singleline(remote_path)
                                                        .hint_text("~/.ssh/authorized_keys")
                                                        .desired_width(336.0),
                                                );
                                                ui.end_row();
                                            });

                                        ui.add_space(12.0);
                                        let kind_label = if proxy_kind == "http" {
                                            "HTTP"
                                        } else {
                                            "SOCKS5"
                                        };
                                        Frame::NONE
                                            .fill(p.surface2)
                                            .stroke(Stroke::new(
                                                1.0_f32,
                                                if *proxy_enabled {
                                                    p.accent.gamma_multiply(0.55)
                                                } else {
                                                    p.border
                                                },
                                            ))
                                            .corner_radius(CornerRadius::same(9))
                                            .inner_margin(Margin::symmetric(10, 8))
                                            .show(ui, |ui| {
                                                ui.set_width(426.0);
                                                ui.horizontal(|ui| {
                                                    let chev = if *proxy_expanded {
                                                        "▾"
                                                    } else {
                                                        "▸"
                                                    };
                                                    if ui
                                                        .add(
                                                            egui::Button::new(
                                                                RichText::new(chev)
                                                                    .size(12.5)
                                                                    .color(p.accent),
                                                            )
                                                            .frame(false),
                                                        )
                                                        .clicked()
                                                    {
                                                        *proxy_expanded = !*proxy_expanded;
                                                    }
                                                    ui.label(
                                                        RichText::new("连接代理（可选）")
                                                            .size(12.5)
                                                            .strong()
                                                            .color(p.text),
                                                    );
                                                    ui.label(
                                                        RichText::new(
                                                            "SSH / SFTP / 终端全部生效",
                                                        )
                                                        .size(10.0)
                                                        .color(p.faint),
                                                    );
                                                    ui.with_layout(
                                                        Layout::right_to_left(Align::Center),
                                                        |ui| {
                                                            let (sw_r, sw_resp) =
                                                                ui.allocate_exact_size(
                                                                    Vec2::new(34.0, 18.0),
                                                                    Sense::click(),
                                                                );
                                                            ui.painter().rect_filled(
                                                                sw_r,
                                                                CornerRadius::same(9),
                                                                if *proxy_enabled {
                                                                    p.accent
                                                                } else {
                                                                    p.surface3
                                                                },
                                                            );
                                                            let knob_x = if *proxy_enabled {
                                                                sw_r.max.x - 8.0
                                                            } else {
                                                                sw_r.min.x + 8.0
                                                            };
                                                            ui.painter().circle_filled(
                                                                Pos2::new(knob_x, sw_r.center().y),
                                                                6.5,
                                                                if *proxy_enabled {
                                                                    Color32::WHITE
                                                                } else {
                                                                    p.dim
                                                                },
                                                            );
                                                            if sw_resp.clicked() {
                                                                *proxy_enabled = !*proxy_enabled;
                                                                if *proxy_enabled {
                                                                    *proxy_expanded = true;
                                                                }
                                                                *proxy_test = None;
                                                            }
                                                            if sw_resp.hovered() {
                                                                ui.ctx().set_cursor_icon(
                                                                    CursorIcon::PointingHand,
                                                                );
                                                            }
                                                            let (chip_text, chip_col) =
                                                                if *proxy_enabled {
                                                                    (
                                                                        format!(
                                                                            "已启用 · {kind_label}"
                                                                        ),
                                                                        p.ok,
                                                                    )
                                                                } else {
                                                                    ("未启用".to_string(), p.faint)
                                                                };
                                                            let (chip_r, _) =
                                                                ui.allocate_exact_size(
                                                                    Vec2::new(88.0, 18.0),
                                                                    Sense::hover(),
                                                                );
                                                            ui.painter().rect_filled(
                                                                chip_r,
                                                                CornerRadius::same(9),
                                                                chip_col.gamma_multiply(0.14),
                                                            );
                                                            ui.painter().text(
                                                                chip_r.center(),
                                                                egui::Align2::CENTER_CENTER,
                                                                chip_text,
                                                                FontId::proportional(10.0),
                                                                chip_col,
                                                            );
                                                        },
                                                    );
                                                });

                                                if *proxy_enabled && *proxy_expanded {
                                                    ui.add_space(8.0);
                                                    ui.horizontal(|ui| {
                                                        ui.label(
                                                            RichText::new("代理类型")
                                                                .size(11.5)
                                                                .color(p.dim),
                                                        );
                                                        if ui
                                                            .selectable_label(
                                                                *proxy_kind == "socks5",
                                                                "SOCKS5",
                                                            )
                                                            .clicked()
                                                        {
                                                            *proxy_kind = "socks5".to_string();
                                                            *proxy_test = None;
                                                        }
                                                        if ui
                                                            .selectable_label(
                                                                *proxy_kind == "http",
                                                                "HTTP",
                                                            )
                                                            .clicked()
                                                        {
                                                            *proxy_kind = "http".to_string();
                                                            *proxy_test = None;
                                                        }
                                                    });
                                                    ui.add_space(4.0);
                                                    ui.horizontal(|ui| {
                                                        ui.label(
                                                            RichText::new("地址")
                                                                .size(11.5)
                                                                .color(p.dim),
                                                        );
                                                        ui.add(
                                                            egui::TextEdit::singleline(proxy_host)
                                                                .hint_text("proxy.example.com")
                                                                .desired_width(232.0),
                                                        );
                                                        ui.label(
                                                            RichText::new("端口")
                                                                .size(11.5)
                                                                .color(p.dim),
                                                        );
                                                        ui.add(
                                                            egui::TextEdit::singleline(proxy_port)
                                                                .desired_width(58.0),
                                                        );
                                                    });
                                                    ui.add_space(4.0);
                                                    ui.horizontal(|ui| {
                                                        ui.label(
                                                            RichText::new("用户名")
                                                                .size(11.5)
                                                                .color(p.dim),
                                                        );
                                                        ui.add(
                                                            egui::TextEdit::singleline(
                                                                proxy_username,
                                                            )
                                                            .hint_text("可选")
                                                            .desired_width(336.0),
                                                        );
                                                    });
                                                    ui.add_space(4.0);
                                                    ui.horizontal(|ui| {
                                                        ui.label(
                                                            RichText::new("密码")
                                                                .size(11.5)
                                                                .color(p.dim),
                                                        );
                                                        let hint = if *proxy_pw_saved {
                                                            "已记住，留空保持不变"
                                                        } else {
                                                            "可选"
                                                        };
                                                        ui.add(
                                                            egui::TextEdit::singleline(
                                                                proxy_password,
                                                            )
                                                            .password(true)
                                                            .hint_text(hint)
                                                            .desired_width(232.0),
                                                        );
                                                        ui.checkbox(
                                                            remember_proxy_password,
                                                            RichText::new("本机记住").size(11.0),
                                                        );
                                                    });
                                                    ui.add_space(6.0);
                                                    ui.horizontal(|ui| {
                                                        let label = if *proxy_testing {
                                                            "正在握手…"
                                                        } else {
                                                            "测试代理"
                                                        };
                                                        if Self::action_btn(
                                                            ui, &p, label, false, false,
                                                        )
                                                        .clicked()
                                                            && !*proxy_testing
                                                        {
                                                            if proxy_host.trim().is_empty() {
                                                                *proxy_test = Some((
                                                                    false,
                                                                    "请先填写代理地址"
                                                                        .to_string(),
                                                                ));
                                                            } else {
                                                                *proxy_testing = true;
                                                                *proxy_test = None;
                                                                self.start_proxy_test(
                                                                    id.clone(),
                                                                    proxy_kind.clone(),
                                                                    proxy_host.clone(),
                                                                    proxy_port.clone(),
                                                                    proxy_username.clone(),
                                                                    proxy_password.clone(),
                                                                    host.clone(),
                                                                    port.clone(),
                                                                );
                                                            }
                                                        }
                                                        match proxy_test.as_ref() {
                                                            Some((ok, msg)) => {
                                                                ui.add(
                                                                    egui::Label::new(
                                                                        RichText::new(msg).size(
                                                                            10.5,
                                                                        ).color(if *ok {
                                                                            p.ok
                                                                        } else {
                                                                            p.danger
                                                                        }),
                                                                    )
                                                                    .truncate(),
                                                                )
                                                                .on_hover_text(msg);
                                                            }
                                                            None => {
                                                                ui.label(
                                                                    RichText::new(
                                                                        "只测代理连通，不登录 SSH",
                                                                    )
                                                                    .size(10.0)
                                                                    .color(p.faint),
                                                                );
                                                            }
                                                        }
                                                    });
                                                    ui.add_space(4.0);
                                                    ui.label(
                                                        RichText::new(if *proxy_kind == "http" {
                                                            "HTTP 代理使用 CONNECT 隧道，认证走 Basic；失败时会提示输入密码。"
                                                        } else {
                                                            "SOCKS5 支持域名地址，由代理解析 DNS；仅支持 TCP CONNECT，不做 UDP。"
                                                        })
                                                        .size(10.0)
                                                        .color(p.faint),
                                                    );
                                                    ui.label(
                                                        RichText::new(
                                                            "记住的密码存于本机 data/proxy-auth.json（0600），不参与同步与导出。",
                                                        )
                                                        .size(10.0)
                                                        .color(p.faint),
                                                    );
                                                }
                                            });

                                        ui.add_space(16.0);
                                        let id_clone = id.clone();
                                        let nm_val = name.trim().to_string();
                                        let h_val = host.trim().to_string();
                                        let p_val = port.trim().parse::<u16>().unwrap_or(22);
                                        let u_val = if username.trim().is_empty() {
                                            "root".to_string()
                                        } else {
                                            username.trim().to_string()
                                        };
                                        let idf_val = if auth_method.trim() == "password" {
                                            String::new()
                                        } else {
                                            identity_file.trim().to_string()
                                        };
                                        let rp_val = remote_path.trim().to_string();
                                        let p_on = *proxy_enabled;
                                        let p_kind = proxy_kind.clone();
                                        let p_host = proxy_host.trim().to_string();
                                        let p_port = proxy_port.trim().parse::<u16>().unwrap_or(1080);
                                        let p_user = proxy_username.trim().to_string();
                                        let p_pw = proxy_password.clone();
                                        let p_remember = *remember_proxy_password;
                                        let p_was_saved = *proxy_pw_saved;
                                        let login_pw = password.clone();
                                        let auth_val = auth_method.trim().to_string();
                                        let data_dir = self.data_dir.clone();

                                        ui.horizontal(|ui| {
                                            if let Some(exist_id) = id_clone.as_ref() {
                                                if Self::action_btn(
                                                    ui,
                                                    &p,
                                                    "删除此服务器",
                                                    false,
                                                    true,
                                                )
                                                .clicked()
                                                {
                                                    let _ = self.engine.delete_host(exist_id);
                                                    write_login_pw(&data_dir, exist_id, None);
                                                    write_auth_method(&data_dir, exist_id, None);
                                                    self.reload_store_data();
                                                    self.push_log(
                                                        "已删除服务器配置",
                                                        LogKind::Info,
                                                    );
                                                    if let Some(next_h) =
                                                        self.hosts.first().cloned()
                                                    {
                                                        switch_to = Some(next_h);
                                                    } else {
                                                        *id = None;
                                                        name.clear();
                                                        host.clear();
                                                        *port = "22".to_string();
                                                        *username = "root".to_string();
                                                        *auth_method = "password".to_string();
                                                        password.clear();
                                                        identity_file.clear();
                                                        *proxy_enabled = false;
                                                        *proxy_expanded = false;
                                                        *proxy_kind = "socks5".to_string();
                                                        proxy_host.clear();
                                                        *proxy_port = "1080".to_string();
                                                        proxy_username.clear();
                                                        proxy_password.clear();
                                                        *remember_proxy_password = true;
                                                        *proxy_pw_saved = false;
                                                        *proxy_testing = false;
                                                        *proxy_test = None;
                                                    }
                                                }
                                            }
                                            ui.with_layout(
                                                Layout::right_to_left(Align::Center),
                                                |ui| {
                                                    if Self::action_btn(
                                                        ui,
                                                        &p,
                                                        "保存配置",
                                                        true,
                                                        false,
                                                    )
                                                    .clicked()
                                                    {
                                                        if h_val.is_empty() {
                                                            self.push_log(
                                                                "请填写主机 IP 或域名",
                                                                LogKind::Warn,
                                                            );
                                                        } else if p_on && p_host.is_empty() {
                                                            self.push_log(
                                                                "已启用代理：请填写代理地址",
                                                                LogKind::Warn,
                                                            );
                                                        } else {
                                                            let patch = HostPatch {
                                                                id: id_clone,
                                                                name: Some(if nm_val.is_empty() {
                                                                    h_val.clone()
                                                                } else {
                                                                    nm_val
                                                                }),
                                                                host: Some(h_val),
                                                                port: Some(p_val),
                                                                username: Some(u_val),
                                                                identity_file: Some(idf_val),
                                                                identity_fingerprint: None,
                                                                remote_path: Some(rp_val),
                                                                proxy_kind: Some(if p_on {
                                                                    p_kind
                                                                } else {
                                                                    String::new()
                                                                }),
                                                                proxy_host: Some(p_host),
                                                                proxy_port: Some(p_port),
                                                                proxy_username: Some(p_user),
                                                                ..Default::default()
                                                            };
                                                            match self.engine.save_host(patch) {
                                                                Ok(saved) => {
                                                                    self.reload_store_data();
                                                                    if let Some(new_id) = saved
                                                                        .get("id")
                                                                        .and_then(|v| v.as_str())
                                                                    {
                                                                        *id = Some(
                                                                            new_id.to_string(),
                                                                        );
                                                                        // 认证方式 + 登录密码写入本机独立文件；
                                                                        // 密钥登录不留密码，密码登录不留私钥路径。
                                                                        write_auth_method(&data_dir, new_id, Some(auth_val.as_str()));
                                                                        write_login_pw(
                                                                            &data_dir,
                                                                            new_id,
                                                                            if auth_val == "password" && !login_pw.is_empty() {
                                                                                Some(login_pw.as_str())
                                                                            } else {
                                                                                None
                                                                            },
                                                                        );
                                                                        // 代理密码只在勾选「本机记住」时落盘；
                                                                        // 取消勾选或关闭代理都会清掉旧密码。
                                                                        let pw_action = if !p_on {
                                                                            Some("")
                                                                        } else if !p_pw.is_empty() {
                                                                            Some(if p_remember {
                                                                                p_pw.as_str()
                                                                            } else {
                                                                                ""
                                                                            })
                                                                        } else {
                                                                            None
                                                                        };
                                                                        if let Some(pw) = pw_action {
                                                                            if let Err(e) = self
                                                                                .engine
                                                                                .set_proxy_password(new_id, pw)
                                                                            {
                                                                                let msg = e
                                                                                    .get("error")
                                                                                    .and_then(|v| {
                                                                                        v.as_str()
                                                                                    })
                                                                                    .unwrap_or(
                                                                                        "保存代理密码失败",
                                                                                    );
                                                                                self.push_log(
                                                                                    msg.to_string(),
                                                                                    LogKind::Err,
                                                                                );
                                                                            }
                                                                        }
                                                                        *proxy_pw_saved = p_on
                                                                            && p_remember
                                                                            && (!p_pw.is_empty()
                                                                                || p_was_saved);
                                                                        proxy_password.clear();
                                                                        *proxy_test = None;
                                                                    }
                                                                    self.push_log(
                                                                        "已保存主机配置",
                                                                        LogKind::Ok,
                                                                    );
                                                                }
                                                                Err(e) => {
                                                                    let msg = e
                                                                        .get("error")
                                                                        .and_then(|v| v.as_str())
                                                                        .unwrap_or("保存失败");
                                                                    self.push_log(
                                                                        msg.to_string(),
                                                                        LogKind::Err,
                                                                    );
                                                                }
                                                            }
                                                        }
                                                    }
                                                },
                                            );
                                        });
                                    });
                                });
                        });

                        if let Some(target) = switch_to {
                            let saved_login_pw = read_login_pw(&self.data_dir, &target.id);
                            let saved_method = read_auth_method(&self.data_dir, &target.id)
                                .unwrap_or_else(|| {
                                    if target.identity_file.trim().is_empty() {
                                        "password".to_string()
                                    } else {
                                        "key".to_string()
                                    }
                                });
                            let pw_saved = self.engine.proxy_password_saved(&target.id);
                            let proxy_on = target.proxy_enabled();
                            let proxy_port_num = target.proxy_port_or_default();
                            *id = Some(target.id.clone());
                            *name = target.name;
                            *host = target.host;
                            *port = target.port.to_string();
                            *username = target.username;
                            *auth_method = saved_method;
                            *password = saved_login_pw.unwrap_or_default();
                            *identity_file = target.identity_file;
                            *remote_path = target.remote_path;
                            *proxy_enabled = proxy_on;
                            *proxy_expanded = proxy_on;
                            *proxy_kind = if target.proxy_kind.is_empty() {
                                "socks5".to_string()
                            } else {
                                target.proxy_kind
                            };
                            *proxy_host = target.proxy_host;
                            *proxy_port = proxy_port_num.to_string();
                            *proxy_username = target.proxy_username;
                            proxy_password.clear();
                            *remember_proxy_password = pw_saved;
                            *proxy_pw_saved = pw_saved;
                            *proxy_testing = false;
                            *proxy_test = None;
                        }
                    }

                    Drawer::ConnectPrompt {
                        host,
                        target_mode,
                        password,
                        passphrase,
                        proxy_password,
                        trust_fp,
                        hostkey_warning,
                        proxy_notice,
                    } => {
                        let title = if host.name.is_empty() {
                            &host.host
                        } else {
                            &host.name
                        };
                        ui.label(
                            RichText::new(format!(
                                "连接认证 — {title} ({}@{}:{})",
                                host.username, host.host, host.port
                            ))
                            .size(14.5)
                            .strong()
                            .color(p.text),
                        );
                        ui.separator();

                        if let Some((w_title, w_msg, is_danger)) = hostkey_warning.as_ref() {
                            let col = if *is_danger { p.danger } else { p.warn };
                            Frame::NONE
                                .fill(col.gamma_multiply(0.14))
                                .stroke(Stroke::new(1.0_f32, col.gamma_multiply(0.45)))
                                .corner_radius(CornerRadius::same(8))
                                .inner_margin(Margin::symmetric(10, 8))
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new(w_title).size(12.5).strong().color(col),
                                    );
                                    ui.label(RichText::new(w_msg).size(11.5).color(p.text));
                                    if let Some(fp) = trust_fp.as_ref() {
                                        ui.label(
                                            RichText::new(format!("指纹: {fp}"))
                                                .size(11.5)
                                                .monospace()
                                                .strong()
                                                .color(p.text),
                                        );
                                    }
                                });
                            ui.add_space(8.0);
                        }

                        if !host.identity_file.is_empty() {
                            ui.label(
                                RichText::new(format!("使用私钥: {}", host.identity_file))
                                    .size(11.5)
                                    .monospace()
                                    .color(p.dim),
                            );
                            ui.add_space(4.0);
                        }

                        if let Some(notice) = proxy_notice.as_ref() {
                            Frame::NONE
                                .fill(p.warn.gamma_multiply(0.14))
                                .stroke(Stroke::new(1.0_f32, p.warn.gamma_multiply(0.45)))
                                .corner_radius(CornerRadius::same(8))
                                .inner_margin(Margin::symmetric(10, 7))
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new(notice).size(11.5).color(p.warn),
                                    );
                                });
                            ui.add_space(8.0);
                        }

                        let auth_kind = read_auth_method(&self.data_dir, &host.id).unwrap_or_default();
                        let mut pw_resp = None;
                        let mut pp_resp = None;
                        if auth_kind.is_empty() {
                            // 旧配置（没选过认证方式）：保留原来的双输入框兼容
                            ui.label(
                                RichText::new("SSH 登录密码（若使用免密私钥可留空）：")
                                    .size(12.0)
                                    .color(p.dim),
                            );
                            pw_resp = Some(ui.add(
                                egui::TextEdit::singleline(password)
                                    .password(true)
                                    .desired_width(f32::INFINITY),
                            ));
                        }
                        if auth_kind.is_empty() || auth_kind == "key" {
                            ui.add_space(6.0);
                            ui.label(
                                RichText::new("私钥解密口令（这把私钥已加密）：")
                                    .size(12.0)
                                    .color(p.dim),
                            );
                            pp_resp = Some(ui.add(
                                egui::TextEdit::singleline(passphrase)
                                    .password(true)
                                    .desired_width(f32::INFINITY),
                            ));
                        }
                        if auth_kind == "password" {
                            ui.label(
                                RichText::new("使用已保存的登录密码直接连接，无需再次输入")
                                    .size(11.5)
                                    .color(p.dim),
                            );
                        }

                        let proxy_needs_password = host.proxy_enabled()
                            && !host.proxy_username.trim().is_empty()
                            && (!self.engine.proxy_password_saved(&host.id)
                                || proxy_notice.is_some());
                        let mut proxy_pw_resp = None;
                        if proxy_needs_password {
                            ui.add_space(6.0);
                            let kind = if host.proxy_kind == "http" {
                                "HTTP"
                            } else {
                                "SOCKS5"
                            };
                            ui.label(
                                RichText::new(format!("代理密码（{kind}）"))
                                    .size(12.0)
                                    .color(p.dim),
                            );
                            proxy_pw_resp = Some(ui.add(
                                egui::TextEdit::singleline(proxy_password)
                                    .password(true)
                                    .desired_width(f32::INFINITY),
                            ));
                        }

                        let enter_pressed = (pw_resp
                            .as_ref()
                            .map(|r| r.lost_focus())
                            .unwrap_or(false)
                            || pp_resp
                                .as_ref()
                                .map(|r| r.lost_focus())
                                .unwrap_or(false)
                            || proxy_pw_resp
                                .as_ref()
                                .map(|r| r.lost_focus())
                                .unwrap_or(false))
                            && ui.input(|i| i.key_pressed(Key::Enter));

                        ui.add_space(12.0);
                        let h_clone = host.clone();
                        let tm = *target_mode;
                        let pw = password.clone();
                        let pp = passphrase.clone();
                        let ppw = proxy_password.clone();
                        let tfp = trust_fp.clone();
                        ui.horizontal(|ui| {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                let btn_lbl = if tfp.is_some() {
                                    "信任指纹并连接"
                                } else {
                                    "立即连接"
                                };
                                if Self::action_btn(ui, &p, btn_lbl, true, false).clicked()
                                    || enter_pressed
                                {
                                    self.execute_connect(h_clone, tm, pw, pp, ppw, tfp);
                                    close_drawer = true;
                                }
                                if Self::action_btn(ui, &p, "取消", false, false).clicked() {
                                    close_drawer = true;
                                }
                            });
                        });
                    }

                    Drawer::AddKey {
                        tab,
                        algo,
                        label,
                        comment,
                        passphrase,
                        selected_local_pub,
                        pasted_pub,
                    } => {
                        ui.label(
                            RichText::new("＋ 新增远端授权公钥")
                                .size(15.5)
                                .strong()
                                .color(p.text),
                        );
                        ui.separator();

                        ui.horizontal(|ui| {
                            for (idx, t_lbl) in [
                                (0, "生成新密钥对并部署"),
                                (1, "从本机公钥选择"),
                                (2, "粘贴现有公钥"),
                            ] {
                                if ui.selectable_label(*tab == idx, t_lbl).clicked() {
                                    *tab = idx;
                                }
                            }
                        });
                        ui.add_space(8.0);

                        match *tab {
                            0 => {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("算法:").color(p.dim));
                                    for a in ["ed25519", "rsa"] {
                                        if ui
                                            .selectable_label(algo == a, a.to_uppercase())
                                            .clicked()
                                        {
                                            *algo = a.to_string();
                                        }
                                    }
                                });
                                ui.add_space(4.0);
                                ui.label(RichText::new("文件名前缀标签:").size(12.0).color(p.dim));
                                ui.add(
                                    egui::TextEdit::singleline(label)
                                        .desired_width(f32::INFINITY),
                                );
                                ui.add_space(4.0);
                                ui.label(RichText::new("公钥注释 (comment):").size(12.0).color(p.dim));
                                ui.add(
                                    egui::TextEdit::singleline(comment)
                                        .desired_width(f32::INFINITY),
                                );
                                ui.add_space(4.0);
                                ui.label(
                                    RichText::new("私钥加密口令 (可选):").size(12.0).color(p.dim),
                                );
                                ui.add(
                                    egui::TextEdit::singleline(passphrase)
                                        .password(true)
                                        .desired_width(f32::INFINITY),
                                );
                            }
                            1 => {
                                ui.label(
                                    RichText::new("选择本机已扫描到的公钥/私钥自动提取公钥：")
                                        .size(12.0)
                                        .color(p.dim),
                                );
                                ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                                    for lk in &self.local_keys {
                                        if let Some(pub_line) = &lk.public_key_line {
                                            let is_sel = selected_local_pub == pub_line;
                                            if ui
                                                .selectable_label(
                                                    is_sel,
                                                    format!("{} ({})", lk.name, lk.fingerprint),
                                                )
                                                .clicked()
                                            {
                                                *selected_local_pub = pub_line.clone();
                                            }
                                        }
                                    }
                                });
                            }
                            _ => {
                                ui.label(
                                    RichText::new("粘贴 ssh-ed25519 / ssh-rsa 公钥行：")
                                        .size(12.0)
                                        .color(p.dim),
                                );
                                ui.add(
                                    egui::TextEdit::multiline(pasted_pub)
                                        .desired_rows(4)
                                        .font(FontId::monospace(12.0))
                                        .desired_width(f32::INFINITY),
                                );
                            }
                        }

                        ui.add_space(12.0);
                        let cur_tab = *tab;
                        let al = algo.clone();
                        let lb = label.trim().to_string();
                        let cm = comment.trim().to_string();
                        let pp = passphrase.clone();
                        let sel_pub = selected_local_pub.trim().to_string();
                        let pst_pub = pasted_pub.trim().to_string();

                        ui.horizontal(|ui| {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if Self::action_btn(ui, &p, "写入远端 authorized_keys", true, false)
                                    .clicked()
                                {
                                    if let Some(sid) = self.current_sid() {
                                        let save_dir = self.current_login_key_dir().unwrap_or_else(|| {
                                            self.engine.state().current_settings().save_dir
                                        });
                                        let body = if cur_tab == 0 {
                                            json!({
                                                "sid": sid,
                                                "mode": "generate",
                                                "generator": al,
                                                "label": if lb.is_empty() { "key".to_string() } else { lb },
                                                "comment": cm,
                                                "passphrase": pp,
                                                "saveDir": save_dir,
                                            })
                                        } else {
                                            let line = if cur_tab == 1 { sel_pub } else { pst_pub };
                                            json!({
                                                "sid": sid,
                                                "mode": "paste",
                                                "publicKey": line,
                                            })
                                        };
                                        self.busy = true;
                                        let engine = Arc::clone(&self.engine);
                                        let tx = self.tx.clone();
                                        self.rt.spawn(async move {
                                            match engine.add_key(body).await {
                                                Ok(v) => {
                                                    if let Some(sess) = v.get("session") {
                                                        let _ = tx.send(BgEvent::SessionUpdated(
                                                            sess.clone(),
                                                        ));
                                                    }
                                                    let _ = tx.send(BgEvent::Log(
                                                        "已成功添加公钥至服务器".into(),
                                                        LogKind::Ok,
                                                    ));
                                                }
                                                Err(e) => {
                                                    let msg = e
                                                        .get("error")
                                                        .and_then(|x| x.as_str())
                                                        .unwrap_or("添加公钥失败");
                                                    let _ = tx.send(BgEvent::Log(
                                                        msg.to_string(),
                                                        LogKind::Err,
                                                    ));
                                                }
                                            }
                                        });
                                        self.trigger_local_scan(true);
                                        close_drawer = true;
                                    }
                                }
                                if Self::action_btn(ui, &p, "取消", false, false).clicked() {
                                    close_drawer = true;
                                }
                            });
                        });
                    }

                    Drawer::ReplaceKey {
                        old_index,
                        old_comment,
                        old_fp,
                        tab,
                        algo,
                        label,
                        comment,
                        passphrase,
                        selected_priv_path,
                    } => {
                        ui.label(
                            RichText::new(format!(
                                "↻ 安全更换密钥 — #{} {}",
                                *old_index + 1,
                                if old_comment.is_empty() {
                                    old_fp.as_str()
                                } else {
                                    old_comment.as_str()
                                }
                            ))
                            .size(15.0)
                            .strong()
                            .color(p.text),
                        );
                        ui.separator();
                        ui.label(
                            RichText::new("三步安全闭环：先追加新公钥 → 用新私钥建立独立 SSH 连接验证可登录 → 验证通过后再移除旧公钥。")
                                .size(11.5)
                                .color(p.dim),
                        );
                        ui.add_space(6.0);

                        ui.horizontal(|ui| {
                            if ui
                                .selectable_label(*tab == 0, "生成新密钥对并替换")
                                .clicked()
                            {
                                *tab = 0;
                            }
                            if ui
                                .selectable_label(*tab == 1, "使用本机已有私钥替换")
                                .clicked()
                            {
                                *tab = 1;
                            }
                        });
                        ui.add_space(6.0);

                        if *tab == 0 {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("算法:").color(p.dim));
                                for a in ["ed25519", "rsa"] {
                                    if ui.selectable_label(algo == a, a.to_uppercase()).clicked() {
                                        *algo = a.to_string();
                                    }
                                }
                            });
                            ui.add_space(4.0);
                            ui.label(RichText::new("私钥保存名称标签:").size(12.0).color(p.dim));
                            ui.add(
                                egui::TextEdit::singleline(label).desired_width(f32::INFINITY),
                            );
                            ui.add_space(4.0);
                            ui.label(RichText::new("新公钥注释:").size(12.0).color(p.dim));
                            ui.add(
                                egui::TextEdit::singleline(comment).desired_width(f32::INFINITY),
                            );
                            ui.add_space(4.0);
                            ui.label(RichText::new("新私钥口令 (可选):").size(12.0).color(p.dim));
                            ui.add(
                                egui::TextEdit::singleline(passphrase)
                                    .password(true)
                                    .desired_width(f32::INFINITY),
                            );
                        } else {
                            ui.label(RichText::new("本机私钥文件路径:").size(12.0).color(p.dim));
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(selected_priv_path)
                                        .desired_width(380.0),
                                );
                                if ui.button("浏览…").clicked() {
                                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                                        *selected_priv_path = path.to_string_lossy().to_string();
                                    }
                                }
                            });
                            ui.add_space(4.0);
                            ui.label(RichText::new("该私钥解密口令 (可选):").size(12.0).color(p.dim));
                            ui.add(
                                egui::TextEdit::singleline(passphrase)
                                    .password(true)
                                    .desired_width(f32::INFINITY),
                            );
                        }

                        ui.add_space(12.0);
                        let cur_tab = *tab;
                        let al = algo.clone();
                        let lb = label.trim().to_string();
                        let cm = comment.trim().to_string();
                        let pp = passphrase.clone();
                        let sp = selected_priv_path.trim().to_string();
                        let ofp = old_fp.clone();

                        ui.horizontal(|ui| {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if Self::action_btn(ui, &p, "执行验证并替换", true, false)
                                    .clicked()
                                {
                                    if let Some(sid) = self.current_sid() {
                                        let save_dir = self.current_login_key_dir().unwrap_or_else(|| {
                                            self.engine.state().current_settings().save_dir
                                        });
                                        let body = if cur_tab == 0 {
                                            json!({
                                                "sid": sid,
                                                "oldFingerprint": ofp,
                                                "mode": "generate",
                                                "generator": al,
                                                "label": if lb.is_empty() { "replaced".to_string() } else { lb },
                                                "comment": cm,
                                                "passphrase": pp,
                                                "saveDir": save_dir,
                                            })
                                        } else {
                                            json!({
                                                "sid": sid,
                                                "oldFingerprint": ofp.clone(),
                                                "mode": "local",
                                                "path": sp,
                                                "passphrase": pp,
                                            })
                                        };
                                        self.busy = true;
                                        let engine = Arc::clone(&self.engine);
                                        let tx = self.tx.clone();
                                        self.rt.spawn(async move {
                                            match engine.replace_key(body).await {
                                                Ok(v) => {
                                                    if let Some(sess) = v.get("session") {
                                                        let _ = tx.send(BgEvent::SessionUpdated(
                                                            sess.clone(),
                                                        ));
                                                    }
                                                    let _ = tx.send(BgEvent::Log(
                                                        "新密钥验证通过并已完成替换".into(),
                                                        LogKind::Ok,
                                                    ));
                                                }
                                                Err(e) => {
                                                    let msg = e
                                                        .get("error")
                                                        .and_then(|x| x.as_str())
                                                        .unwrap_or("更换密钥失败");
                                                    let _ = tx.send(BgEvent::Log(
                                                        msg.to_string(),
                                                        LogKind::Err,
                                                    ));
                                                }
                                            }
                                        });
                                        self.trigger_local_scan(true);
                                        close_drawer = true;
                                    }
                                }
                                if Self::action_btn(ui, &p, "取消", false, false).clicked() {
                                    close_drawer = true;
                                }
                            });
                        });
                    }

                    Drawer::EditNote {
                        fingerprint,
                        comment,
                        note,
                    } => {
                        ui.label(
                            RichText::new("✎ 编辑公钥归属备注")
                                .size(15.0)
                                .strong()
                                .color(p.text),
                        );
                        ui.separator();
                        if !comment.is_empty() {
                            ui.label(RichText::new(comment.as_str()).size(12.5).color(p.text));
                        }
                        ui.label(
                            RichText::new(fingerprint.as_str())
                                .size(11.5)
                                .monospace()
                                .color(p.dim),
                        );
                        ui.add_space(6.0);
                        ui.add(
                            egui::TextEdit::singleline(note)
                                .hint_text("输入便于识别的用途或持有人备注（仅存本机）…")
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(12.0);
                        let fp_val = fingerprint.clone();
                        let nt_val = note.trim().to_string();
                        ui.horizontal(|ui| {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if Self::action_btn(ui, &p, "保存备注", true, false).clicked() {
                                    let _ = self.engine.set_key_note(&fp_val, &nt_val);
                                    self.reload_store_data();
                                    self.push_log("已更新公钥备注", LogKind::Ok);
                                    close_drawer = true;
                                }
                                if Self::action_btn(ui, &p, "取消", false, false).clicked() {
                                    close_drawer = true;
                                }
                            });
                        });
                    }

                    Drawer::ConfirmDelete {
                        fingerprints,
                        message,
                    } => {
                        ui.label(
                            RichText::new("确认强制删除公钥")
                                .size(15.0)
                                .strong()
                                .color(p.danger),
                        );
                        ui.separator();
                        ui.label(RichText::new(message.as_str()).size(12.5).color(p.text));
                        ui.add_space(8.0);
                        ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                            for fp in fingerprints.iter() {
                                ui.label(
                                    RichText::new(fp.as_str())
                                        .size(11.0)
                                        .monospace()
                                        .color(p.dim),
                                );
                            }
                        });
                        ui.add_space(12.0);
                        let fps = fingerprints.clone();
                        ui.horizontal(|ui| {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if Self::action_btn(ui, &p, "强制删除", false, true).clicked() {
                                    self.delete_keys_by_fingerprints(fps, true);
                                    close_drawer = true;
                                }
                                if Self::action_btn(ui, &p, "取消", false, false).clicked() {
                                    close_drawer = true;
                                }
                            });
                        });
                    }

                    Drawer::Backups {
                        items,
                        selected_name,
                        diff,
                    } => {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("远端 authorized_keys 历史备份")
                                    .size(15.0)
                                    .strong()
                                    .color(p.text),
                            );
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if Self::action_btn(ui, &p, "关闭", false, false).clicked() {
                                    close_drawer = true;
                                }
                            });
                        });
                        ui.separator();

                        ScrollArea::vertical().max_height(240.0).show(ui, |ui| {
                            if items.is_empty() {
                                ui.label(
                                    RichText::new("当前远端尚无历史备份文件")
                                        .size(12.5)
                                        .color(p.dim),
                                );
                            }
                            for b in items.iter() {
                                let name = b
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let mtime = b.get("mtime").and_then(|v| v.as_str()).unwrap_or("");
                                Frame::NONE
                                    .fill(p.panel)
                                    .stroke(Stroke::new(1.0_f32, p.border))
                                    .corner_radius(CornerRadius::same(8))
                                    .inner_margin(Margin::symmetric(12, 8))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.vertical(|ui| {
                                                ui.label(
                                                    RichText::new(&name)
                                                        .size(12.5)
                                                        .monospace()
                                                        .strong()
                                                        .color(p.text),
                                                );
                                                ui.label(
                                                    RichText::new(mtime).size(11.0).color(p.dim),
                                                );
                                            });
                                            ui.with_layout(
                                                Layout::right_to_left(Align::Center),
                                                |ui| {
                                                    if Self::action_btn(
                                                        ui, &p, "恢复此备份", false, false,
                                                    )
                                                    .clicked()
                                                    {
                                                        if let Some(sid) = self.current_sid() {
                                                            self.busy = true;
                                                            let engine = Arc::clone(&self.engine);
                                                            let tx = self.tx.clone();
                                                            let nm = name.clone();
                                                            self.rt.spawn(async move {
                                                                let body = json!({
                                                                    "sid": sid,
                                                                    "name": nm,
                                                                });
                                                                match engine
                                                                    .restore_backup(body)
                                                                    .await
                                                                {
                                                                    Ok(v) => {
                                                                        if let Some(sess) =
                                                                            v.get("session")
                                                                        {
                                                                            let _ = tx.send(BgEvent::SessionUpdated(sess.clone()));
                                                                        }
                                                                        let _ = tx.send(
                                                                            BgEvent::Log(
                                                                                "已从备份恢复远端公钥"
                                                                                    .into(),
                                                                                LogKind::Ok,
                                                                            ),
                                                                        );
                                                                    }
                                                                    Err(e) => {
                                                                        let msg = e
                                                                            .get("error")
                                                                            .and_then(|x| {
                                                                                x.as_str()
                                                                            })
                                                                            .unwrap_or(
                                                                                "恢复备份失败",
                                                                            );
                                                                        let _ = tx.send(
                                                                            BgEvent::Log(
                                                                                msg.to_string(),
                                                                                LogKind::Err,
                                                                            ),
                                                                        );
                                                                    }
                                                                }
                                                            });
                                                            close_drawer = true;
                                                        }
                                                    }
                                                    if Self::action_btn(
                                                        ui, &p, "对比差异", false, false,
                                                    )
                                                    .clicked()
                                                    {
                                                        if let Some(sid) = self.current_sid() {
                                                            let engine = Arc::clone(&self.engine);
                                                            let tx = self.tx.clone();
                                                            let nm = name.clone();
                                                            self.rt.spawn(async move {
                                                                if let Ok(d) = engine
                                                                    .backup_diff(&sid, &nm)
                                                                    .await
                                                                {
                                                                    let _ = tx.send(
                                                                        BgEvent::BackupDiffLoaded(
                                                                            nm, d,
                                                                        ),
                                                                    );
                                                                }
                                                            });
                                                        }
                                                    }
                                                },
                                            );
                                        });
                                    });
                                ui.add_space(6.0);
                            }
                        });

                        if let Some(d) = diff.as_ref() {
                            ui.separator();
                            ui.label(
                                RichText::new(format!("与当前文件对比 ({selected_name}):"))
                                    .size(12.0)
                                    .strong()
                                    .color(p.text),
                            );
                            let summary = serde_json::to_string_pretty(d).unwrap_or_default();
                            ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
                                ui.label(
                                    RichText::new(summary)
                                        .size(11.0)
                                        .monospace()
                                        .color(p.dim),
                                );
                            });
                        }
                    }

                    Drawer::Sshd { info } => {
                        ui.label(
                            RichText::new("远端 SSHD 安全加固")
                                .size(15.0)
                                .strong()
                                .color(p.text),
                        );
                        ui.separator();

                        let key_only = info
                            .get("keyOnly")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let pub_auth = info
                            .get("pubkeyAuthentication")
                            .and_then(|v| v.as_str())
                            .unwrap_or("yes");
                        let pwd_auth = info
                            .get("passwordAuthentication")
                            .and_then(|v| v.as_str())
                            .unwrap_or("yes");

                        ui.label(
                            RichText::new(format!(
                                "PubkeyAuthentication: {pub_auth}  |  PasswordAuthentication: {pwd_auth}"
                            ))
                            .size(12.5)
                            .monospace()
                            .color(p.text),
                        );
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new("开启「仅密钥登录」将在校验 sshd -t 无误后关闭密码认证并平滑重载 sshd，防暴力破解。")
                                .size(11.5)
                                .color(p.dim),
                        );

                        ui.add_space(12.0);
                        ui.horizontal(|ui| {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                let target_enable = !key_only;
                                let lbl = if target_enable {
                                    "开启「仅密钥登录」(禁用密码)"
                                } else {
                                    "恢复允许密码登录"
                                };
                                if Self::action_btn(ui, &p, lbl, target_enable, !target_enable)
                                    .clicked()
                                {
                                    if let Some(sid) = self.current_sid() {
                                        self.busy = true;
                                        let engine = Arc::clone(&self.engine);
                                        let tx = self.tx.clone();
                                        self.rt.spawn(async move {
                                            match engine.set_key_only(&sid, target_enable).await {
                                                Ok(v) => {
                                                    let _ = tx.send(BgEvent::SshdLoaded {
                                                        info: v,
                                                        open_drawer: false,
                                                    });
                                                    let _ = tx.send(BgEvent::Log(
                                                        "已更新远端 SSHD 登录策略".into(),
                                                        LogKind::Ok,
                                                    ));
                                                }
                                                Err(e) => {
                                                    let msg = e
                                                        .get("error")
                                                        .and_then(|x| x.as_str())
                                                        .unwrap_or("修改 SSHD 配置失败");
                                                    let _ = tx.send(BgEvent::Log(
                                                        msg.to_string(),
                                                        LogKind::Err,
                                                    ));
                                                }
                                            }
                                        });
                                        close_drawer = true;
                                    }
                                }
                                if Self::action_btn(ui, &p, "关闭", false, false).clicked() {
                                    close_drawer = true;
                                }
                            });
                        });
                    }

                    Drawer::Sync {
                        client_id,
                        passphrase,
                        remember_key,
                        device_prompt,
                        conflicts,
                    } => {
                        ui.label(
                            RichText::new("微软 OneDrive 端到端加密云同步")
                                .size(15.0)
                                .strong()
                                .color(p.text),
                        );
                        ui.separator();

                        let logged_in = self
                            .ms_status
                            .get("loggedIn")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let account = self
                            .ms_status
                            .get("account")
                            .and_then(|a| a.get("displayName").or_else(|| a.get("userPrincipalName")))
                            .and_then(|v| v.as_str())
                            .unwrap_or("已登录微软账号");

                        if logged_in {
                            ui.label(
                                RichText::new(format!("● 当前账号: {account}"))
                                    .size(12.5)
                                    .strong()
                                    .color(p.ok),
                            );
                        } else {
                            ui.label(
                                RichText::new("Azure App Client ID (可选，留空用默认):").color(p.dim),
                            );
                            ui.add(
                                egui::TextEdit::singleline(client_id)
                                    .desired_width(f32::INFINITY),
                            );
                        }

                        if let Some((code, uri)) = device_prompt.as_ref() {
                            ui.add_space(6.0);
                            Frame::NONE
                                .fill(p.surface2)
                                .stroke(Stroke::new(1.0_f32, p.accent))
                                .corner_radius(CornerRadius::same(8))
                                .inner_margin(Margin::symmetric(12, 8))
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new(format!("设备登录码: {code}"))
                                            .size(14.0)
                                            .monospace()
                                            .strong()
                                            .color(p.accent),
                                    );
                                    if ui.button("复制验证码并打开浏览器").clicked() {
                                        self.copy_to_clipboard(code, "微软设备验证码");
                                        let _ = open::that(uri);
                                    }
                                });
                        }

                        ui.add_space(8.0);
                        ui.label(RichText::new("端到端加密口令:").size(12.0).color(p.dim));
                        ui.add(
                            egui::TextEdit::singleline(passphrase)
                                .password(true)
                                .hint_text("用于 Argon2id + AES-256-GCM 加密主机与备注元数据")
                                .desired_width(f32::INFINITY),
                        );
                        ui.checkbox(remember_key, "在本机记住加密口令");

                        // 同步进行中 / 刚结束的反馈就贴在这里 —— 按钮旁边，
                        // 而不是顶栏角落一个谁都不会注意的小圈。
                        ui.add_space(10.0);
                        if let Some(phase) = self.sync_phase {
                            Self::draw_sync_progress(
                                ui,
                                &p,
                                phase,
                                self.sync_started.map(|t| t.elapsed()).unwrap_or_default(),
                            );
                        } else if let Some(out) = &self.sync_outcome {
                            Self::draw_sync_outcome(ui, &p, out);
                        }

                        if !conflicts.is_empty() {
                            ui.add_space(6.0);
                            ui.label(
                                RichText::new(format!(
                                    "⚠ 发现 {} 项主机指纹冲突，点击同步将信任新指纹",
                                    conflicts.len()
                                ))
                                .size(11.5)
                                .color(p.warn),
                            );
                        }

                        ui.add_space(12.0);
                        let cid_val = client_id.trim().to_string();
                        let pp_val = passphrase.clone();
                        let rem = *remember_key;
                        ui.horizontal(|ui| {
                            if !logged_in {
                                if Self::action_btn(ui, &p, "登录微软账号", true, false).clicked()
                                {
                                    let engine = Arc::clone(&self.engine);
                                    let tx = self.tx.clone();
                                    self.rt.spawn(async move {
                                        let cid_opt = if cid_val.is_empty() {
                                            None
                                        } else {
                                            Some(cid_val.as_str())
                                        };
                                        match engine.ms_start_login(cid_opt).await {
                                            Ok(flow) => {
                                                let uc = flow
                                                    .get("userCode")
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or("")
                                                    .to_string();
                                                let uri = flow
                                                    .get("verificationUri")
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or("https://microsoft.com/devicelogin")
                                                    .to_string();
                                                let dc = flow
                                                    .get("deviceCode")
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or("")
                                                    .to_string();
                                                let _ = tx.send(BgEvent::SyncDeviceCode {
                                                    user_code: uc,
                                                    verify_uri: uri.clone(),
                                                });
                                                let _ = open::that(&uri);
                                                if let Ok(st) =
                                                    engine.ms_complete_login(&dc, 300).await
                                                {
                                                    let _ = tx.send(BgEvent::SyncStatus(st));
                                                }
                                            }
                                            Err(e) => {
                                                let _ = tx.send(BgEvent::Log(e, LogKind::Err));
                                            }
                                        }
                                    });
                                }
                            } else {
                                // 同步中置灰并换文案：点下去要立刻有反应，也顺手
                                // 掐掉连点两次并发同步的可能。
                                let running = self.sync_phase.is_some();
                                let sync_label = if running {
                                    "↻ 正在同步…"
                                } else {
                                    "↻ 立即双向同步"
                                };
                                let sync_clicked = ui
                                    .add_enabled_ui(!running, |ui| {
                                        Self::action_btn(ui, &p, sync_label, true, false)
                                    })
                                    .inner
                                    .clicked();
                                if sync_clicked {
                                    if rem && !pp_val.is_empty() {
                                        let _ = self.engine.ms_save_config(None, Some(&pp_val));
                                    }
                                    self.busy = true;
                                    // 点下去立刻进「同步中」：不等后台第一个回调，
                                    // 否则网络那几百毫秒里界面还是死的。
                                    self.sync_phase = Some(ms_sync::SyncPhase::Fetching);
                                    self.sync_started = Some(Instant::now());
                                    self.sync_outcome = None;
                                    self.sync_hosts_before = self.hosts.len();
                                    let engine = Arc::clone(&self.engine);
                                    let tx = self.tx.clone();
                                    let phase_tx = tx.clone();
                                    self.rt.spawn(async move {
                                        match engine
                                            .ms_sync_with(&pp_val, &[], false, move |ph| {
                                                let _ = phase_tx.send(BgEvent::SyncProgress(ph));
                                            })
                                            .await
                                        {
                                            Ok(rep) => {
                                                let st = engine.ms_status();
                                                let _ = tx.send(BgEvent::SyncDone {
                                                    report: rep,
                                                    status: st,
                                                });
                                            }
                                            Err(e) => {
                                                // 失败也要让抽屉里留张红卡：只写日志
                                                // 等于没反馈，日志抽屉默认是关的。
                                                let _ = tx.send(BgEvent::SyncFailed(e));
                                            }
                                        }
                                    });
                                }
                                if Self::action_btn(ui, &p, "退出账号", false, true).clicked() {
                                    let _ = self.engine.ms_logout();
                                    self.ms_status = self.engine.ms_status();
                                    // 换了/退了账号，上一次的结果卡就不再适用了。
                                    self.sync_outcome = None;
                                }
                            }
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if Self::action_btn(ui, &p, "关闭", false, false).clicked() {
                                    close_drawer = true;
                                }
                            });
                        });
                    }

                    Drawer::Settings {
                        theme_choice,
                        local_key_dir,
                        save_dir,
                        remote_path,
                    } => {
                        ui.label(
                            RichText::new("全局外观与路径设置")
                                .size(15.5)
                                .strong()
                                .color(p.text),
                        );
                        ui.separator();

                        ui.label(RichText::new("配色主题:").color(p.dim));
                        ui.horizontal_wrapped(|ui| {
                            for (tid, tname) in THEME_CHOICES {
                                if ui
                                    .selectable_label(theme_choice.as_str() == tid, tname)
                                    .clicked()
                                {
                                    *theme_choice = tid.to_string();
                                    self.theme_choice = tid.to_string();
                                    let sys_dark = is_system_dark();
                                    self.palette = resolve_palette(&self.theme_choice, sys_dark);
                                    apply_palette(ctx, &self.palette);
                                    let _ = save_theme(&self.data_dir, &self.theme_choice);
                                }
                            }
                        });

                        ui.add_space(8.0);
                        ui.label(RichText::new("本机密钥扫描目录:").color(p.dim));
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(local_key_dir).desired_width(380.0),
                            );
                            if ui.button("选择目录…").clicked() {
                                if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                                    *local_key_dir = dir.to_string_lossy().to_string();
                                }
                            }
                        });

                        ui.add_space(6.0);
                        ui.label(RichText::new("生成密钥默认保存目录:").color(p.dim));
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(save_dir).desired_width(380.0));
                            if ui.button("选择目录…").clicked() {
                                if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                                    *save_dir = dir.to_string_lossy().to_string();
                                }
                            }
                        });

                        ui.add_space(6.0);
                        ui.label(RichText::new("远端默认 authorized_keys 路径:").color(p.dim));
                        ui.add(
                            egui::TextEdit::singleline(remote_path).desired_width(f32::INFINITY),
                        );

                        ui.add_space(12.0);
                        let lkd = local_key_dir.trim().to_string();
                        let sd = save_dir.trim().to_string();
                        let rp = remote_path.trim().to_string();
                        ui.horizontal(|ui| {
                            if Self::action_btn(ui, &p, "打开数据目录", false, false).clicked() {
                                let _ = open::that(&self.data_dir);
                            }
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if Self::action_btn(ui, &p, "保存设置", true, false).clicked() {
                                    let _ = save_theme(&self.data_dir, &self.theme_choice);
                                    let _ = self.engine.state().store.update_settings(
                                        SettingsPatch {
                                            local_key_dir: Some(lkd),
                                            save_dir: Some(sd),
                                            remote_path: Some(rp),
                                        },
                                    );
                                    self.trigger_local_scan(true);
                                    self.push_log("全局设置已保存", LogKind::Ok);
                                    close_drawer = true;
                                }
                                if Self::action_btn(ui, &p, "关闭", false, false).clicked() {
                                    close_drawer = true;
                                }
                            });
                        });
                    }

                    Drawer::FileNewDir { name } => {
                        ui.label(
                            RichText::new("新建文件夹")
                                .size(15.5)
                                .strong()
                                .color(p.text),
                        );
                        ui.separator();
                        ui.label(
                            RichText::new(format!("位置：{}", self.files_path))
                                .size(11.5)
                                .monospace()
                                .color(p.dim),
                        );
                        ui.add_space(8.0);
                        ui.add(
                            egui::TextEdit::singleline(name)
                                .hint_text("文件夹名称")
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(12.0);
                        ui.horizontal(|ui| {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if Self::action_btn(ui, &p, "创建", true, false).clicked() {
                                    let target = name.trim().to_string();
                                    if target.is_empty() {
                                        self.push_log("文件夹名不能为空", LogKind::Warn);
                                    } else {
                                        self.file_mkdir(target);
                                        close_drawer = true;
                                    }
                                }
                                if Self::action_btn(ui, &p, "取消", false, false).clicked() {
                                    close_drawer = true;
                                }
                            });
                        });
                    }

                    Drawer::FileRename { from, name } => {
                        ui.label(
                            RichText::new("重命名")
                                .size(15.5)
                                .strong()
                                .color(p.text),
                        );
                        ui.separator();
                        ui.label(
                            RichText::new(format!("原路径：{from}"))
                                .size(11.5)
                                .monospace()
                                .color(p.dim),
                        );
                        ui.add_space(8.0);
                        ui.add(
                            egui::TextEdit::singleline(name)
                                .hint_text("新名称")
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(12.0);
                        ui.horizontal(|ui| {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if Self::action_btn(ui, &p, "保存", true, false).clicked() {
                                    let target = name.trim().to_string();
                                    if target.is_empty() {
                                        self.push_log("新名称不能为空", LogKind::Warn);
                                    } else {
                                        self.file_rename(from.clone(), target);
                                        close_drawer = true;
                                    }
                                }
                                if Self::action_btn(ui, &p, "取消", false, false).clicked() {
                                    close_drawer = true;
                                }
                            });
                        });
                    }

                    Drawer::FileChmod { path, mode } => {
                        ui.label(
                            RichText::new("修改权限")
                                .size(15.5)
                                .strong()
                                .color(p.text),
                        );
                        ui.separator();
                        ui.label(
                            RichText::new(format!("路径：{path}"))
                                .size(11.5)
                                .monospace()
                                .color(p.dim),
                        );
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("八进制权限:").color(p.dim));
                            ui.add(
                                egui::TextEdit::singleline(mode)
                                    .hint_text("644")
                                    .font(FontId::monospace(13.0))
                                    .desired_width(120.0),
                            );
                            ui.label(
                                RichText::new("例如 644 / 755 / 600")
                                    .size(11.0)
                                    .color(p.faint),
                            );
                        });
                        ui.add_space(12.0);
                        ui.horizontal(|ui| {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if Self::action_btn(ui, &p, "应用", true, false).clicked() {
                                    match u32::from_str_radix(mode.trim(), 8) {
                                        Ok(m) if m <= 0o7777 => {
                                            self.file_chmod(path.clone(), m);
                                            close_drawer = true;
                                        }
                                        _ => self.push_log(
                                            "权限值必须是 0–7777 的八进制",
                                            LogKind::Warn,
                                        ),
                                    }
                                }
                                if Self::action_btn(ui, &p, "取消", false, false).clicked() {
                                    close_drawer = true;
                                }
                            });
                        });
                    }

                    Drawer::FileRemove { path, is_dir } => {
                        let kind = if *is_dir { "文件夹" } else { "文件" };
                        ui.label(
                            RichText::new(format!("删除{kind}"))
                                .size(15.5)
                                .strong()
                                .color(p.text),
                        );
                        ui.separator();
                        ui.label(
                            RichText::new(path.as_str())
                                .size(11.5)
                                .monospace()
                                .color(p.dim),
                        );
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(if *is_dir {
                                "目录必须为空才能被 SFTP 删除；删除后不可恢复。"
                            } else {
                                "删除后不可恢复，请确认路径无误。"
                            })
                            .size(11.5)
                            .color(p.warn),
                        );
                        ui.add_space(12.0);
                        ui.horizontal(|ui| {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if Self::action_btn(ui, &p, "确认删除", false, true).clicked() {
                                    self.file_remove(path.clone());
                                    close_drawer = true;
                                }
                                if Self::action_btn(ui, &p, "取消", false, false).clicked() {
                                    close_drawer = true;
                                }
                            });
                        });
                    }
                }

                if !close_drawer {
                    self.drawer = current;
                }
            });
    }

    /// 同步进行中的进度条：当前阶段高亮，后面的阶段淡着。
    fn draw_sync_progress(
        ui: &mut egui::Ui,
        p: &Palette,
        phase: ms_sync::SyncPhase,
        elapsed: Duration,
    ) {
        let steps = [
            (ms_sync::SyncPhase::Fetching, "读取云端"),
            (ms_sync::SyncPhase::Merging, "解密合并"),
            (ms_sync::SyncPhase::Uploading, "上传"),
        ];
        let idx = steps.iter().position(|(s, _)| *s == phase).unwrap_or(0);

        Frame::NONE
            .fill(p.surface2)
            .stroke(Stroke::new(1.0_f32, p.border))
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::symmetric(12, 10))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(
                        RichText::new(format!("正在同步… {:.1}s", elapsed.as_secs_f32()))
                            .size(12.5)
                            .strong()
                            .color(p.text),
                    );
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    for (i, (_, name)) in steps.iter().enumerate() {
                        let reached = i <= idx;
                        Frame::NONE
                            .fill(if reached { p.accent_soft } else { p.surface3 })
                            .corner_radius(CornerRadius::same(10))
                            .inner_margin(Margin::symmetric(9, 3))
                            .show(ui, |ui| {
                                ui.label(RichText::new(*name).size(11.5).color(if reached {
                                    p.accent
                                } else {
                                    p.faint
                                }));
                            });
                        if i + 1 < steps.len() {
                            ui.label(RichText::new("›").size(11.0).color(p.faint));
                        }
                    }
                });
            });
    }

    /// 同步结束后的结果卡：成功留绿卡，失败 / 冲突留红卡。
    fn draw_sync_outcome(ui: &mut egui::Ui, p: &Palette, out: &SyncOutcome) {
        let (fg, fill, edge) = if out.ok {
            (p.ok, p.ok_soft, p.ok.gamma_multiply(0.45))
        } else {
            (p.danger, p.danger_soft, p.danger.gamma_multiply(0.45))
        };
        Frame::NONE
            .fill(fill)
            .stroke(Stroke::new(1.0_f32, edge))
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::symmetric(12, 10))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(out.title.as_str())
                        .size(12.5)
                        .strong()
                        .color(fg),
                );
                ui.add_space(4.0);
                for line in &out.lines {
                    ui.label(RichText::new(line.as_str()).size(11.5).color(p.dim));
                }
            });
    }

    fn action_btn(
        ui: &mut egui::Ui,
        p: &Palette,
        label: &str,
        primary: bool,
        danger: bool,
    ) -> egui::Response {
        let (fill, stroke, fg) = if primary {
            (p.accent, Stroke::new(1.0_f32, p.accent), Color32::WHITE)
        } else if danger {
            (
                p.danger.gamma_multiply(0.14),
                Stroke::new(1.0_f32, p.danger.gamma_multiply(0.45)),
                p.danger,
            )
        } else {
            (p.surface3, Stroke::new(1.0_f32, p.border), p.text)
        };
        ui.add(
            egui::Button::new(RichText::new(label).size(12.0).strong().color(fg))
                .fill(fill)
                .stroke(stroke)
                .corner_radius(CornerRadius::same(7))
                .min_size(Vec2::new(0.0, 28.0)),
        )
    }
}

/* ------------------------------------------------------------------ */
/* 状态监控：卡片与图表的小工具                                        */
/* ------------------------------------------------------------------ */

fn mon_card<R>(
    ui: &mut egui::Ui,
    p: &Palette,
    width: f32,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    Frame::NONE
        .fill(p.panel)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(15, 12))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.set_width((width - 30.0).max(40.0));
                add(ui)
            })
        })
        .inner
        .inner
}

fn mon_cardhead(ui: &mut egui::Ui, p: &Palette, title: &str, hint: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(title).size(12.5).strong().color(p.text));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(hint).size(10.5).color(p.faint));
        });
    });
    ui.add_space(10.0);
}

fn mon_tag(ui: &mut egui::Ui, p: &Palette, prefix: &str, value: &str) {
    Frame::NONE
        .fill(p.surface3)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                if !prefix.is_empty() {
                    ui.label(RichText::new(prefix).size(10.5).color(p.faint));
                }
                if !value.is_empty() {
                    ui.label(RichText::new(value).size(10.5).color(p.dim));
                }
            });
        });
}

fn mon_seg(ui: &mut egui::Ui, p: &Palette, current: u64) -> Option<u64> {
    let mut picked = None;
    Frame::NONE
        .fill(p.surface2)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(2))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                for (ms, label) in [(1000u64, "1s"), (2000, "2s"), (5000, "5s")] {
                    if mon_seg_btn(ui, p, label, current == ms).clicked() {
                        picked = Some(ms);
                    }
                }
            });
        });
    picked
}

fn mon_seg_btn(ui: &mut egui::Ui, p: &Palette, label: &str, on: bool) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(36.0, 22.0), Sense::click());
    if on {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(6), p.accent_soft);
    } else if resp.hovered() {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(6), p.surface3);
    }
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        label,
        FontId::proportional(11.5),
        if on { p.text } else { p.dim },
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
    }
    resp
}

/// `warn` 为真时是「暂停」按钮（琥珀色），为假时是「继续」（蓝色）。
fn mon_small_btn(ui: &mut egui::Ui, p: &Palette, label: &str, warn: bool) -> egui::Response {
    let (fill, stroke, fg) = if warn {
        (
            p.warn_soft,
            Stroke::new(1.0_f32, p.warn.gamma_multiply(0.35)),
            p.warn,
        )
    } else {
        (
            p.accent_soft,
            Stroke::new(1.0_f32, p.accent.gamma_multiply(0.5)),
            p.text,
        )
    };
    ui.add(
        egui::Button::new(RichText::new(label).size(12.0).color(fg))
            .fill(fill)
            .stroke(stroke)
            .corner_radius(CornerRadius::same(8))
            .min_size(Vec2::new(58.0, 30.0)),
    )
}

#[allow(clippy::too_many_arguments)]
fn mon_kpi(
    ui: &mut egui::Ui,
    p: &Palette,
    width: f32,
    icon: Icon,
    title: &str,
    value: &str,
    unit: &str,
    sub: &[(String, String)],
    hist: &VecDeque<f64>,
    color: Color32,
) {
    Frame::NONE
        .fill(p.panel)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(15, 11))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.set_width((width - 30.0).max(40.0));
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 7.0;
                    let (icon_rect, _) = ui.allocate_exact_size(Vec2::splat(13.0), Sense::hover());
                    draw_icon(ui.painter(), icon_rect.center(), 13.0, icon, p.dim);
                    ui.label(RichText::new(title).size(11.5).color(p.dim));
                });
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 7.0;
                    ui.label(
                        RichText::new(value)
                            .size(24.0)
                            .strong()
                            .monospace()
                            .color(p.text),
                    );
                    if !unit.is_empty() {
                        ui.label(RichText::new(unit).size(11.0).color(p.faint));
                    }
                });
                ui.add_space(5.0);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 5.0;
                    for (i, (lab, val)) in sub.iter().enumerate() {
                        if i > 0 {
                            ui.label(RichText::new("·").size(10.5).color(p.faint));
                        }
                        ui.label(RichText::new(lab).size(10.5).color(p.faint));
                        ui.label(RichText::new(val).size(10.5).color(p.dim));
                    }
                });
                ui.add_space(3.0);
                let (rect, _) =
                    ui.allocate_exact_size(Vec2::new(ui.available_width(), 34.0), Sense::hover());
                let w = rect.width().min(118.0);
                let spark = Rect::from_min_size(
                    Pos2::new(rect.right() - w, rect.top()),
                    Vec2::new(w, 34.0),
                );
                paint_sparkline(ui.painter(), spark, hist, color);
            });
        });
}

fn mon_kpi_cpu(
    ui: &mut egui::Ui,
    p: &Palette,
    width: f32,
    s: &MonitorSnapshot,
    hist: &VecDeque<f64>,
) {
    let sub = vec![
        ("用户".to_string(), format!("{:.1}%", s.cpu.user)),
        ("系统".to_string(), format!("{:.1}%", s.cpu.system)),
        ("IO".to_string(), format!("{:.1}%", s.cpu.iowait)),
    ];
    mon_kpi(
        ui,
        p,
        width,
        Icon::Cpu,
        "CPU",
        &format!("{:.1}%", s.cpu.total),
        &format!("{} 核平均", s.cores.max(1)),
        &sub,
        hist,
        p.accent,
    );
}

fn mon_kpi_mem(
    ui: &mut egui::Ui,
    p: &Palette,
    width: f32,
    s: &MonitorSnapshot,
    hist: &VecDeque<f64>,
) {
    let pct = if s.mem.total > 0.0 {
        s.mem.used / s.mem.total * 100.0
    } else {
        0.0
    };
    let sub = vec![
        (
            "Swap".to_string(),
            format!(
                "{} / {}",
                mon_bytes(s.mem.swap_used as u64),
                mon_bytes(s.mem.swap_total as u64)
            ),
        ),
        ("缓存".to_string(), mon_bytes(s.mem.cached as u64)),
    ];
    mon_kpi(
        ui,
        p,
        width,
        Icon::Memory,
        "内存",
        &format!("{pct:.0}%"),
        &format!(
            "{} / {}",
            mon_bytes(s.mem.used as u64),
            mon_bytes(s.mem.total as u64)
        ),
        &sub,
        hist,
        p.ok,
    );
}

fn mon_kpi_load(
    ui: &mut egui::Ui,
    p: &Palette,
    width: f32,
    s: &MonitorSnapshot,
    hist: &VecDeque<f64>,
) {
    let sub = vec![
        ("5 分钟".to_string(), format!("{:.2}", s.load.five)),
        ("15 分钟".to_string(), format!("{:.2}", s.load.fifteen)),
    ];
    mon_kpi(
        ui,
        p,
        width,
        Icon::Load,
        "系统负载",
        &format!("{:.2}", s.load.one),
        "1 分钟",
        &sub,
        hist,
        p.warn,
    );
}

fn mon_kpi_net(
    ui: &mut egui::Ui,
    p: &Palette,
    width: f32,
    s: &MonitorSnapshot,
    hist: &VecDeque<f64>,
) {
    let sub = vec![
        ("↑".to_string(), mon_rate(s.net.tx_bytes_per_sec)),
        ("累计 ↓".to_string(), mon_bytes(s.net.rx_total as u64)),
    ];
    mon_kpi(
        ui,
        p,
        width,
        Icon::Network,
        "网络",
        &mon_rate(s.net.rx_bytes_per_sec),
        "↓",
        &sub,
        hist,
        p.accent,
    );
}

fn mon_cores_card(
    ui: &mut egui::Ui,
    p: &Palette,
    width: f32,
    s: &MonitorSnapshot,
    interval_ms: u64,
    paused: bool,
) {
    mon_card(ui, p, width, |ui| {
        let hint = if paused {
            "已暂停".to_string()
        } else {
            format!("每 {} 秒采样 /proc/stat", (interval_ms / 1000).max(1))
        };
        mon_cardhead(ui, p, "CPU 核心", &hint);
        let n = s.cpu.per_core.len();
        if n == 0 {
            ui.label(
                RichText::new("服务器没有返回每核数据")
                    .size(11.0)
                    .color(p.faint),
            );
            return;
        }
        let cols = n.min(4);
        let inner = ui.available_width();
        let gap = 14.0_f32;
        let cell_w = ((inner - gap * (cols as f32 - 1.0)) / cols as f32).max(40.0);
        for start in (0..n).step_by(cols) {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = gap;
                for i in start..(start + cols).min(n) {
                    let v = s.cpu.per_core[i];
                    ui.allocate_ui_with_layout(
                        Vec2::new(cell_w, 31.0),
                        Layout::top_down(Align::Min),
                        |ui| {
                            ui.spacing_mut().item_spacing.y = 5.0;
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!("cpu{i}"))
                                        .size(10.5)
                                        .monospace()
                                        .color(p.faint),
                                );
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(
                                        RichText::new(format!("{v:.0}%"))
                                            .size(10.5)
                                            .monospace()
                                            .color(p.dim),
                                    );
                                });
                            });
                            let color = if v >= 85.0 {
                                p.danger
                            } else if v >= 60.0 {
                                p.warn
                            } else {
                                p.accent
                            };
                            paint_bar(ui, cell_w, 6.0, (v / 100.0) as f32, color, p.surface3);
                        },
                    );
                }
            });
            ui.add_space(10.0);
        }
    });
}

fn mon_disks_card(ui: &mut egui::Ui, p: &Palette, width: f32, s: &MonitorSnapshot) {
    mon_card(ui, p, width, |ui| {
        mon_cardhead(ui, p, "磁盘使用", "df -P -B1");
        if s.disks.is_empty() {
            ui.label(
                RichText::new("没有可展示的本地文件系统")
                    .size(11.0)
                    .color(p.faint),
            );
            return;
        }
        for d in &s.disks {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&d.mount).size(11.0).monospace().color(p.text));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("{:.0}%", d.percent))
                            .size(10.5)
                            .monospace()
                            .color(p.dim),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{} / {}",
                            mon_bytes(d.used as u64),
                            mon_bytes(d.total as u64)
                        ))
                        .size(10.5)
                        .monospace()
                        .color(p.faint),
                    );
                });
            });
            ui.add_space(5.0);
            paint_bar(
                ui,
                ui.available_width(),
                7.0,
                (d.percent / 100.0) as f32,
                p.accent,
                p.surface3,
            );
            ui.add_space(10.0);
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn mon_net_card(
    ui: &mut egui::Ui,
    p: &Palette,
    width: f32,
    s: &MonitorSnapshot,
    down_hist: &VecDeque<f64>,
    up_hist: &VecDeque<f64>,
    peak_down: f64,
    peak_up: f64,
) {
    mon_card(ui, p, width, |ui| {
        mon_cardhead(ui, p, "网络吞吐", "/proc/net/dev 差值");
        let inner = ui.available_width();
        let gap = 16.0;
        let col_w = ((inner - gap) / 2.0).max(80.0);
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            mon_net_col(
                ui,
                p,
                col_w,
                "↓",
                p.accent,
                &mon_rate(s.net.rx_bytes_per_sec),
                &format!(
                    "累计 {} · 峰值 {}",
                    mon_bytes(s.net.rx_total as u64),
                    mon_rate(peak_down)
                ),
                down_hist,
                p.accent,
            );
            mon_net_col(
                ui,
                p,
                col_w,
                "↑",
                p.ok,
                &mon_rate(s.net.tx_bytes_per_sec),
                &format!(
                    "累计 {} · 峰值 {}",
                    mon_bytes(s.net.tx_total as u64),
                    mon_rate(peak_up)
                ),
                up_hist,
                p.ok,
            );
        });
    });
}

#[allow(clippy::too_many_arguments)]
fn mon_net_col(
    ui: &mut egui::Ui,
    p: &Palette,
    width: f32,
    arrow: &str,
    arrow_color: Color32,
    rate: &str,
    total: &str,
    hist: &VecDeque<f64>,
    line_color: Color32,
) {
    ui.allocate_ui_with_layout(
        Vec2::new(width, 122.0),
        Layout::top_down(Align::Min),
        |ui| {
            ui.set_width(width);
            ui.spacing_mut().item_spacing.y = 4.0;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(RichText::new(arrow).size(12.0).color(arrow_color));
                ui.label(
                    RichText::new(rate)
                        .size(18.0)
                        .strong()
                        .monospace()
                        .color(p.text),
                );
            });
            ui.label(RichText::new(total).size(10.0).monospace().color(p.faint));
            ui.add_space(4.0);
            let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 74.0), Sense::hover());
            paint_net_chart(ui.painter(), rect, hist, line_color, p.surface2, p.border);
        },
    );
}

fn mon_procs_card(ui: &mut egui::Ui, p: &Palette, width: f32, s: &MonitorSnapshot, sort_by_mem: &mut bool) {
    mon_card(ui, p, width, |ui| {
        let sort_label = if *sort_by_mem {
            "按 内存 排序 · top 6"
        } else {
            "按 CPU 排序 · top 6"
        };
        mon_cardhead(ui, p, "高占用进程", sort_label);
        if s.processes.is_empty() {
            ui.label(
                RichText::new("没有可展示的进程数据")
                    .size(11.0)
                    .color(p.faint),
            );
            return;
        }
        let inner = ui.available_width();
        let compact = inner < 340.0;
        let pid_w = 40.0;
        let cpu_w = 46.0;
        let mem_w = if compact { 64.0 } else { 118.0 };
        let gap = 12.0;
        let comm_w = (inner - pid_w - cpu_w - mem_w - gap * 3.0).max(56.0);
        let max_mem = s
            .processes
            .iter()
            .map(|x| x.mem_bytes)
            .fold(0.0f64, f64::max)
            .max(1.0);

        let mut procs = s.processes.clone();
        if *sort_by_mem {
            procs.sort_by(|a, b| b.mem_bytes.total_cmp(&a.mem_bytes));
        } else {
            procs.sort_by(|a, b| b.cpu.total_cmp(&a.cpu));
        }

        egui::Grid::new("kw_monitor_procs")
            .num_columns(4)
            .spacing([gap, 7.0])
            .show(ui, |ui| {
                ui.allocate_ui_with_layout(
                    Vec2::new(pid_w, 14.0),
                    Layout::left_to_right(Align::Center),
                    |ui| {
                        ui.label(RichText::new("PID").size(10.0).color(p.faint));
                    },
                );
                ui.allocate_ui_with_layout(
                    Vec2::new(comm_w, 14.0),
                    Layout::left_to_right(Align::Center),
                    |ui| {
                        ui.label(RichText::new("命令").size(10.0).color(p.faint));
                    },
                );
                ui.allocate_ui_with_layout(
                    Vec2::new(cpu_w, 14.0),
                    Layout::right_to_left(Align::Center),
                    |ui| {
                        let text = if !*sort_by_mem { "CPU ▼" } else { "CPU" };
                        let col = if !*sort_by_mem { p.accent } else { p.faint };
                        if ui
                            .add(egui::Label::new(RichText::new(text).size(10.0).strong().color(col)).sense(Sense::click()))
                            .on_hover_text("点击按 CPU 占用排序")
                            .clicked()
                        {
                            *sort_by_mem = false;
                        }
                    },
                );
                ui.allocate_ui_with_layout(
                    Vec2::new(mem_w, 14.0),
                    Layout::left_to_right(Align::Center),
                    |ui| {
                        let text = if *sort_by_mem { "内存 ▼" } else { "内存" };
                        let col = if *sort_by_mem { p.accent } else { p.faint };
                        if ui
                            .add(egui::Label::new(RichText::new(text).size(10.0).strong().color(col)).sense(Sense::click()))
                            .on_hover_text("点击按内存占用排序")
                            .clicked()
                        {
                            *sort_by_mem = true;
                        }
                    },
                );
                ui.end_row();

                for pr in procs.iter().take(6) {
                    ui.allocate_ui_with_layout(
                        Vec2::new(pid_w, 16.0),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            let resp = ui.add(
                                egui::Label::new(
                                    RichText::new(pr.pid.to_string())
                                        .size(10.5)
                                        .monospace()
                                        .color(p.dim),
                                )
                                .sense(Sense::click()),
                            );
                            resp.context_menu(|ui| {
                                if ui.button(format!("📋 复制 PID ({})", pr.pid)).clicked() {
                                    ui.ctx().copy_text(pr.pid.to_string());
                                    ui.close_menu();
                                }
                            });
                        },
                    );
                    ui.allocate_ui_with_layout(
                        Vec2::new(comm_w, 16.0),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&pr.comm).size(10.5).monospace().color(p.text),
                                )
                                .truncate(),
                            );
                        },
                    );
                    ui.allocate_ui_with_layout(
                        Vec2::new(cpu_w, 16.0),
                        Layout::right_to_left(Align::Center),
                        |ui| {
                            let col = if pr.cpu > 50.0 { p.warn } else { p.dim };
                            ui.label(
                                RichText::new(format!("{:.1}%", pr.cpu))
                                    .size(10.5)
                                    .monospace()
                                    .color(col),
                            );
                        },
                    );
                    ui.allocate_ui_with_layout(
                        Vec2::new(mem_w, 16.0),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            if !compact {
                                let frac = (pr.mem_bytes / max_mem) as f32;
                                paint_bar(ui, 54.0, 5.0, frac, p.accent, p.surface3);
                                ui.add_space(7.0);
                            }
                            ui.label(
                                RichText::new(mon_bytes(pr.mem_bytes as u64))
                                    .size(10.0)
                                    .monospace()
                                    .color(p.dim),
                            );
                        },
                    );
                    ui.end_row();
                }
            });
    });
}

fn paint_bar(ui: &mut egui::Ui, width: f32, height: f32, frac: f32, color: Color32, bg: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, height), Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::same(3), bg);
    let frac = frac.clamp(0.0, 1.0);
    if frac > 0.0 {
        let w = (rect.width() * frac).max(2.0).min(rect.width());
        let fill = Rect::from_min_size(rect.min, Vec2::new(w, rect.height()));
        ui.painter().rect_filled(fill, CornerRadius::same(3), color);
    }
}

fn paint_sparkline(painter: &egui::Painter, rect: Rect, data: &VecDeque<f64>, color: Color32) {
    if data.is_empty() {
        return;
    }
    let mut max = data.iter().cloned().fold(0.0f64, f64::max) * 1.15;
    if max <= 0.0 {
        max = 1.0;
    }
    let n = data.len();
    let mut pts: Vec<Pos2> = Vec::with_capacity(n);
    for (i, v) in data.iter().enumerate() {
        let x = if n == 1 {
            rect.right()
        } else {
            rect.left() + rect.width() * (i as f32 / (n - 1) as f32)
        };
        let y = rect.bottom() - ((v / max).clamp(0.0, 1.0) as f32) * rect.height();
        pts.push(Pos2::new(x, y));
    }
    if n == 1 {
        pts.insert(0, Pos2::new(rect.left(), pts[0].y));
    }
    let mut fill_pts = pts.clone();
    fill_pts.push(Pos2::new(rect.right(), rect.bottom()));
    fill_pts.push(Pos2::new(rect.left(), rect.bottom()));
    painter.add(egui::Shape::Path(egui::epaint::PathShape {
        points: fill_pts,
        closed: true,
        fill: color.gamma_multiply(0.10),
        stroke: egui::epaint::PathStroke::NONE,
    }));
    painter.add(egui::Shape::line(pts, Stroke::new(1.4_f32, color)));
}

fn paint_net_chart(
    painter: &egui::Painter,
    rect: Rect,
    data: &VecDeque<f64>,
    line: Color32,
    bg: Color32,
    grid: Color32,
) {
    painter.rect_filled(rect, CornerRadius::same(8), bg);
    painter.rect_stroke(
        rect,
        CornerRadius::same(8),
        Stroke::new(1.0_f32, grid.gamma_multiply(0.6)),
        StrokeKind::Inside,
    );
    for i in 1..4 {
        let y = rect.top() + rect.height() * i as f32 / 4.0;
        painter.line_segment(
            [
                Pos2::new(rect.left() + 1.0, y),
                Pos2::new(rect.right() - 1.0, y),
            ],
            Stroke::new(1.0_f32, grid.gamma_multiply(0.55)),
        );
    }
    if data.len() < 2 {
        return;
    }
    let mut max = data.iter().cloned().fold(0.0f64, f64::max) * 1.15;
    if max <= 0.0 {
        max = 1.0;
    }
    let pad = 4.0;
    let inner = Rect::from_min_max(
        Pos2::new(rect.left() + pad, rect.top() + pad),
        Pos2::new(rect.right() - pad, rect.bottom() - pad),
    );
    let n = data.len();
    let pts: Vec<Pos2> = data
        .iter()
        .enumerate()
        .map(|(i, v)| {
            Pos2::new(
                inner.left() + inner.width() * (i as f32 / (n - 1) as f32),
                inner.bottom() - ((v / max).clamp(0.0, 1.0) as f32) * inner.height(),
            )
        })
        .collect();
    painter.add(egui::Shape::line(pts, Stroke::new(1.5_f32, line)));
}

fn mon_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if size >= 100.0 {
        format!("{size:.0} {}", UNITS[unit])
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

fn mon_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1024.0 {
        format!("{bytes_per_sec:.0} B/s")
    } else if bytes_per_sec < 1024.0 * 1024.0 {
        format!("{:.0} KB/s", bytes_per_sec / 1024.0)
    } else if bytes_per_sec < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.2} MB/s", bytes_per_sec / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB/s", bytes_per_sec / (1024.0 * 1024.0 * 1024.0))
    }
}

fn mon_uptime(secs: f64) -> String {
    let total = secs.max(0.0) as u64;
    let days = total / 86_400;
    let hours = (total % 86_400) / 3600;
    let mins = (total % 3600) / 60;
    if days > 0 {
        if hours > 0 {
            format!("{days} 天 {hours} 小时")
        } else {
            format!("{days} 天")
        }
    } else if hours > 0 {
        format!("{hours} 小时")
    } else {
        format!("{} 分钟", mins.max(1))
    }
}

fn join_remote(dir: &str, name: &str) -> String {
    let name = name.trim_start_matches('/');
    if dir.is_empty() || dir == "/" {
        format!("/{name}")
    } else if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn err_text(value: &Value, fallback: &str) -> String {
    value
        .get("error")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback)
        .to_string()
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut size = bytes as f64 / 1024.0;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    format!("{size:.1} {}", UNITS[unit])
}

fn format_unix_time(secs: u64) -> String {
    // 固定按东八区显示，和界面其它时间戳一致。
    let local = secs + 8 * 3600;
    let (year, month, day) = civil_from_days((local / 86_400) as i64);
    let rem = local % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

async fn list_and_notify(engine: &MobileEngine, tx: &Sender<BgEvent>, sid: &str, dir: &str) {
    match engine.sftp_list(sid, dir).await {
        Ok(v) => {
            let entries = v
                .get("entries")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default();
            let _ = tx.send(BgEvent::FilesListed {
                path: dir.to_string(),
                entries,
            });
        }
        Err(e) => {
            let _ = tx.send(BgEvent::FilesFailed(err_text(&e, "刷新目录失败")));
        }
    }
}

fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    let cjk_candidates = [
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\msyh.ttf",
        r"C:\Windows\Fonts\simhei.ttf",
    ];
    for path in cjk_candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert("sys_cjk".to_owned(), Arc::new(FontData::from_owned(bytes)));
            fonts
                .families
                .entry(FontFamily::Proportional)
                .or_default()
                .insert(0, "sys_cjk".to_owned());
            fonts
                .families
                .entry(FontFamily::Monospace)
                .or_default()
                .push("sys_cjk".to_owned());
            break;
        }
    }

    let mono_candidates = [
        r"C:\Windows\Fonts\CascadiaMono.ttf",
        r"C:\Windows\Fonts\consola.ttf",
    ];
    for path in mono_candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert("sys_mono".to_owned(), Arc::new(FontData::from_owned(bytes)));
            fonts
                .families
                .entry(FontFamily::Monospace)
                .or_default()
                .insert(0, "sys_mono".to_owned());
            break;
        }
    }

    let sym_candidates = [r"C:\Windows\Fonts\seguisym.ttf"];
    for (idx, path) in sym_candidates.iter().enumerate() {
        if let Ok(bytes) = std::fs::read(path) {
            let key = format!("sys_sym_{idx}");
            fonts
                .font_data
                .insert(key.clone(), Arc::new(FontData::from_owned(bytes)));
            fonts
                .families
                .entry(FontFamily::Proportional)
                .or_default()
                .push(key.clone());
            fonts
                .families
                .entry(FontFamily::Monospace)
                .or_default()
                .push(key);
        }
    }

    ctx.set_fonts(fonts);
}

#[cfg(test)]
mod login_pw_tests {
    use super::*;

    #[test]
    fn login_password_roundtrip_stays_out_of_config() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        assert_eq!(read_login_pw(p, "host-1"), None);
        write_login_pw(p, "host-1", Some("s3cret"));
        assert_eq!(read_login_pw(p, "host-1").as_deref(), Some("s3cret"));
        assert!(
            !p.join("config.json").exists(),
            "密码绝不能写进 config.json"
        );
        assert!(login_pw_file(p).exists());
        write_login_pw(p, "host-1", None);
        assert_eq!(read_login_pw(p, "host-1"), None);
        assert!(!login_pw_file(p).exists(), "清空后删掉文件，不留空壳");
    }

    #[test]
    fn empty_password_is_never_persisted() {
        let dir = tempfile::tempdir().unwrap();
        write_login_pw(dir.path(), "h", Some(""));
        assert_eq!(read_login_pw(dir.path(), "h"), None);
        assert!(!login_pw_file(dir.path()).exists());
    }

    #[test]
    fn multiple_hosts_are_independent() {
        let dir = tempfile::tempdir().unwrap();
        write_login_pw(dir.path(), "a", Some("pw-a"));
        write_login_pw(dir.path(), "b", Some("pw-b"));
        assert_eq!(read_login_pw(dir.path(), "a").as_deref(), Some("pw-a"));
        write_login_pw(dir.path(), "a", None);
        assert_eq!(read_login_pw(dir.path(), "a"), None);
        assert_eq!(read_login_pw(dir.path(), "b").as_deref(), Some("pw-b"));
    }
}

#[cfg(test)]
mod auth_method_tests {
    use super::*;

    #[test]
    fn auth_method_roundtrip_is_isolated_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        assert_eq!(read_auth_method(p, "h1"), None);
        write_auth_method(p, "h1", Some("key"));
        assert_eq!(read_auth_method(p, "h1").as_deref(), Some("key"));
        assert!(!p.join("config.json").exists());
        assert!(!login_pw_file(p).exists(), "认证方式与密码是两份独立文件");
        write_auth_method(p, "h1", Some("junk"));
        assert_eq!(read_auth_method(p, "h1"), None);
        assert!(!auth_method_file(p).exists());
    }

    #[test]
    fn encrypted_key_needs_passphrase_plain_key_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let plain = kw_keys::keygen::generate_ed25519(None, None).unwrap();
        let locked = kw_keys::keygen::generate_ed25519(None, Some("s3cret")).unwrap();
        let p1 = dir.path().join("plain.pem");
        let p2 = dir.path().join("locked.pem");
        std::fs::write(&p1, &plain.private_key_pem).unwrap();
        std::fs::write(&p2, &locked.private_key_pem).unwrap();
        assert!(!private_key_needs_passphrase(p1.to_str().unwrap()));
        assert!(private_key_needs_passphrase(p2.to_str().unwrap()));
        assert!(!private_key_needs_passphrase("Z:/definitely-missing.pem"));
    }
}

/// 云同步结果卡的「说清楚」测试。
///
/// 这几条是反证：只要后端把 `knownHostConflicts` 或 `addedHosts` 的
/// camelCase 字段改掉、或者把冲突挪到外层，卡片就会退化成一句「同步完成」，
/// 用户又回到「点了没反应」的状态 —— 所以字段路径必须被钉住。
#[cfg(test)]
mod sync_outcome_tests {
    use super::*;

    fn sample(
        pulled: bool,
        pushed: bool,
        counts: (u64, u64, u64, u64, u64),
        conflicts: Vec<Value>,
    ) -> Value {
        json!({
            "pulled": pulled,
            "pushed": pushed,
            "lastSyncAt": 1_700_000_000_000u64,
            "report": {
                "addedHosts": counts.0,
                "updatedHosts": counts.1,
                "deletedHosts": counts.2,
                "syncedNotes": counts.3,
                "importedKeys": counts.4,
                "knownHostConflicts": conflicts,
            }
        })
    }

    fn body(out: &SyncOutcome) -> String {
        out.lines.join(" | ")
    }

    #[test]
    fn merged_result_reports_real_numbers() {
        let r = sample(true, true, (2, 1, 0, 3, 1), vec![]);
        let out = KwDesktopApp::build_sync_outcome(&r, 7, 8, Duration::from_millis(2400));
        assert!(out.ok);
        assert!(out.title.contains("2.4s"), "{}", out.title);
        let text = body(&out);
        assert!(text.contains("7 台 → 8 台"), "{text}");
        assert!(
            text.contains("新增 2 · 更新 1 · 删除 0 · 备注 3 · 私钥 1"),
            "{text}"
        );
        assert!(text.contains("上次同步"), "{text}");
    }

    #[test]
    fn untouched_library_says_so_instead_of_showing_zeros() {
        let r = sample(true, true, (0, 0, 0, 0, 0), vec![]);
        let out = KwDesktopApp::build_sync_outcome(&r, 5, 5, Duration::from_millis(900));
        let text = body(&out);
        assert!(text.contains("两边本来就一致"), "{text}");
        assert!(!text.contains("新增 0"), "不该把一排 0 摊给用户：{text}");
    }

    #[test]
    fn conflicts_block_upload_and_name_the_host() {
        let r = sample(
            true,
            false,
            (0, 0, 0, 0, 0),
            vec![json!({"host": "10.0.0.9", "port": 2222})],
        );
        let out = KwDesktopApp::build_sync_outcome(&r, 3, 3, Duration::from_secs(1));
        assert!(!out.ok);
        assert!(out.title.contains("1 项"), "{}", out.title);
        let text = body(&out);
        assert!(text.contains("10.0.0.9:2222"), "{text}");
        assert!(text.contains("未上传"), "{text}");
    }

    #[test]
    fn first_upload_is_labelled_as_such() {
        let r = sample(false, true, (9, 0, 0, 0, 4), vec![]);
        let out = KwDesktopApp::build_sync_outcome(&r, 0, 9, Duration::from_millis(1500));
        let text = body(&out);
        assert!(text.contains("首次上传"), "{text}");
        assert!(text.contains("0 台 → 9 台"), "{text}");
    }
}
