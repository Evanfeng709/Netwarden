# Netwarden

本地 SSH 运维工作台 —— 管密钥、开终端、传文件、看状态、做同步。

Netwarden 是旧版 Electron + Node 实现（`../ssh-keywarden`）的 Rust 重写。它最初叫 SSH Keywarden，
v2026.11.15.1 起更名为 Netwarden：不再只是 `authorized_keys` 管理器，而是把密钥管理、SSH 终端、
SFTP 文件管理、主机监控、微软云同步和连接代理收进同一个工作台。

**桌面端是 100% 纯 Rust 原生 GUI**（eframe / egui 0.31）：没有 Tauri、没有 WebView2、没有本地
HTTP 服务，进程内直接调用 `kw-ffi::MobileEngine`，Working Set 从 120–180MB 降到 8–24MB。
手机端（Flutter）走同一个 `kw-ffi` 的 C ABI，两端共用业务层，都不需要监听端口。
SSH 层是 russh 0.65 + `ring`。`assets/public` 仍是独立浏览器模式的调试前端，桌面窗口不加载它。

> 当前版本：桌面 **v2026.11.15.1** / 手机 **v2026.11.16.1**；
> GitHub 仓库：[Evanfeng709/Netwarden](https://github.com/Evanfeng709/Netwarden)。
> crate 名仍是 `kw-*`，旧版 Electron 在 `../ssh-keywarden`。
> 改代码前先确认动的是哪一版。

## 功能一览

### 密钥管理

| 功能 | 说明 |
|---|---|
| 查看 | 拉取 `authorized_keys`，解析类型 / SHA256 指纹 / 注释 / options，与本地密钥库比对并标出对应私钥文件 |
| 搜索筛选 | 按注释、指纹、本地文件名 / 路径、备注实时过滤；可筛「本地无匹配 / 重复 / 本次在用」 |
| 备注 | 给钥匙写本地归属备注，只存 `key-notes.json`，不写服务器 |
| 备份恢复 | 列出 `.bak.YYYYMMDDHHMMSS`，先看差异再恢复；恢复前自动再备份，空备份硬拒绝 |
| 新增 | 本机生成 Ed25519 / RSA3072（可设 passphrase）、选已有公钥或直接粘贴；私钥默认落在本次登录私钥所在目录，注释默认 `用户名@服务器名-日期`（同日重复自动 `-2`、`-3`），写入后回读校验 |
| 更换 | 严格三步：加新钥匙 → 用新私钥**真实登录一次** → 才删旧；验证不过保留旧钥匙 |
| 删除 | 多选删除；不允许删空，不允许删掉本次连接正在用的钥匙（需二次确认） |
| 仅密钥登录 | 检测登录方式并改 `sshd_config`（含 `sshd_config.d` drop-in）；开启前要求当前确为密钥登录且该钥匙在文件里 |
| 认证方式 | 每台主机可选密码 / 密钥登录，表单只显示对应字段；选择存本机 `auth-method.json`，不参与同步 |

### 终端与文件

- **多会话终端标签**：连接即建标签，标签栏并入顶栏；切走的标签继续收输出，不会丢回显。
- **终端体验**：划选文本（含回滚区）、右键「有选区复制 / 无选区粘贴」、`Ctrl+Shift+C/V`、
  括号化粘贴（防批量粘贴误执行）、`Ctrl+A`~`Ctrl+Z`、`F1`~`F12`、方向键应用模式适配 vim/nano。
- **状态监控**：终端视图底部信息条显示 `user@host`、CPU / 内存 / 磁盘 / 网速和 RTT
  （`exec("true")` 往返测量），每 2 秒低频刷新；监控页有可排序的高占用进程表，PID 可右键复制。
- **SFTP 文件管理**：面包屑路径导航（点层级跳转 / `✏` 手动输入）、双击进目录或下载文件、
  右键菜单（进入 / 下载 / 重命名 / chmod / 复制绝对路径 / 删除）；路径支持回车跳转，上传目录会记住。
- **纯终端模式**：只建 SSH 会话，不读家目录、不读 `authorized_keys`；切回密钥模式才按需补读。
- **连接代理**：SOCKS5 / HTTP CONNECT，只做 TCP 隧道，握手后把裸 TCP 交给 russh；
  **主机指纹仍按真实目标校验**，不会把信任交给代理。

### 界面与同步

- **主题**：曜石（深色）/ 亚麻（浅色）两套，顶栏一键切换；桌面主题、视图、窗口状态落盘保持。
- **全局快捷键**：`Alt+1`~`Alt+4` 切视图，`Ctrl+Tab` / `Ctrl+Shift+Tab` 切标签。
- **云同步**：OneDrive 应用专属文件夹同步主机列表、备注、主机指纹；可选把主机实际在用的私钥
  加密随包带走（必须口令）。三阶段进度与结果卡让「同步到底做了什么」看得见。
- **手机端**：Flutter 三 Tab（服务器密钥 / 纯终端 / 密钥包·同步），主机卡片即时筛选与编辑，
  终端底部虚拟辅助键盘条（ESC / TAB / Ctrl-C 等），适配触屏的划选复制。

## 快速开始

### 桌面端

```bash
cd D:/my-own-program/Netwarden

# 开发态：debug 构建保留控制台，方便看日志
cargo run -p kw-desktop

# 发布构建 → target/release/netwarden.exe
cargo build -p kw-desktop --release

# 打包安装包 → target/release/bundle/nsis/Netwarden_<version>_x64-setup.exe
makensis -INPUTCHARSET UTF8 scripts\installer.nsi
```

安装包装到 `%LOCALAPPDATA%\Programs\Netwarden`，安装前会结束正在运行的旧进程并清理旧版
SSH Keywarden 的快捷方式和注册表项。未装 NSIS 时把 `makensis` 加入 PATH 或用完整路径调用。

首次启动自动做两件事：读 `~/.ssh/config`，主机列表为空时导入一次 Host；从 `IdentityFile`
往上找「密钥文件最多」的那层目录作为本地密钥库默认扫描目录。

### 浏览器模式（调试用）

```bash
cargo run -p kw-server
cargo run -p kw-server -- --no-open   # 不自动打开登录文件
node scripts/server-smoke.mjs         # Windows + Edge 冒烟，KW_TEST_BROWSER 可指定浏览器
```

浏览器入口只监听 `127.0.0.1`，用随机令牌 + 临时登录文件换取会话 Cookie，不打印令牌、
访问首页不下发 Cookie。该文件含登录凭据，请勿分享；正常退出会删除，强制终止后要自行清理。
支持 `--port` / `-p`（优先于 `PORT`）、`KW_PUBLIC_DIR` 指定前端资源目录；单独分发需携带 `public/`。

### 手机端

```bash
cargo build -p kw-ffi --release        # cdylib / staticlib，再交叉编译 Android .so / iOS .a
cd mobile && flutter analyze && flutter test
```

Android 构建见 `mobile/README.md`：先 `cargo ndk` 编三个 ABI 的 `libkw_ffi.so`，再
`flutter build apk --release`。成品归档到 `dist/android/`（universal + arm64-v8a +
armeabi-v7a + x86_64）。

## 架构

```
Netwarden/
├── crates/
│   ├── kw-core/       Secret：敏感串封装（zeroize，不实现 Serialize，Debug 只出 ***）
│   ├── kw-keys/       纯文本规则层：authorized_keys 解析/渲染、keygen、本地扫描、
│   │                  备份差异、sshd 判定、POSIX 路径、私钥加载与加密判定
│   ├── kw-store/      config.json / key-notes.json 持久化，~/.ssh/config 导入
│   ├── kw-ssh/        russh 客户端：连接/认证/exec/原子写/PTY/验登、known_hosts TOFU、
│   │                  sshd 改写，以及 proxy（SOCKS5/HTTP）、sftp、terminal、metrics
│   ├── kw-server/     共用业务层 + 同步：连接、密钥操作、SFTP、会话、路由、监控、
│   │                  ms_sync / sync（sync_now_with 带阶段回调）；axum 仅用于独立浏览器模式
│   ├── kw-desktop/    eframe + egui 原生桌面 GUI：app.rs（主 UI）、vt.rs（ANSI/VT 仿真、
│   │                  跨回滚区选区提取）、icons.rs（矢量图标）、theme.rs、desktop.rs
│   ├── kw-ffi/        桌面与手机门面：MobileEngine + C ABI，复用 kw-server 业务实现
│   └── kw-sync/       同步 CLI：login / sync / status / logout / --force-upload
├── assets/public/     浏览器模式前端（原生 JS + xterm）
├── mobile/            Flutter 手机端（直连 kw-ffi，不开 HTTP）
└── scripts/
    ├── installer.nsi      手写 NSIS 打包脚本（eframe 版，不依赖 Tauri bundler）
    ├── desktop-smoke.mjs  旧 Tauri/WebView2 遗留脚本，现行 eframe 版不适用
    └── server-smoke.mjs   浏览器模式登录与退出冒烟
```

关键约束：

- `kw-keys` 不碰网络和 UI，各端共用；桌面与手机都通过 `kw-ffi` 在进程内调用 `kw-server`
  的会话 / 密钥实现，不经过本地 HTTP；
- `ssh-key` 0.6 与 russh 内部的 0.7 类型不互通，私钥统一在 `kw-keys` 里解成未加密
  OpenSSH 文本再交给 russh（`private_key_openssh`）；
- `authorized_keys` 改写只依赖远端 `base64/mv/cp/chmod/mkdir/printf/uname` 和 sh 内建，
  **不走 SFTP**；文件管理页才开 SFTP 子系统通道；
- 同步合并的关键不变量：`identityFile` 是设备本地设置不随包覆盖，删除打墓碑，
  `known_hosts` 指纹冲突默认拒绝覆盖。

## 手机端 FFI

`kw-ffi` 把核心直接编进 App，**不开 HTTP、不依赖桌面壳**；会话与密钥操作复用 `kw-server`
实现（`connect::open` / `keys_ops::*`），安全闸门与桌面是同一条代码路径。

```text
kw_init(app_dir)                     // 一次；data/ 放配置，keys/ 放随身密钥包
kw_call("bootstrap", "{}")           // 主机 + 备注 + 本地密钥扫描
kw_call("connect", {"hostId":"…","passphrase":"…","withKeys":true})
kw_call("addKey" | "replaceKey" | "deleteKeys" | "restoreBackup", {"sid":"…", …})
kw_call("backups" | "backupDiff" | "sshd" | "setKeyOnly", {…})
kw_call("sftpHome" | "sftpList" | "sftpStat" | "sftpMkdir" | "sftpRename"
        | "sftpRemove" | "sftpChmod" | "sftpDownload" | "sftpUpload", {…})
kw_call("msStatus" | "msSaveConfig" | "msStartLogin" | "msCompleteLogin"
        | "msLogout" | "msSync", {…})
kw_call("termOpen" | "termRead" | "termWrite" | "termResize" | "termClose", {…})
kw_free_string(ptr)                  // 释放每次返回的字符串
```

返回统一为 `{"ok":true,"data":…}` 或 `{"ok":false,"error":…,"code":…,"details":…}`；
主机指纹错误带 `HOSTKEY_UNKNOWN` / `HOSTKEY_CHANGED`，死连接返回 `SESSION_LOST`。
手机生成的私钥落在 `app_dir/keys`，0600（Unix）。Dart 侧 VT 是常用子集（SGR / CUP /
ED / EL / 换行与延迟折行 / 备用屏 / 滚动区），不是完整 xterm；桌面另有独立的 Rust VT
仿真，两者不共享代码。

## 微软账号同步

设计取向：**每台设备一把自己的钥匙**。服务器上的 `authorized_keys` 本身就是事实源，
默认只同步本机数据——主机列表、钥匙归属备注、已信任的主机指纹；需要换设备免重造钥匙时，
可显式开启「私钥随包同步」（必须口令，只带主机实际在用的私钥，落地 `data/keys`，0600）。
撤销一台设备 = 从服务器删掉那把公钥，不涉及私钥搬运。

同步包是 OneDrive 应用专属文件夹（`approot/ssh-keywarden.kwsync`）里的单个加密 JSON。
包体用 Argon2id 派生口令 + AES-256-GCM 加密，口令不出设备，微软也解不开；忘了口令
只能删掉云端包重新开始。合并规则：

- 主机按 `id`（缺失则 `host:port:user`）合并，**`updated_at` 新者胜**，删除打墓碑；
- 备注按 `updatedAt` 合并，空备注 = 墓碑；`known_hosts` 指纹相同只补缺，
  **不一致默认拒绝覆盖**——本次保留本机、其余照常合并且不上传，直到显式信任
  （桌面 / 手机弹窗，CLI `--trust-changed host:port`）；
- 指纹冲突会逐条列出 `host:port` 并说明为什么没上传；同步结果卡显示拉取 / 上传、
  新增 / 更新 / 删除 / 备注 / 私钥计数，失败也留红卡。
- 上传被截断或换了口令导致云端包解不开时，CLI 的 `--force-upload` 可用本机覆盖云端
  （二次确认）。

### 获取 Azure 客户端 ID（一次性）

仓库不内置任何第三方应用 ID，用你自己的应用注册：

1. <https://portal.azure.com> → **Microsoft Entra ID** → **应用注册** → **新注册**，名称随意；
2. 受支持的账户类型选「仅个人 Microsoft 账户」（要同时支持工作账户就选带组织的项）；
3. 「身份验证」→ 高级设置里打开 **允许公共客户端流**（设备码登录不需要重定向 URI）；
4. 「API 权限」加 Microsoft Graph **委托**权限 `Files.ReadWrite.AppFolder`、`User.Read`、
   `offline_access`，并授予同意；
5. 在应用的「概览」页复制 **应用程序（客户端）ID**，填进桌面顶栏「同步」弹窗、
   手机同步页配置弹窗，或 CLI 的 `--client-id` / `KW_MS_CLIENT_ID`。

不需要客户端密钥，也不需要租户 ID（代码走 `/consumers` 端点）。

### 三端用法

桌面：顶栏「同步」→ 配置客户端 ID → 登录（设备码，浏览器输一次 8 位码）→ 立即同步。
口令可记住（存本机 `ms-config.json`）；退出登录只清本机 token，云端包保留。

CLI：

```bash
cargo build -p kw-sync --release
export KW_MS_CLIENT_ID=<你的客户端 ID>

./target/release/kw-sync login                       # 屏幕给 8 位码，浏览器输一次
./target/release/kw-sync status --json
KW_SYNC_PASSPHRASE=… ./target/release/kw-sync sync --remember-key
./target/release/kw-sync sync --trust-changed host:22 --json
./target/release/kw-sync sync --force-upload         # 云端包坏了，用本机覆盖
./target/release/kw-sync logout                      # 只删本机 token
```

口令来源顺序：`KW_SYNC_PASSPHRASE` → 本机记住的口令 → 交互询问。

手机：「密钥包·同步」页配置客户端 ID（可顺手记住口令）→ 设备码登录 → 立即同步；
指纹冲突弹窗二选一：「保留本机」或「全部覆盖后重传」。

## 安全边界

这是能改服务器登录凭据的工具，边界卡得比较死：

- 桌面端进程内调用引擎，**不监听任何端口**；浏览器模式只绑 `127.0.0.1`，校验 `Host` 头
  （挡 DNS rebinding），每次启动随机令牌，入口 `KW_NO_AUTO_COOKIE=1`，访问首页不下发 Cookie；
- 首次连接确认主机指纹，后续变化拦下要求确认（TOFU，存 `known_hosts.json`）；
- 密码 / passphrase 是 `kw_core::Secret`：不实现 `Serialize`、`Debug` 只出 `***`、Drop 清零、
  认证后即释放。这不覆盖 HTTP 原始请求体、第三方库副本和 C 调用方缓冲区；
- 写盘前自动备份，写入原子化（同目录临时文件 → `mv` → `chmod 600` → 回读比对）；
- 备份名只认同目录 + 固定前缀 + 14 位时间戳，接口不会被当成任意远端文件读取器；
- 删空、删当前连接钥匙、新钥匙验证不过，全部拦下并说明原因；
- 代理只做 TCP 隧道，主机指纹按目标服务器校验，不因经过代理而放宽；
- 对外网络请求只有微软同步：设备码与 Graph 都走 HTTPS，用内置 `webpki-roots` 校验，
  token 存 `ms-auth.json`（0600 / 用户目录 ACL），不打印、不进仓库。

## 数据目录

| 项 | 位置 |
|---|---|
| 桌面数据目录 | `NW_DATA_DIR` → `KW_DATA_DIR` → Windows `%APPDATA%\netwarden\data` / Unix `$HOME/.netwarden` |
| 浏览器数据目录 | `KW_DATA_DIR` 优先，否则当前工作目录的 `data/` |
| 主机与设置 | `config.json` |
| 本地备注 | `key-notes.json` |
| 主机指纹 | `known_hosts.json` |
| 微软登录令牌 | `ms-auth.json`（0600 / 用户目录 ACL） |
| 微软同步配置 | `ms-config.json`（客户端 ID、可选记住的口令） |
| 认证方式 / 登录密码 | `auth-method.json` / `login-auth.json`（独立文件，不参与同步） |
| 桌面状态 | `theme.json` / `ui.json` / `window-state.json`（原子写） |

从 SSH Keywarden 升级时，若新目录还没有 `config.json`，会自动把旧目录
（`%APPDATA%\ssh-keywarden\data`）的配置、私钥库、备注等完整迁移过来。

## 兼容性

- `authorized_keys` 改写只依赖远端 `base64/mv/cp/chmod/mkdir/printf/uname` 和 sh 内建，
  **不需要 SFTP 子系统**；文件管理页走 russh-sftp（需要远端开启 SFTP）；
- 认证支持私钥（含 passphrase）与密码（含 keyboard-interactive）；
- 只出 Windows x64 桌面安装包，手机出 Android APK；iOS 需自行用 Xcode 链构建。

## 测试

```bash
cargo test --workspace                 # 规则 / 存储 / 路由 / 真实 SSH 环回 / 代理 / 桌面状态 / FFI
cargo build -p kw-server -p kw-desktop
cd mobile && flutter analyze && flutter test   # 39 过 1 跳过；需 KW_FFI_LIB 指向 kw_ffi 动态库
```

- `kw-keys/tests/parity.rs`（33 项）是与旧 Node 版行为一致的移植验收标准；
- `kw-server/tests/e2e.rs` 用真实 russh 环回服务端验证认证与安全操作顺序，
  远端命令 / 文件是内存模型，**不代替真实 Linux sshd 的改写与 reload 验收**；
- `kw-server/tests/proxy_connect.rs`、`kw-ssh/tests/proxy.rs` 覆盖 SOCKS5 / HTTP 代理；
- `kw-ffi` 覆盖密钥落包与扫描、加密同步包往返、错误口令拒绝、微软同步配置与令牌落盘、
  终端缓冲、C ABI 初始化与分发；`kw-sync` 覆盖参数解析与 JSON 输出；
- `mobile/test/ffi_test.dart` 是真 FFI（非 mock）；`terminal_input_test.dart` /
  `terminal_painter_test.dart` 覆盖终端手势与绘制状态；
- `scripts/desktop-smoke.mjs` 是旧 Tauri/WebView2 遗留脚本，现行 eframe 版没有 CDP 通道，
  不能再用；桌面 UI 回归以 `cargo test` + 手点为主。

### 提交钩子

`.githooks/pre-commit` 在 staged 含 `mobile/` 文件时自动跑 `flutter test`，不通过就阻止提交。
起因是 `kMobileVersion` 漏补零让版本单测红了三天。新 clone 需启用一次：

```bash
git config core.hooksPath .githooks
```

改 Rust 不触发，改手机端多花约 10 秒。确实要跳过用 `git commit --no-verify`。

## 版本号规则

- 桌面日期制：`v2026.11.15.1`（当天第 N 次），Cargo 里存成 `2026.11.15-1`；
- 单一来源是根 `Cargo.toml` 的 `[workspace.package].version`；
- 同步四处：`crates/kw-desktop/tauri.conf.json`、`scripts/installer.nsi`（含 `VIProductVersion`）、
  `CHANGELOG.md` 的 `## v<version>` 标题，漏改单测 `version_matches_tauri_conf_and_changelog` 会红；
- 手机独立编号：`pubspec.yaml` 的 `versionName` 是日期，`versionCode` 为 `YYYYMMDDNN` 且
  必须单调递增（否则某些 ROM 会把新包当同版本拒绝安装），`mobile/lib/src/version.dart` 跟着走。

## 已知限制

- 桌面只出 Windows x64 未签名安装包，首次运行可能弹 SmartScreen，无自动更新。
- eframe 版桌面 UI 没有自动化冒烟，多标签 / 信息条 / SFTP 菜单都要手点验收。
- SSH 端到端测试是内存远端模型；真实 Linux sshd 的配置改写与重载尚未实机验收。
- 微软同步需要你自己的 Azure 应用注册；设备码登录与 Graph 上传下载尚未用真实账号实网验收。
- TLS 只信内置 `webpki-roots`，企业私有根 CA 环境连不上；Windows 的 `ms-auth.json`
  只能靠用户目录 ACL，没有 Unix 的 0600。
- 两端 VT 都是常用子集，全屏 TUI 的部分特性（鼠标上报、OSC 52 等）显示不全。
- 手机 APK 用 Flutter 模板的 debug 签名，可侧载、不能上架；iOS 未打包（缺 Xcode）。
- 同步墓碑无自动清理；备份不自动清理，同一秒两次写盘会覆盖同一个 `.bak`。
- 不走跳板机 / ProxyJump；密钥库位于 OneDrive 等按需同步目录时，首次扫描会触发占位符下载。

## 许可

MIT，见 [LICENSE](LICENSE)。
