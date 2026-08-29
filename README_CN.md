# sudo2fa

一个零依赖、适配 setuid 的 Linux TOTP 授权工具。
把一次性或限时的 root 权限授予某个进程——AI Agent、cron 任务、远程
Shell——而全程不暴露任何密码。

## 为什么

经典提权方式在非交互、无显示器的场景下都会失效：

- **`sudo`** 从控制终端（TTY）读取密码。在大多数 Agent 框架（OpenAI、
  Claude 等）下，Agent 的 `bash` 工具没有 TTY，`sudo` 会一直挂起直到
  工具超时。
- **`pkexec`** 需要同一显示器上的图形化 Polkit 代理。无头服务器、
  systemd 服务、SSH 会话里都无法使用。
- **把 root 密码直接交给 Agent** 等于把长期凭证暴露给一个自主、且可能
  被外部控制（prompt injection 等）的进程。

sudo2fa 反转了这个模型：**人负责认证，机器负责执行**。由你（或 Agent）
用 6 位 TOTP 验证码换取一个短期、带签名、绑定进程的 token，然后用这个
token——而不是密码——来执行提权命令。

```text
你:       sudo2fa setup --qrcode            # 扫码加入你的验证器
Agent:    sudo2fa 123456 -- apt update      # 一个验证码 = 一条命令
Agent:    TOKEN=$(sudo2fa 123456 -t 300)    # 或签发可复用的 token
Agent:    sudo2fa "$TOKEN" -- systemctl restart nginx
```

TOTP 密钥只存放在 `/etc/shadow2fa`，Agent 的任何操作都无法将其还原。

## 安装

```sh
cargo build --release
install -o root -g root -m 4755 target/release/sudo2fa /usr/local/sbin/sudo2fa
sudo /usr/local/sbin/sudo2fa setup --qrcode
```

二进制以 setuid root 安装。二维码（`--qrcode`）直接渲染在终端里；
不向磁盘写入任何含密钥的文件。

`/etc/shadow2fa` 为 root 所有、权限 `0600`，每行一条记录，格式为
`UID:BASE32_SECRET`。`setup` 只替换当前管理员（经 sudo 运行时取
`SUDO_USER`）对应的记录，保留其他管理员的密钥。

## 用法

```text
sudo2fa <code|token> command [args...]      以 root 执行
sudo2fa <code|token> --token [seconds]      签发 token（默认 120s，范围 20–1800s）
sudo2fa <code|token> --token --cross-process [seconds]
sudo2fa <code|token> --user <name> command  以其他用户执行
sudo2fa <code|token> -i                     启动登录 Shell
sudo2fa setup [-q|--qrcode]                 （重新）初始化当前管理员的密钥
```

`--` 之后的所有参数都归命令所有，因此命令可以放心使用本会被 sudo2fa
解析的选项：

```text
sudo2fa <code> -- ls -l /root
```

一个新鲜的 TOTP 验证码在 30 秒窗口内有效一次。token 由 HMAC-SHA1 签名、
自动过期，并且——除非指定 `--cross-process`——绑定签发进程的父进程，
无法被挪到签发会话之外使用。这使得 Agent 在单个短任务里连续执行多条
提权命令时可以安全地复用 token。

## 安全模型

- 密钥只存在于 `/etc/shadow2fa`（0600、root 所有）；二进制在权限不符时
  拒绝运行。
- 真实 UID 从 `/proc` 读取（setuid 下 `id -u` 报告的是有效 UID，不可用）；
  sudo 场景下用 `SUDO_USER` 选择对应密钥。
- 外部辅助程序一律通过绝对路径调用——绝不走 `PATH`——防止 setuid
  进程被劫持。
- token 共 36 字节：8 字节过期时间、8 字节绑定的父进程 pid（0 表示不绑定）、
  20 字节对头部的 HMAC-SHA1，常量时间比对。
- TOTP 遵循 RFC 6238，窗口为当前、前两个、后一个时间片（±1）。

## 已知限制

- 整条链路基于 TOTP，单次授权受 30 秒验证码窗口限制；长时间运行的
  Agent 任务应改用 token。
- token 绑定在 Shell 的 `exec` 优化下是尽力而为（见 `docs/DESIGN.md`
  §4）；测试时请使用 `timeout`/`setsid` 这类真正 fork 的包装器。
- 二维码输出面向 Version 5-L（106 字节负载）；只渲染到终端，不写文件。

## 开发

```sh
cargo test --release
bash scripts/docker_verify.sh   # archlinux 容器内的全流程验证
```

验证套件用真实解码器（OpenCV）解码渲染出的二维码，并用 `pyotp` 独立
交叉校验 TOTP 验证码。完整设计见 `docs/DESIGN.md`。
