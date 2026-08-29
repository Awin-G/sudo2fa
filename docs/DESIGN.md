# sudo2fa 设计文档

## 1. 概述

sudo2fa 是一个零依赖（纯 Rust 标准库）的 Linux TOTP 临时授权工具。
管理员用户各自持有独立 TOTP 密钥，验证通过后可以：

1. 直接执行一条指令（配合 setuid 位实现提权）
2. 换取一个限时 HMAC token（默认 120s，20–1800s），token 可代替验证码复用
3. 启动登录 shell（`-i`）
4. root 运行 `setup` 初始化/重置 TOTP，可选生成二维码（`-q/--qrcode`）

密钥文件：`/etc/shadow2fa`，格式 `UID:BASE32_SECRET`，每行一条，
root:root 所有、权限必须为 `0600`，否则拒绝执行任何操作。

## 2. 模块结构

```
src/
  base32.rs   RFC 4648 Base32 编解码（密钥存储格式）
  crypto.rs   SHA-1 与 HMAC-SHA1（纯手写实现）
  totp.rs     RFC 6238 TOTP：6 位十进制、30s 步长
  token.rs    HMAC token 签发/校验
  qr.rs       内置 QR Code 编码器（Version 5-L，37x37）→ 终端半块渲染
  main.rs     CLI、密钥文件管理、权限检查、命令执行
scripts/
  verify_qr.py      Python 辅助验证：cv2 解码 SVG 二维码 + pyotp 生成 TOTP
  docker_verify.sh  容器内全流程验证脚本
```

无任何外部 crate；与内核交互仅通过 `/proc/self/stat`、`/proc/self/status`
和外部命令（`id`、`su`）。

## 3. 密码学设计

- **TOTP**：HMAC-SHA1(secret, counter_be_8bytes)，动态截断后 mod 10^6。
  验证窗口：当前、前 2 个、后 1 个时间片（now, now-30, now-60, now+30）。
- **密钥生成**：`totp::new_secret()` 从 /dev/urandom 读取 20 字节，
  读取失败则 setup 直接报错（无弱熵回退）。
- **Token**（36 字节 = 72 hex 字符）：
  ```
  [0..8]   expiry   u64 BE（签发时间 + 有效秒数）
  [8..16]  parent   u64 BE（父进程 pid；0 表示不绑定）
  [16..36] mac      HMAC-SHA1(secret, expiry||parent)[..20]
  ```
  校验：重算 MAC 比对 → 检查过期 → 检查父进程绑定。

## 4. 父进程绑定语义

- 签发：记录**签发进程的父进程 pid**（通常是用户 shell），
  `-c/--cross-process` 时写 0（不绑定）。
- 校验：读取校验进程自身的 ppid（`/proc/self/stat` 第 4 字段），
  与 token 内 parent 比对；parent==0 时跳过。
- 效果：同一 shell 会话内可复用；跨 shell/脚本（父进程不同）被拒。
- 注意：`sh -c "单命令"` 会被 shell exec 优化（sh 进程被被测程序替换），
  此时校验进程继承 sh 的父进程，绑定判定为"同会话"属预期行为。
  需要确定性异父场景时用会真实 fork 的包装器（如 `timeout`）。

## 5. QR 编码器（qr.rs）

固定 Version 5-L（37×37，1 个数据块：108 数据码字 + 26 纠错码字，
容量 106 字节，足以容纳标准 otpauth URI）。

- 位流：4 位 byte-mode(0100) + 8 位长度 + 数据（**跨字节紧排**）+
  终止符(≤4 位 0) + 字节对齐 + 0xEC/0x11 交替填充
- RS：GF(2^8) 0x11d，生成多项式根 α^0..α^25，26 纠错码字
- 功能图形：3 个定位图形+分隔带（8×8 预留）、时序图形、
  对齐图形仅 (30,30)（v5 其余中心与定位图形重叠，按标准省略）、
  暗模块 (29,8)
- 格式信息：EC=L(01)+mask0，BCH(15,5) 多项式 0x537，异或 0x5412，
  两份副本按 ISO 位置放置（第一副本 bits0-5 沿第 8 列向下、
  bits9-14 沿第 8 行向左）
- 掩码：固定 mask 0（(row+col)%2==0 取反），与格式信息一致
- 输出：终端半块字符渲染（两模块/字符，ANSI 黑 fg 白 bg 固定极性，
  4 模块留白边；磁盘不写入任何含密钥文件）

## 6. 权限模型

- 二进制安装为 setuid root（4755）。
- **真实 UID** 通过 `/proc/self/status` 的 `Uid:` 第一字段获取
  （`id -u` 在 setuid 下返回有效 uid 0，不可用）。
- 密钥查找：优先 `SUDO_USER`（sudo 场景），否则真实 UID。
- `setup` 要求真实 UID==0；写入记录按 `SUDO_USER`（或 0）定位行，
  只替换该 UID 的记录，保留其他管理员的密钥。
- 密钥文件校验：mode==0600 且 owner==0，否则拒绝（不修复）；
  setup 时修复为 0600。
- 非 setuid 运行时，非 root 用户无法读取 0600 的密钥文件，
  天然拒绝。

## 7. CLI

```
sudo2fa <code|token> [--] [选项] 指令...
sudo2fa <code|token> -t|--token [秒] [-c|--cross-process]
sudo2fa <code|token> -i
sudo2fa <code|token> [-u|--user <name>] 指令
sudo2fa setup [-q|--qrcode]
```

`--` 之后的所有参数视为指令的一部分（避免与选项混淆）。
`-u` 通过 `su -s /bin/sh -c "<cmd>" <user>` 切换用户（需 root）。
注意：`su` 按**真实 UID** 认证，setuid 二进制下真实 UID 是调用者（非 root），
因此 `-u` 分支在 exec 前用 `CommandExt::uid(0)`（setuid syscall）把子进程的
真实/有效/保存 UID 全部提升为 0，`su` 见到真实 root 即免密切换。

## 8. 验证策略（不得点阵断言）

二维码正确性必须通过**真实解码器**验证：`scripts/verify_qr.py` 将
二进制 stderr/stdout 中的半块字符 QR（ANSI 转义先剥离）还原为模块矩阵，
重渲染为位图（多尺度 6–20 px/模块 × 高斯模糊 0/3/5 模拟镜头），
用 OpenCV QRCodeDetector 解码，要求解码结果 == 预期 otpauth URI。
TOTP 用 pyotp 独立生成，与二进制交叉验证。

## 9. 已知限制

- SHA-1 仅用于 TOTP 兼容（RFC 6238 要求），不作通用哈希
- token 为 URL 安全 hex，但泄露即等于验证码（限时长内）
- `-u` 依赖 `su`，PAM 配置严格的系统上依赖 `-u` 分支对子进程的
  `setuid(0)` 提权（见 §7），已实测通过；个别 PAM 配置仍可能行为不同
- QR 仅支持 Version 5-L，URI 超 106 字节会拒绝；输出只到终端，不落盘
