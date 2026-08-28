# 开发进度

## 已完成

### 代码（全部通过 cargo test，5 项单测）
| 模块 | 状态 | 说明 |
|---|---|---|
| base32.rs | ✅ | RFC 4648 编解码，含填充容忍 |
| crypto.rs | ✅ | SHA-1（RFC 向量验证）、HMAC-SHA1 |
| totp.rs | ✅ | RFC 6238 测试向量（59s→287082，1111111109→81804） |
| token.rs | ✅ | 签发/校验往返、错误密钥拒绝、异父拒绝（单元级） |
| qr.rs | ✅ | v5-L 编码器，经 cv2 真解码验证 |
| main.rs | ✅ | CLI 全模式、密钥文件权限模型、setuid 真实 UID |

### Docker 全流程验证（scripts/docker_verify.sh，archlinux 容器，拷贝宿主二进制）
当前 **17 PASS / 1 FAIL**（stage 2 聚合）：

通过的：
- setup 生成密钥 + SVG；密钥文件 0600 root-owned；root 记录正确
- 错误权限拒绝；QR 经 cv2 解码 == otpauth URI；pyotp 生码可用
- token 签发；**同会话 token 可用**；跨进程 token(-c) 子 shell 可用
- 过期 token 拒绝；篡改 token 拒绝
- 验证码执行指令为 root；错误/垃圾验证码拒绝；-i 登录 shell
- `-u tester` 以 uid 1000 执行；whoami == tester
- 第二管理员(nobody) setup：新增记录且保留 root 记录
- **setuid 提权**：nobody 用自己的码 → uid 0；错误码拒绝
- 无 setuid 副本：非 root 读不了密钥文件（天然拒绝）

### Git 历史（master）
```
bdeca1e Add dependency-free TOTP primitives
c7a7eeb Add built-in QR code generator
243a8fb Add sudo2fa authorization CLI
0f46b2e Use invoking sudo account for TOTP lookup
1756367 Fix QR format BCH, placement and reserved modules
（待提交：-- 支持、token 父进程绑定、验证脚本、文档）
```

### 调试过程中修复的重大缺陷（QR）
1. 格式信息 BCH 缺少 `<<10` 移位 → 值错误
2. 第一份格式信息副本**行列转置**（对照 python-qrcode 逐单元定位）
3. 副本二覆盖暗模块、位序偏移
4. reserved 把 v5 不存在的对齐图形 (6,30)/(30,6) 也预留（浪费 ~40 模块）
5. **模式指示符写成整字节 0x40 而非 4 位紧排** → 整个数据流错位 4 位
   （cv2 表现为 `idx < data.size()` 断言崩溃；长度被读成 4）
6. 缺少终止符；填充奇偶与 ISO 不一致（奇长度消息时 0x11 起始）

修复方法：与 venv `qrcode` 包（mask_pattern=0, optimize=0）逐单元矩阵
比对 + 位流读回对比 + cv2 真解码，最终多尺度解码全部匹配。

## 待办

- [ ] **卡住：token 异父拒绝在某上下文失效**（见 HANDOVER.md）
- [ ] 密钥生成改用 /dev/urandom
- [ ] stage 2 通过后全套验证 24/24
- [ ] README 更新（-- 用法、token 绑定语义）
