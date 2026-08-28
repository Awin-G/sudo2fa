# 交接：当前卡住的问题

## 问题一句话

**token 的"父进程不匹配拒绝"逻辑在 docker_verify.sh stage 2 的上下文中
意外放行了异父进程的调用，而相同结构在独立诊断脚本中正确拒绝。**
行为取决于运行上下文，疑似 bash/dash 的 fork/exec 优化差异，
但尚未定位到确切机制。

## 复现

容器内（archlinux:latest，二进制 4755，/etc/shadow2fa 已 setup）：

```bash
docker exec -i -e CODE="$CODE" s2fa-diag bash -s <<'EOF'
pass=0; fail=0
T=$(sudo2fa "$CODE" -t 25)                 # issuer: ppid = bash pid B
[ "$(sudo2fa "$T" -- id -u)" = "0" ]       # 同会话 → 通过（正确）
if sh -c "sudo2fa $T -- id -u; :" >/dev/null 2>&1
then echo "FAIL: foreign parent ALLOWED"   # ← 实际走到这里
else echo "PASS: foreign parent refused"
fi
EOF
```

而下面这个**几乎相同**的独立诊断中，同样的调用被正确拒绝：

```bash
docker exec -i -e CODE="$CODE" s2fa-diag bash -s <<'EOF'
T=$(sudo2fa "$CODE" -t 25)
export T
sh -c 'sudo2fa "$T" -- id -u; echo A-exit=$?'   # → mismatch, exit 1 ✅
sh -c "sudo2fa $T -- id -u; :; echo B-exit=\$?" # → mismatch（B-exit 是 : 的退出码）
EOF
```

## 已确认的事实

1. **签发侧正确**：token 的 parent 字段（hex 字节 16..24）实测 =
   签发 bash 的 pid（0x33=51），即 `parent_pid()` 读 /proc/self/stat
   第 4 字段无误。
2. **同会话校验正确**：`sudo2fa "$T" -- id -u` 通过（ppid==parent）。
3. **拒绝路径本身可用**：独立诊断中 `token parent process mismatch`
   正常触发（异父、过期、篡改、错误密钥都拒）。
4. `sudo2fa` 校验逻辑：`token::verify(secret, token, parent_pid())`，
   `parent_pid()` 解析 `/proc/self/stat` 的 ppid（rsplit_once(") ")
   后 nth(1)），与重算 HMAC 无关的纯比对。
5. 在失败的上下文中，`sh -c "sudo2fa $T -- id -u; :"`（命令列表）
   与 `sh -c "sudo2fa $T -- id -u"`（单命令，dash 会 exec 优化）
   **都**被放行 → 说明 sudo2fa 进程的 ppid == 签发时的 bash pid B。
6. 后台探针（`sudo2fa "$T" -- sleep 0.5 & p=$!; grep PPid /proc/$p/status`）
   两次都因进程退出太快没读到（/proc/$p/status: No such file），
   **尚未拿到失败上下文中 verifier 的真实 PPid 数值**。

## 待验证假设（按优先级）

1. **H1（最可疑）：失败上下文里 `T=$(sudo2fa ...)` 的 $() 子 shell 与
   `sh -c` 的子进程发生了 pid 复用/时序巧合** —— 概率太低，基本排除。
2. **H2：`sh -c "cmd; :"` 在 arch 的 /bin/sh（→bash）下，第一条外部
   命令被 exec 直接替换 sh 进程**（即 sh 进程变成 sudo2fa，ppid 仍是
   bash B）→ 与"独立诊断中同样写法被拒"矛盾 —— 需要解释差异。
   *注意：两次运行的区别可能在于 heredoc 中 `if` 条件上下文、
   `>/dev/null 2>&1` 重定向、或 bash -s 的 posix 模式差异。*
3. **H3：`sh -c` 单命令 exec 优化确实发生**（arch /bin/sh=bash，
   bash 对 -c 的最后一条简单命令 exec 优化）→ 单命令版放行是**预期**；
   但列表版 `; :` 放行无法用 H3 解释，且独立诊断中单命令版**被拒**
   与 H3 矛盾 → 需要重新在**同一上下文**中对照。
4. **H4：测试脚本自身缺陷** —— 例如 stage 2 中 `$T` 在某处被清空/
   覆盖，或 `[ "$(...)" = "0" ]` 的结果误读。已核对过引号与 heredoc
   quoted（'EOF'），未发现。

## 建议的下一步（给接手模型）

1. 用"慢命令"保证探针窗口：把被测命令换成
   `sudo2fa "$T" -- sleep 2`，再 `& p=$!; sleep 0.1; grep PPid /proc/$p/status`。
   在**失败的原始 stage 2 上下文**中（不是新脚本）加入该探针，
   拿到 verifier 的真实 PPid 与签发 bash pid 对比。
2. 在同一脚本里同时打印：
   - `$$`（bash-s 的 pid）
   - `T=$(sudo2fa ...)` 的 parent 字段：`${T:16:8}`（hex→十进制比对）
   - `sh -c 'echo $PPid...'` 前后壳的 pid（`grep PPid /proc/self/status`）
3. 对照实验：分别用 `dash` 显式调用（容器里装？arch 无 dash，可用
   `busybox sh`？arch 基础镜像没有 busybox；可用 `bash --posix -c`）、
   以及把 `sh -c` 换成 `setsid`、`timeout 5`、`useradd 场景的 su` 等
   确定性 fork 的包装器，观察哪些被拒。
4. 若确认是 bash 对 `sh -c "单命令"` 的 exec 优化所致（H3），
   则**修复测试脚本**而非产品代码：异父测试必须用确定性产生不同
   父进程的包装器，例如：
   ```bash
   bash -c 'sudo2fa "$T" -- id -u; :'   # 列表仍可能 exec 优化最后一条
   timeout 5 sudo2fa "$T" -- id -u      # timeout fork 子进程，父=timeout
   setsid sudo2fa "$T" -- id -u         # setsid fork，父很快变 1，有竞态
   ```
   推荐 `timeout`：父进程确定是 timeout（pid ≠ bash），且无竞态。
   同时在产品 README 中写明绑定语义 = "调用者的父进程"，shell 包装器
   的 exec 优化会让"直接 exec 替换 sh"的场景天然继承 shell 父 pid，
   这属于预期行为。
5. 若探针显示失败上下文中 verifier 的 PPid 确实 == bash pid（即 H3
   在该上下文成立），则检查 bash `if` 条件/重定向是否改变 fork 决策，
   并考虑在产品语义上是否需要更强绑定（如绑定 session id，读
   /proc/self/stat 的 sid 字段 6）。

## 环境速查

- 宿主 Arch / glibc 2.44 / rust 1.93.1；容器 archlinux:latest（无网络、
  无 python）；二进制**拷贝**进容器（用户明确要求不在容器内编译）。
- venv：/home/awinx/dev/venv/bin/python（3.14，opencv 5.0.0.93 可用；
  pyzbar 因缺 libzbar 不可用；qrcode、pyotp 可用作参考实现）。
- cv2 解码我们的 SVG：scale 6–8 锐利可解，10–20 需配合高斯模糊 3–5。
- 运行中的诊断容器：s2fa-diag（可 docker rm -f 清理）。
- docker_verify.sh 当前 17 PASS / 1 FAIL（stage 2 聚合 fail+1）。
