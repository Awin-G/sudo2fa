# 交接：token 异父拒绝"失效"问题 —— 已解决（事后分析）

## 结论一句话

**产品代码没有 bug。stage 2 的失败是测试脚本自身缺陷：
`sh -c "sudo2fa $T -- id -u; :"` 中尾随的 `:` 总会把 `sh -c` 的整体退出码
覆盖成 0，于是 `if` 误判为"放行"，而实际上 sudo2fa 每次都正确输出了
`token parent process mismatch` 并退出 1。**

## 根因

`sh -c "a; b"` 的退出状态是**最后一条命令** b 的状态。stage 2 为了阻止
`sh -c` 对单命令的 exec 优化，在命令后追加了 `; :`，但这同时让退出码被
`:`（恒 0）吞掉：

| 构造 | sudo2fa 的父进程 | sudo2fa 实际行为 | `sh -c` 退出码 | `if` 判定 |
|---|---|---|---|---|
| `sh -c "sudo2fa $T -- id -u"` | 主 shell（exec 优化，sh 被替换） | 父进程相同 → 放行 | 0 | "放行"（预期行为，绑定语义如此） |
| `sh -c "sudo2fa $T -- id -u; :"` | sh 的 fork 子进程（异父 ✓） | **正确拒绝**，stderr 报 mismatch，退出 1 | **0（被 `:` 覆盖）** | 误判"放行" ❌ |

前版文档中"同一构造在独立诊断里被正确拒绝"的观察也吻合：诊断脚本用的是
`sh -c '...; echo A-exit=$?'`，靠**打印出来的** `$?`=1 与 stderr 信息判断
拒绝，而不是 `if` 的整体退出码。

以上均在容器内实测验证（bash 5.3，archlinux:latest）。

## 修复

`docker_verify.sh` stage 2 改用 `timeout` 包装——它 fork 子进程（父进程确定
不是签发 shell）且忠实传播退出码，无副作用：

```bash
if timeout 5 sudo2fa "$T" -- id -u >/dev/null 2>&1; then no ...; else ok ...; fi
```

修复后全套验证 **24 PASS / 0 FAIL**。

## 教训（给后续测试编写者）

1. 用退出码判断"拒绝"时，确保被拒绝进程的退出码能**传播到断言处**；
   任何尾随的 `; :`、`; true` 都会掩盖它。
2. `sh -c "单命令"` 会被 exec 优化，被测进程继承 shell 的父进程——
   测"异父拒绝"时必须用确定性 fork 的包装器（`timeout` 最干净）。
3. stderr 上的错误信息先肉眼确认一次，再谈 shell 理论。

## 环境速查（保留）

- 宿主 Arch / glibc 2.44 / rust 1.93.1；容器 archlinux:latest（无网络、
  无 python）；二进制**拷贝**进容器（用户明确要求不在容器内编译）。
- venv：/home/awinx/dev/venv/bin/python（3.14，opencv 5.0.0.93 可用；
  pyzbar 因缺 libzbar 不可用；qrcode、pyotp 可用作参考实现）。
- cv2 解码我们的 SVG：scale 6–8 锐利可解，10–20 需配合高斯模糊 3–5。
- docker_verify.sh 当前 24 PASS / 0 FAIL。
