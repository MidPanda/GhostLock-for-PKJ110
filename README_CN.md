# GhostLock — OPPO Find X8 Ultra (PKJ110)

[English](README.md) | 中文

CVE-2026-43499 内核提权 PoC。

| | |
|---|---|
| 机型 | OPPO Find X8 Ultra (PKJ110) |
| SoC | Snapdragon 8 Elite (SM8750) |
| 内核 | `6.6.89-android15-8-gf4dc45704e54-abogki446052083-4k` |
| 固件 | `PKJ110_16.0.3.500(CN01)` |

仅在上述完全一致的内核与固件上验证通过。偏移量和 secureguard / Swordfish 中和逻辑都硬绑定在这个构建上——换任何东西直接崩溃。如果想移植到其他设备，`src/targets/` 基本要从头重写。

## 攻击链（7 步）

```
1/7 KASLR 泄漏      pselect + boot_id（nfnetlink logger 指针）
2/7 内核页喷射      skb 喷射，伪造 waiter/task/fops 页
3/7 FOPS 劫持       PI-walk 栈左写：*ashmem_misc.fops = fake_fops
4/7 CFI 验证        通过 fake fops 打开 ashmem；恢复 misc.fops；
                    修复 boot_id / loggers[1] 渲染槽
 ├ 5/7 pipe 物理读写 splice/page_cache 读写 physmap/slab
 ├ 6/7 secureguard  清零 oplus_secure_guard_new kprobe handlers
 └ 7/7 UMH root     伪造 work_struct → system_unbound_wq；内核 fork
                     出 root 脚本（不触发 setuid/setenforce 调用）
                     回退路径：cred patch
                     之后：Swordfish 看守器清除缓解属性
```

UMH 失败会回退到 cred patching，但在此设备上 UMH 一直稳定，回退路径基本没测过。

## 构建

NDK r27d, clang, aarch64-linux-android35：

```bash
_rebuild.bat          # Windows
# 或者看 _build.py 里的 clang 调用
```

产物：`build/oppo-findx8ultra/bin/preload.so`

## 运行

```bash
adb push build/oppo-findx8ultra/bin/preload.so /data/local/tmp/gl-aso.so
# 建议重启后等 uptime >= 3 分钟，成功概率高
cd /data/local/tmp
GHOSTLOCK_MAGICA=1 DEBUG=1 LD_PRELOAD=./gl-aso.so /system/bin/true
```

不带 `DEBUG=1` 时只打印每步状态标记和最终结果（`ROOT 成功` / `ROOT 失败`），带了会输出完整诊断日志。

调试用的环境变量（仅泄漏实验，不拿 root）：`GHOSTLOCK_SLIDE_ONLY`、`GHOSTLOCK_BOOT_ID_LEAK_ONLY`、`GHOSTLOCK_FOPS_PI_ONLY`、`GHOSTLOCK_KERNELSNITCH_ONLY`、`GHOSTLOCK_FOPS_DRYRUN`、`GHOSTLOCK_FORCE_KASLR_BASE`。

## 目录结构

```
src/main.c            入口，步骤链，结果判定
src/slide.c           KASLR 泄漏（pselect / boot_id）
src/fops.c            FOPS 劫持，CFI 阶段，子进程 root 安装
src/pipe.c            基于 pipe 的物理内存读写
src/secureguard.c     oplus_secure_guard_new 中和
src/umh_root.c        UMH root 注入 + Swordfish 看守器
src/root.c            回退 cred patch + magica 阶段
src/magica.c          KernelSU 加载 / 属性设置 / 软重启
src/preload.c         LD_PRELOAD 构造函数
src/targets/          设备专属偏移（PKJ110）
src/kernelsnitch/     泄漏原语（来自上游）
build/                预构建产物
```

## 鸣谢

- [JoinChang/ghostlock-oneplus](https://github.com/joinchang/ghostlock-oneplus) —— 本项目基于的 GhostLock 原版利用。FOPS 劫持、pipe 物理读写、UMH root 路径和 kernelsnitch 工具均来自这个仓库。
- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) —— GhostLock 原始研究（IonStack 系列文章）。

## 说明

本项目大部分工作由 AI 辅助完成。

仅供授权安全研究使用，仅限自有设备。滥用造成的后果由使用者自行承担。
