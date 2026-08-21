# GhostLock for PKJ110

English | [中文](README_CN.md)

CVE-2026-43499 exploit for the OPPO Find X8 Ultra.

| | |
|---|---|
| Device | OPPO Find X8 Ultra (PKJ110) |
| SoC | Snapdragon 8 Elite (SM8750) |
| Kernel | `6.6.89-android15-8-gf4dc45704e54-abogki446052083-4k` |
| Firmware | `PKJ110_16.0.3.500(CN01)` |

Only tested on the exact kernel and firmware above. The offsets and the
secureguard/Swordfish neutralization are tied to this build — on anything
else it just crashes. If you're porting to another device, expect to redo
most of `src/targets/` from scratch.

## Exploit chain

```
1/7 KASLR leak      pselect + boot_id (nfnetlink logger pointer)
2/7 kernel page     skb spray, fake waiter/task/fops page
3/7 FOPS hijack     PI-walk stack left-write: *ashmem_misc.fops = fake_fops
4/7 CFI verify      open ashmem through fake fops; restore misc.fops;
                    repair boot_id / loggers[1] render slot
 ├ 5/7 pipe phys-RW splice/page_cache read-write of physmap/slab
 ├ 6/7 secureguard  zero oplus_secure_guard_new kprobe handlers
 └ 7/7 UMH root     fake work_struct → system_unbound_wq; kernel forks
                    the root script (no setuid/setenforce syscall)
                    fallback: cred patch
                    then: Swordfish watcher clears mitigation props
```

If UMH fails it falls back to cred patching, but on this device UMH has
been reliable, so the fallback path is mostly untested.

## Build

NDK r27d, clang, aarch64-linux-android35:

```bash
_rebuild.bat          # Windows
# or: see the clang invocation inside _build.py
```

Output: `build/oppo-findx8ultra/bin/preload.so`

## Run

```bash
adb push build/oppo-findx8ultra/bin/preload.so /data/local/tmp/gl-aso.so
# after reboot: waiting for uptime >= 3 min is recommended for a high success rate
cd /data/local/tmp
GHOSTLOCK_MAGICA=1 LD_PRELOAD=./gl-aso.so timeout 115 /system/bin/true
```

Without `DEBUG=1` it only prints the per-step markers and the final
verdict (`ROOT 成功` / `ROOT 失败`). With it, the full diagnostic log.

Debug env vars (leak experiments, no root): `GHOSTLOCK_SLIDE_ONLY`,
`GHOSTLOCK_BOOT_ID_LEAK_ONLY`, `GHOSTLOCK_FOPS_PI_ONLY`,
`GHOSTLOCK_KERNELSNITCH_ONLY`, `GHOSTLOCK_FOPS_DRYRUN`,
`GHOSTLOCK_FORCE_KASLR_BASE`.

## Layout

```
src/main.c            exploit entry, step chain, verdicts
src/slide.c           KASLR leak (pselect / boot_id)
src/fops.c            FOPS hijack, CFI stage, child-root install
src/pipe.c            pipe-based physical read/write
src/secureguard.c     oplus_secure_guard_new neutralization
src/umh_root.c        UMH root injection + Swordfish watcher
src/root.c            fallback cred-patch + magica stages
src/magica.c          KernelSU load / props / soft reboot
src/preload.c         LD_PRELOAD constructor
src/targets/          device-specific offsets (PKJ110)
src/kernelsnitch/     leak primitives (from upstream)
build/                prebuilt artifacts
```

## Thanks

- [JoinChang/ghostlock-oneplus](https://github.com/joinchang/ghostlock-oneplus) —
  the GhostLock exploit this is based on. The fops hijack, pipe physrw,
  UMH root path and kernelsnitch utils all come from this tree.
- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) —
  the original GhostLock research (IonStack writeups).

## Note

Most of the work is done with the help of AI.

For authorized security research only, on devices you own. The author
takes no responsibility for misuse.
