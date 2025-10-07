#include "stealth.h"

#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/syscall.h>
#include <sys/prctl.h>
#endif

#ifndef THREAD_NAME_MAX
#define THREAD_NAME_MAX 15
#endif

#ifndef LOGW
#define LOGW(fmt, ...) __android_log_print(ANDROID_LOG_WARN, "DexDumper", fmt, ##__VA_ARGS__)
#endif
#ifndef VLOGD
#define VLOGD(fmt, ...) do { if (verbose_logging) __android_log_print(ANDROID_LOG_DEBUG, "DexDumper", fmt, ##__VA_ARGS__); } while(0)
#endif

extern int verbose_logging;

/**
 * Secure random with cross-version fallback:
 * - syscall(__NR_getrandom) for modern kernels
 * - /dev/urandom fallback
 * - rand() fallback (least secure)
 */
static uint32_t secure_rand_u32(uint32_t range) {
    if (range == 0) return 0;
    uint32_t v = 0;

#if defined(__NR_getrandom)
    long ret = syscall(__NR_getrandom, &v, sizeof(v), 0);
    if (ret == sizeof(v)) {
        return v % range;
    }
#endif

    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t rn = read(fd, &v, sizeof(v));
        close(fd);
        if (rn == sizeof(v)) {
            return v % range;
        }
    }

    v = (uint32_t)rand();
    return v % range;
}

void apply_stealth_techniques(void) {
    static const char* thread_name_pool[] = {
        "Binder", "JDWP", "Finalizer", "GC", "SignalC",
        "hwuiTask", "RenderThread", "BgThread", "PoolThread",
        "AsyncTask", "Thread", "OkHttp", "Retrofit"
    };

    const size_t pool_count = sizeof(thread_name_pool) / sizeof(thread_name_pool[0]);
    uint32_t name_index = secure_rand_u32((uint32_t)pool_count);

    char temporary_thread_name[THREAD_NAME_MAX + 1];
    snprintf(temporary_thread_name, sizeof(temporary_thread_name), "%s", thread_name_pool[name_index]);
    temporary_thread_name[THREAD_NAME_MAX] = '\0';

#if defined(__ANDROID__) || defined(_GNU_SOURCE)
    int rc = pthread_setname_np(pthread_self(), temporary_thread_name);
    if (rc != 0) {
        VLOGD("pthread_setname_np failed: %s", strerror(rc));
    }
#else
    if (prctl(PR_SET_NAME, (unsigned long)temporary_thread_name, 0, 0, 0) != 0) {
        LOGW("prctl(PR_SET_NAME) failed: %s", strerror(errno));
    }
#endif

    uint32_t min_ms = 100;
    uint32_t max_ms = 2000;
    uint32_t jitter = min_ms + secure_rand_u32(max_ms - min_ms + 1);

    usleep(jitter * 1000U);
    VLOGD("Stealth applied: name='%s', jitter=%ums", temporary_thread_name, jitter);
}    useconds_t sleep_us = (useconds_t)jitter_ms * 1000U;
    usleep(sleep_us);

    VLOGD("Stealth applied: name='%s', jitter=%ums", temporary_thread_name, jitter_ms);
}
