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
#include <sys/random.h> 
#include <sys/prctl.h>
#endif

#ifndef THREAD_NAME_MAX
#define THREAD_NAME_MAX 15  // 15 chars + '\0' = 16 bytes limit on many kernels 
#endif

extern int verbose_logging;
#define VLOGD(fmt, ...) do { if (verbose_logging) __android_log_print(ANDROID_LOG_DEBUG, "DexDumper", fmt, ##__VA_ARGS__); } while(0)
#define LOGW(fmt, ...) do { __android_log_print(ANDROID_LOG_WARN, "DexDumper", fmt, ##__VA_ARGS__); } while(0)

// scure random in range [0, range-1]. Use getrandom() if available, fallback to /dev/urandom, finally rand().
static uint32_t secure_rand_u32(uint32_t range) {
    if (range == 0) return 0;
    uint32_t v = 0;

#if defined(__linux__) || defined(__ANDROID__)
    // try getrandom syscall
    ssize_t r = getrandom(&v, sizeof(v), 0);
    if (r == (ssize_t)sizeof(v)) {
        return (uint32_t)(v % range);
    }
    // fallback to /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t rn = read(fd, &v, sizeof(v));
        close(fd);
        if (rn == (ssize_t)sizeof(v)) {
            return (uint32_t)(v % range);
        }
    }
#endif

    
    v = (uint32_t)rand();
    return (uint32_t)(v % range);
}

void apply_stealth_techniques(void) {
    const char* thread_name_pool[] = {
        "Binder", "JDWP", "Finalizer", "GC", "SignalC",
        "hwuiTask", "RenderThread", "BgThread", "PoolThread",
        "AsyncTask", "Thread", "OkHttp", "Retrofit"
    };
    const size_t pool_count = sizeof(thread_name_pool) / sizeof(thread_name_pool[0]);

    // choose random index
    uint32_t name_index = secure_rand_u32((uint32_t)pool_count);

    char temporary_thread_name[THREAD_NAME_MAX + 1];
    int n = snprintf(temporary_thread_name, sizeof(temporary_thread_name), "%s", thread_name_pool[name_index]);
    if (n < 0) {
        // fallback 
        snprintf(temporary_thread_name, sizeof(temporary_thread_name), "Thread");
    } else if (n > THREAD_NAME_MAX) {
        // ensure null-termination (snprintf already truncates)
        temporary_thread_name[THREAD_NAME_MAX] = '\0';
    }

    // set thread name - prefer pthread_setname_np when available
    int rc = -1;
#if defined(__ANDROID__) || defined(_GNU_SOURCE)
    // Many Android / glibc variants support pthread_setname_np(pthread_t, const char*)
    rc = pthread_setname_np(pthread_self(), temporary_thread_name);
    if (rc != 0) {
        VLOGD("pthread_setname_np returned %d (%s)", rc, strerror(rc));
    } else {
        VLOGD("Set thread name via pthread_setname_np -> %s", temporary_thread_name);
    }
#else
    errno = 0;
    if (prctl(PR_SET_NAME, (unsigned long)temporary_thread_name, 0, 0, 0) == 0) {
        VLOGD("Set thread name via prctl -> %s", temporary_thread_name);
    } else {
        LOGW("prctl(PR_SET_NAME) failed: %s", strerror(errno));
    }
#endif

    // random delay between min_ms - max_ms
    const uint32_t min_ms = 100;   // 100 ms
    const uint32_t max_ms = 2000;  // 2000 ms
    uint32_t range = (max_ms - min_ms) + 1;
    uint32_t jitter_ms = min_ms + secure_rand_u32(range);

    // convert to microseconds for usleep
    useconds_t sleep_us = (useconds_t)jitter_ms * 1000U;
    usleep(sleep_us);

    VLOGD("Stealth applied: name='%s', jitter=%ums", temporary_thread_name, jitter_ms);
}
