#include "hook_libc.h"
#include "../utils/log.h"
#include "../utils/safe_bytehook.h"
#include <bytehook.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/system_properties.h>
#include <sys/syscall.h>
#include <link.h>

namespace hook_libc {

// 真实函数指针（支持 LSPosed inline hook backup 与 dlsym 回退）
static FILE* (*real_fopen_ptr)(const char*, const char*) = nullptr;
static char* (*real_fgets_ptr)(char*, int, FILE*) = nullptr;
static int (*real_open_ptr)(const char*, int, mode_t) = nullptr;
static int (*real_openat_ptr)(int, const char*, int, mode_t) = nullptr;
static int (*real_access_ptr)(const char*, int) = nullptr;
static int (*real_faccessat_ptr)(int, const char*, int, int) = nullptr;
static int (*real_stat_ptr)(const char*, struct stat*) = nullptr;
static int (*real_lstat_ptr)(const char*, struct stat*) = nullptr;
static int (*real_fstatat_ptr)(int, const char*, struct stat*, int) = nullptr;
static ssize_t (*real_readlink_ptr)(const char*, char*, size_t) = nullptr;
static ssize_t (*real_readlinkat_ptr)(int, const char*, char*, size_t) = nullptr;
static int (*real_dladdr_ptr)(const void*, Dl_info*) = nullptr;
static int (*real_dl_iterate_phdr_ptr)(int (*)(struct dl_phdr_info*, size_t, void*), void*) = nullptr;
static int (*real_system_property_get_ptr)(const char*, char*) = nullptr;
static const prop_info* (*real_system_property_find_ptr)(const char*) = nullptr;
typedef long (*syscall_func_t)(long, void*, void*, void*, void*, void*, void*);
static syscall_func_t real_syscall_ptr = nullptr;

static void ensure_real_funcs() {
    if (!real_fopen_ptr) real_fopen_ptr = (FILE* (*)(const char*, const char*))dlsym(RTLD_DEFAULT, "fopen");
    if (!real_fgets_ptr) real_fgets_ptr = (char* (*)(char*, int, FILE*))dlsym(RTLD_DEFAULT, "fgets");
    if (!real_open_ptr) real_open_ptr = (int (*)(const char*, int, mode_t))dlsym(RTLD_DEFAULT, "open");
    if (!real_openat_ptr) real_openat_ptr = (int (*)(int, const char*, int, mode_t))dlsym(RTLD_DEFAULT, "openat");
    if (!real_access_ptr) real_access_ptr = (int (*)(const char*, int))dlsym(RTLD_DEFAULT, "access");
    if (!real_faccessat_ptr) real_faccessat_ptr = (int (*)(int, const char*, int, int))dlsym(RTLD_DEFAULT, "faccessat");
    if (!real_stat_ptr) real_stat_ptr = (int (*)(const char*, struct stat*))dlsym(RTLD_DEFAULT, "stat");
    if (!real_lstat_ptr) real_lstat_ptr = (int (*)(const char*, struct stat*))dlsym(RTLD_DEFAULT, "lstat");
    if (!real_fstatat_ptr) real_fstatat_ptr = (int (*)(int, const char*, struct stat*, int))dlsym(RTLD_DEFAULT, "fstatat");
    if (!real_readlink_ptr) real_readlink_ptr = (ssize_t (*)(const char*, char*, size_t))dlsym(RTLD_DEFAULT, "readlink");
    if (!real_readlinkat_ptr) real_readlinkat_ptr = (ssize_t (*)(int, const char*, char*, size_t))dlsym(RTLD_DEFAULT, "readlinkat");
    if (!real_dladdr_ptr) real_dladdr_ptr = (int (*)(const void*, Dl_info*))dlsym(RTLD_DEFAULT, "dladdr");
    if (!real_dl_iterate_phdr_ptr) real_dl_iterate_phdr_ptr = (int (*)(int (*)(struct dl_phdr_info*, size_t, void*), void*))dlsym(RTLD_DEFAULT, "dl_iterate_phdr");
    if (!real_system_property_get_ptr) real_system_property_get_ptr = (int (*)(const char*, char*))dlsym(RTLD_DEFAULT, "__system_property_get");
    if (!real_system_property_find_ptr) real_system_property_find_ptr = (const prop_info* (*)(const char*))dlsym(RTLD_DEFAULT, "__system_property_find");
    if (!real_syscall_ptr) real_syscall_ptr = (syscall_func_t)dlsym(RTLD_DEFAULT, "syscall");
}

bool is_sensitive_path(const char* path) {
    if (!path) return false;
    const char* hidden[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/data/local/tmp/su", "/data/local/tmp/frida", "re.frida.server",
        "/system/xposed", "/data/adb/lsposed", "/data/adb/modules",
        "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap", "/data/adb/apatch",
        "/data/adb/shamiko", "libriru", "libzygisk",
        "Superuser.apk", "SuperSU.apk", "Magisk.apk",
        "/system/bin/install-recovery.sh", "/system/etc/install-recovery.sh",
        "/system/bin/debuggerd", "/system/bin/debuggerd64", "/system/bin/ddexe",
        "/sys/fs/selinux/enforce",
        "dexkit", "libdexkit", "flatbuffers", "sandhook", "yahfa",
        "epic", "pine", "taichi", "liblspd", "lsposed", "edxposed",
        "qqbypass", "libnative-bypass", "libbytehook", "xalsace",
        "zygisk_lsposed", "zygisksu", "bin.mt.plus",
        "bytehook", "native-bypass", "apatch",
        nullptr
    };
    for (int i = 0; hidden[i]; i++) {
        if (strcasestr(path, hidden[i])) return true;
    }
    return false;
}

// 创建内存虚拟文件（优先使用 memfd_create，无磁盘权限限制，确保在沙箱应用内 100% 成功）
static FILE* create_memory_file(const char* name) {
#if defined(__aarch64__)
    int fd = (int)syscall(279, name ? name : "anon_mem", 1 /* MFD_CLOEXEC */);
#elif defined(__arm__)
    int fd = (int)syscall(385, name ? name : "anon_mem", 1 /* MFD_CLOEXEC */);
#else
    int fd = (int)syscall(__NR_memfd_create, name ? name : "anon_mem", 1);
#endif
    if (fd >= 0) {
        FILE* fp = fdopen(fd, "r+");
        if (fp) return fp;
        close(fd);
    }
    // 回退到应用私有 cache 目录
    char cache_path[256];
    snprintf(cache_path, sizeof(cache_path), "/data/data/com.tencent.mobileqq/cache/.%s_%d", name ? name : "tmp", getpid());
    int cfd = open(cache_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (cfd >= 0) {
        unlink(cache_path);
        FILE* fp = fdopen(cfd, "r+");
        if (fp) return fp;
        close(cfd);
    }
    return tmpfile();
}

// 构造过滤掉 hook 特征库与 rwxp 蹦床的 maps 临时文件
FILE* build_filtered_maps() {
    ensure_real_funcs();
    if (!real_fopen_ptr || !real_fgets_ptr) return nullptr;

    FILE* real = real_fopen_ptr("/proc/self/maps", "r");
    if (!real) return nullptr;

    FILE* fake = create_memory_file("maps");
    if (!fake) {
        fclose(real);
        return nullptr;
    }

    char line[2048];
    const char* blacklist[] = {
        "lsposed", "xposed", "riru", "zygisk", "edxposed",
        "frida", "substrate", "libDalvikLoader", "libAndroidCydia",
        "magisk", "ksu", "kernelsu", "supersu", "superuser",
        "libnative-bypass", "libbytehook", "xalsace", "qq_hook",
        "dexkit", "libdexkit", "flatbuffers", "sandhook", "yahfa",
        "epic", "pine", "taichi", "top.canyie", "liblspd", "qqbypass",
        "zygisk_lsposed", "zygisksu", "/data/adb", "bin.mt.plus",
        "bytehook", "trampoline", "native-bypass", "apatch", "libxposed",
        "qauxv", "io.github.qauxv", "libqauxv", "libqauxv-core0", "cc.ioctl", "qnotified",
        nullptr
    };

    while (real_fgets_ptr(line, sizeof(line), real)) {
        bool filter = false;
        for (int i = 0; blacklist[i]; i++) {
            if (strcasestr(line, blacklist[i])) { filter = true; break; }
        }
        // 过滤非系统 Dalvik 的匿名可读写执行蹦床 (rwxp)
        if (!filter && strstr(line, "rwxp") && strstr(line, "[anon:") && !strstr(line, "dalvik")) {
            filter = true;
        }
        if (!filter) fputs(line, fake);
    }
    fclose(real);
    rewind(fake);
    return fake;
}

// 构造过滤掉 root / magisk 挂载点的 mounts 临时文件
FILE* build_filtered_mounts() {
    ensure_real_funcs();
    if (!real_fopen_ptr || !real_fgets_ptr) return nullptr;

    FILE* real = real_fopen_ptr("/proc/mounts", "r");
    if (!real) real = real_fopen_ptr("/proc/self/mounts", "r");
    if (!real) return nullptr;

    FILE* fake = create_memory_file("mounts");
    if (!fake) {
        fclose(real);
        return nullptr;
    }

    char line[512];
    const char* blacklist[] = {
        "magisk", "core/mirror", "core/img", "/data/adb",
        "modules", "ksu", "apatch", "overlay", "lsposed",
        nullptr
    };

    while (real_fgets_ptr(line, sizeof(line), real)) {
        bool filter = false;
        for (int i = 0; blacklist[i]; i++) {
            if (strcasestr(line, blacklist[i])) { filter = true; break; }
        }
        if (!filter) fputs(line, fake);
    }
    fclose(real);
    rewind(fake);
    return fake;
}

// 构造过滤掉 TracerPid / 跟踪调试状态的 status 虚拟文件
FILE* build_filtered_status() {
    ensure_real_funcs();
    if (!real_fopen_ptr || !real_fgets_ptr) return nullptr;

    FILE* real = real_fopen_ptr("/proc/self/status", "r");
    if (!real) return nullptr;

    FILE* fake = create_memory_file("status");
    if (!fake) {
        fclose(real);
        return nullptr;
    }

    char line[512];
    while (real_fgets_ptr(line, sizeof(line), real)) {
        if (strstr(line, "TracerPid:")) {
            fputs("TracerPid:\t0\n", fake);
        } else if (strstr(line, "State:") && strstr(line, "T (tracing stop)")) {
            fputs("State:\tS (sleeping)\n", fake);
        } else {
            fputs(line, fake);
        }
    }
    fclose(real);
    rewind(fake);
    return fake;
}

// 构造过滤掉 ptrace_stop 的 wchan 虚拟文件
FILE* build_filtered_wchan() {
    FILE* fake = create_memory_file("wchan");
    if (!fake) return nullptr;
    fputs("sys_epoll_wait\n", fake);
    rewind(fake);
    return fake;
}

// ==================== 统一 Hook 实现 ====================

static FILE* fake_fopen(const char* pathname, const char* mode) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();

    if (is_sensitive_path(pathname)) {
        LOGD("Hidden path fopen: %s", pathname);
        errno = ENOENT;
        return nullptr;
    }

    if (pathname) {
        if (strcmp(pathname, "/proc/self/maps") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/maps"))) {
            LOGI("Intercepted fopen maps: %s", pathname);
            FILE* fake = build_filtered_maps();
            if (fake) return fake;
        }
        if (strcmp(pathname, "/proc/mounts") == 0 ||
            strcmp(pathname, "/proc/self/mounts") == 0 ||
            strcmp(pathname, "/proc/self/mountinfo") == 0) {
            LOGI("Intercepted fopen mounts: %s", pathname);
            FILE* fake = build_filtered_mounts();
            if (fake) return fake;
        }
        if (strcmp(pathname, "/proc/self/status") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/status"))) {
            LOGI("Intercepted fopen status: %s", pathname);
            FILE* fake = build_filtered_status();
            if (fake) return fake;
        }
        if (strcmp(pathname, "/proc/self/wchan") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/wchan"))) {
            LOGI("Intercepted fopen wchan: %s", pathname);
            FILE* fake = build_filtered_wchan();
            if (fake) return fake;
        }
    }

    if (real_fopen_ptr) return real_fopen_ptr(pathname, mode);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_fopen, pathname, mode);
    int o_flags = (mode && mode[0] == 'r') ? O_RDONLY : O_RDWR;
    int fd = (int)syscall(__NR_openat, AT_FDCWD, pathname, o_flags, 0);
    return fd >= 0 ? fdopen(fd, mode) : nullptr;
}

static char* fake_fgets(char* s, int size, FILE* stream) {
    SAFE_BYTEHOOK_SCOPE();
    char* result = nullptr;
    if (real_fgets_ptr) result = real_fgets_ptr(s, size, stream);
    else if (g_bytehook_hooks_installed) result = BYTEHOOK_CALL_PREV(fake_fgets, s, size, stream);
    else result = fgets(s, size, stream);
    if (!result) return result;

    if (strstr(result, "TracerPid:")) {
        char* colon = strchr(result, ':');
        if (colon) {
            int pid = 0;
            if (sscanf(colon + 1, "%d", &pid) == 1 && pid != 0) {
                snprintf(result, size, "TracerPid:\t0\n");
                LOGI("Hidden TracerPid: %d -> 0", pid);
            }
        }
    }
    return result;
}

static int fake_open(const char* pathname, int flags, ...) {
    SAFE_BYTEHOOK_SCOPE();

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (is_sensitive_path(pathname)) {
        LOGD("Hidden path open: %s", pathname);
        errno = ENOENT;
        return -1;
    }

    if (pathname) {
        if (strcmp(pathname, "/proc/self/maps") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/maps"))) {
            LOGI("Intercepted open maps: %s", pathname);
            FILE* fake = build_filtered_maps();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (strcmp(pathname, "/proc/mounts") == 0 ||
            strcmp(pathname, "/proc/self/mounts") == 0 ||
            strcmp(pathname, "/proc/self/mountinfo") == 0) {
            LOGI("Intercepted open mounts: %s", pathname);
            FILE* fake = build_filtered_mounts();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (strcmp(pathname, "/proc/self/status") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/status"))) {
            LOGI("Intercepted open status: %s", pathname);
            FILE* fake = build_filtered_status();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (strcmp(pathname, "/proc/self/wchan") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/wchan"))) {
            LOGI("Intercepted open wchan: %s", pathname);
            FILE* fake = build_filtered_wchan();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
    }

    if (real_open_ptr) return real_open_ptr(pathname, flags, mode);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_open, pathname, flags, mode);
    return (int)syscall(__NR_openat, AT_FDCWD, pathname, flags, mode);
}

static int fake_openat(int dirfd, const char* pathname, int flags, ...) {
    SAFE_BYTEHOOK_SCOPE();

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (is_sensitive_path(pathname)) {
        LOGD("Hidden path openat: %s", pathname);
        errno = ENOENT;
        return -1;
    }

    if (pathname) {
        if (strcmp(pathname, "/proc/self/maps") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/maps"))) {
            LOGI("Intercepted openat maps: %s", pathname);
            FILE* fake = build_filtered_maps();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (strcmp(pathname, "/proc/mounts") == 0 ||
            strcmp(pathname, "/proc/self/mounts") == 0 ||
            strcmp(pathname, "/proc/self/mountinfo") == 0) {
            LOGI("Intercepted openat mounts: %s", pathname);
            FILE* fake = build_filtered_mounts();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (strcmp(pathname, "/proc/self/status") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/status"))) {
            LOGI("Intercepted openat status: %s", pathname);
            FILE* fake = build_filtered_status();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (strcmp(pathname, "/proc/self/wchan") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/wchan"))) {
            LOGI("Intercepted openat wchan: %s", pathname);
            FILE* fake = build_filtered_wchan();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
    }

    if (real_openat_ptr) return real_openat_ptr(dirfd, pathname, flags, mode);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_openat, dirfd, pathname, flags, mode);
    return (int)syscall(__NR_openat, dirfd, pathname, flags, mode);
}

static ssize_t fake_readlink(const char* pathname, char* buf, size_t bufsiz) {
    SAFE_BYTEHOOK_SCOPE();

    if (pathname && strcmp(pathname, "/proc/self/exe") == 0) {
        const char* fake_exe = "/system/bin/app_process64";
        size_t len = strlen(fake_exe);
        if (bufsiz <= len) {
            errno = ERANGE;
            return -1;
        }
        strncpy(buf, fake_exe, bufsiz);
        LOGI("Hidden /proc/self/exe -> %s", fake_exe);
        return len;
    }

    if (is_sensitive_path(pathname)) {
        errno = ENOENT;
        return -1;
    }

    if (real_readlink_ptr) return real_readlink_ptr(pathname, buf, bufsiz);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_readlink, pathname, buf, bufsiz);
    return (ssize_t)syscall(__NR_readlinkat, AT_FDCWD, pathname, buf, bufsiz);
}

static ssize_t fake_readlinkat(int dirfd, const char* pathname, char* buf, size_t bufsiz) {
    SAFE_BYTEHOOK_SCOPE();

    if (pathname && strcmp(pathname, "/proc/self/exe") == 0) {
        const char* fake_exe = "/system/bin/app_process64";
        size_t len = strlen(fake_exe);
        if (bufsiz <= len) {
            errno = ERANGE;
            return -1;
        }
        strncpy(buf, fake_exe, bufsiz);
        LOGI("Hidden /proc/self/exe (at) -> %s", fake_exe);
        return len;
    }

    if (is_sensitive_path(pathname)) {
        errno = ENOENT;
        return -1;
    }

    if (real_readlinkat_ptr) return real_readlinkat_ptr(dirfd, pathname, buf, bufsiz);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_readlinkat, dirfd, pathname, buf, bufsiz);
    return (ssize_t)syscall(__NR_readlinkat, dirfd, pathname, buf, bufsiz);
}

static int fake_dladdr(const void* addr, Dl_info* info) {
    SAFE_BYTEHOOK_SCOPE();
    int result = 0;
    if (real_dladdr_ptr) result = real_dladdr_ptr(addr, info);
    else if (g_bytehook_hooks_installed) result = BYTEHOOK_CALL_PREV(fake_dladdr, addr, info);
    else result = dladdr(addr, info);
    if (result != 0 && info && info->dli_fname) {
        const char* hidden[] = {
            "libnative-bypass", "libbytehook", "xalsace",
            "lsposed", "dexkit", "libdexkit", nullptr
        };
        for (int i = 0; hidden[i]; i++) {
            if (strstr(info->dli_fname, hidden[i])) {
                LOGD("Hidden dladdr library: %s", info->dli_fname);
                info->dli_fname = "/system/lib64/libc.so";
                info->dli_fbase = nullptr;
                info->dli_sname = nullptr;
                info->dli_saddr = nullptr;
                break;
            }
        }
    }
    return result;
}

struct dl_iterate_cookie {
    int (*callback)(struct dl_phdr_info*, size_t, void*);
    void* data;
};

static int dl_iterate_callback_wrapper(struct dl_phdr_info* info, size_t size, void* data) {
    auto* cookie = static_cast<dl_iterate_cookie*>(data);
    if (info && info->dlpi_name) {
        const char* hidden[] = {
            "libnative-bypass", "libbytehook", "xalsace",
            "lsposed", "dexkit", "libdexkit", nullptr
        };
        for (int i = 0; hidden[i]; i++) {
            if (strstr(info->dlpi_name, hidden[i])) {
                LOGD("Hidden library in dl_iterate_phdr: %s", info->dlpi_name);
                return 0; // 跳过此条目
            }
        }
    }
    return cookie->callback(info, size, cookie->data);
}

static int fake_dl_iterate_phdr(int (*callback)(struct dl_phdr_info*, size_t, void*), void* data) {
    SAFE_BYTEHOOK_SCOPE();
    dl_iterate_cookie cookie{callback, data};
    if (real_dl_iterate_phdr_ptr) return real_dl_iterate_phdr_ptr(dl_iterate_callback_wrapper, &cookie);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_dl_iterate_phdr, dl_iterate_callback_wrapper, &cookie);
    return dl_iterate_phdr(dl_iterate_callback_wrapper, &cookie);
}

static int fake_access(const char* pathname, int mode) {
    SAFE_BYTEHOOK_SCOPE();
    if (is_sensitive_path(pathname)) {
        LOGD("Hidden path access: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    if (real_access_ptr) return real_access_ptr(pathname, mode);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_access, pathname, mode);
    return (int)syscall(__NR_faccessat, AT_FDCWD, pathname, mode, 0);
}

static int fake_faccessat(int dirfd, const char* pathname, int mode, int flags) {
    SAFE_BYTEHOOK_SCOPE();
    if (is_sensitive_path(pathname)) {
        LOGD("Hidden path faccessat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    if (real_faccessat_ptr) return real_faccessat_ptr(dirfd, pathname, mode, flags);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_faccessat, dirfd, pathname, mode, flags);
    return (int)syscall(__NR_faccessat, dirfd, pathname, mode, flags);
}

static int fake_stat(const char* pathname, struct stat* statbuf) {
    SAFE_BYTEHOOK_SCOPE();
    if (is_sensitive_path(pathname)) {
        LOGD("Hidden path stat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    if (real_stat_ptr) return real_stat_ptr(pathname, statbuf);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_stat, pathname, statbuf);
    return (int)syscall(__NR_newfstatat, AT_FDCWD, pathname, statbuf, 0);
}

static int fake_lstat(const char* pathname, struct stat* statbuf) {
    SAFE_BYTEHOOK_SCOPE();
    if (is_sensitive_path(pathname)) {
        LOGD("Hidden path lstat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    if (real_lstat_ptr) return real_lstat_ptr(pathname, statbuf);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_lstat, pathname, statbuf);
    return (int)syscall(__NR_newfstatat, AT_FDCWD, pathname, statbuf, AT_SYMLINK_NOFOLLOW);
}

static int fake_fstatat(int dirfd, const char* pathname, struct stat* statbuf, int flags) {
    SAFE_BYTEHOOK_SCOPE();
    if (is_sensitive_path(pathname)) {
        LOGD("Hidden path fstatat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    if (real_fstatat_ptr) return real_fstatat_ptr(dirfd, pathname, statbuf, flags);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_fstatat, dirfd, pathname, statbuf, flags);
    return (int)syscall(__NR_newfstatat, dirfd, pathname, statbuf, flags);
}

static int fake_system_property_get(const char* name, char* value) {
    SAFE_BYTEHOOK_SCOPE();
    if (!name || !value) return 0;

    if (strcmp(name, "ro.debuggable") == 0) {
        strcpy(value, "0");
        return 1;
    }
    if (strcmp(name, "ro.secure") == 0) {
        strcpy(value, "1");
        return 1;
    }
    if (strcmp(name, "ro.build.tags") == 0) {
        strcpy(value, "release-keys");
        return strlen("release-keys");
    }
    if (strcmp(name, "ro.boot.flash.locked") == 0) {
        strcpy(value, "1");
        return 1;
    }
    if (strcmp(name, "ro.boot.verifiedbootstate") == 0) {
        strcpy(value, "green");
        return strlen("green");
    }
    if (strstr(name, "magisk") || strstr(name, "ksu") || strstr(name, "apatch")) {
        value[0] = '\0';
        return 0;
    }
    if (real_system_property_get_ptr) return real_system_property_get_ptr(name, value);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_system_property_get, name, value);
    return __system_property_get(name, value);
}

static const prop_info* fake_system_property_find(const char* name) {
    SAFE_BYTEHOOK_SCOPE();
    if (name) {
        if (strstr(name, "magisk") || strstr(name, "ksu") || strstr(name, "apatch")) {
            return nullptr;
        }
    }
    if (real_system_property_find_ptr) return real_system_property_find_ptr(name);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_system_property_find, name);
    return __system_property_find(name);
}

long fake_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();

    // 56: __NR_openat, 437: __NR_openat2, 322: __NR_openat on arm
    if (number == 56 || number == 437 || number == 322) {
        const char* path = (const char*)a2;
        if (path) {
            if (is_sensitive_path(path)) {
                LOGD("fake_syscall: openat blocked sensitive: %s", path);
                errno = ENOENT;
                return -1;
            }
            if (strcmp(path, "/proc/self/maps") == 0 ||
                (strstr(path, "/proc/") && strstr(path, "/maps"))) {
                LOGI("fake_syscall: openat maps redirected: %s", path);
                FILE* fake = build_filtered_maps();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    return fd;
                }
            }
            if (strcmp(path, "/proc/mounts") == 0 ||
                strcmp(path, "/proc/self/mounts") == 0 ||
                strcmp(path, "/proc/self/mountinfo") == 0) {
                LOGI("fake_syscall: openat mounts redirected: %s", path);
                FILE* fake = build_filtered_mounts();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    return fd;
                }
            }
            if (strcmp(path, "/proc/self/status") == 0 ||
                (strstr(path, "/proc/") && strstr(path, "/status"))) {
                LOGI("fake_syscall: openat status redirected: %s", path);
                FILE* fake = build_filtered_status();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    return fd;
                }
            }
            if (strcmp(path, "/proc/self/wchan") == 0 ||
                (strstr(path, "/proc/") && strstr(path, "/wchan"))) {
                LOGI("fake_syscall: openat wchan redirected: %s", path);
                FILE* fake = build_filtered_wchan();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    return fd;
                }
            }
        }
    }
    // 79: __NR_newfstatat
    else if (number == 79) {
        const char* path = (const char*)a2;
        if (path && is_sensitive_path(path)) {
            LOGD("fake_syscall: newfstatat blocked sensitive: %s", path);
            errno = ENOENT;
            return -1;
        }
    }
    // 48 / 439: __NR_faccessat, __NR_faccessat2
    else if (number == 48 || number == 439) {
        const char* path = (const char*)a2;
        if (path && is_sensitive_path(path)) {
            LOGD("fake_syscall: faccessat blocked sensitive: %s", path);
            errno = ENOENT;
            return -1;
        }
    }
    // 78: __NR_readlinkat
    else if (number == 78) {
        const char* path = (const char*)a2;
        if (path && is_sensitive_path(path)) {
            LOGD("fake_syscall: readlinkat blocked sensitive: %s", path);
            errno = ENOENT;
            return -1;
        }
    }
    // 117: __NR_ptrace on aarch64, 26 on arm
#if defined(__aarch64__)
    else if (number == 117) {
#elif defined(__arm__)
    else if (number == 26) {
#else
    else if (number == __NR_ptrace) {
#endif
        // PTRACE_TRACEME = 0
        if ((long)a1 == 0) {
            LOGI("fake_syscall: ptrace(PTRACE_TRACEME) neutralized");
            return 0;
        }
    }

    if (real_syscall_ptr) {
        return real_syscall_ptr(number, a1, a2, a3, a4, a5, a6);
    }
    return syscall(number, a1, a2, a3, a4, a5, a6);
}


void install_hooks() {
    LOGI("Installing libc hooks (ByteHook)...");
    ensure_real_funcs();

    bytehook_hook_all(nullptr, "fopen", (void*)fake_fopen, nullptr, nullptr);
    bytehook_hook_all(nullptr, "fopen64", (void*)fake_fopen, nullptr, nullptr);
    bytehook_hook_all(nullptr, "open", (void*)fake_open, nullptr, nullptr);
    bytehook_hook_all(nullptr, "open64", (void*)fake_open, nullptr, nullptr);
    bytehook_hook_all(nullptr, "openat", (void*)fake_openat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "openat64", (void*)fake_openat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "fgets", (void*)fake_fgets, nullptr, nullptr);
    bytehook_hook_all(nullptr, "readlink", (void*)fake_readlink, nullptr, nullptr);
    bytehook_hook_all(nullptr, "readlinkat", (void*)fake_readlinkat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "dladdr", (void*)fake_dladdr, nullptr, nullptr);
    bytehook_hook_all(nullptr, "dl_iterate_phdr", (void*)fake_dl_iterate_phdr, nullptr, nullptr);
    bytehook_hook_all(nullptr, "access", (void*)fake_access, nullptr, nullptr);
    bytehook_hook_all(nullptr, "faccessat", (void*)fake_faccessat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "stat", (void*)fake_stat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "stat64", (void*)fake_stat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "lstat", (void*)fake_lstat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "lstat64", (void*)fake_lstat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "fstatat", (void*)fake_fstatat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "fstatat64", (void*)fake_fstatat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "syscall", (void*)fake_syscall, nullptr, nullptr);
    bytehook_hook_all(nullptr, "__system_property_get", (void*)fake_system_property_get, nullptr, nullptr);
    bytehook_hook_all(nullptr, "__system_property_find", (void*)fake_system_property_find, nullptr, nullptr);

    LOGI("libc hooks installed (filesystem, maps, mounts, syscalls, and properties)");
}

} // namespace hook_libc
