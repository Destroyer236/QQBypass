#include "hook_libc.h"
#include "../utils/log.h"
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

namespace hook_libc {

// 直接从 libc 取到的真实函数指针（绕过 PLT，避免在辅助函数里再次触发 hook 造成递归）
static FILE* (*real_fopen)(const char*, const char*) = nullptr;
static char* (*real_fgets)(char*, int, FILE*) = nullptr;

static void ensure_real_funcs() {
    if (!real_fopen) {
        real_fopen = (FILE* (*)(const char*, const char*))dlsym(RTLD_NEXT, "fopen");
    }
    if (!real_fgets) {
        real_fgets = (char* (*)(char*, int, FILE*))dlsym(RTLD_NEXT, "fgets");
    }
}

bool is_sensitive_path(const char* path) {
    if (!path) return false;
    const char* hidden[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/data/local/tmp/su", "/data/local/tmp/frida", "re.frida.server",
        "/system/xposed", "/data/adb/lsposed", "/data/adb/modules",
        "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap",
        "/data/adb/shamiko", "libriru", "libzygisk",
        "Superuser.apk", "SuperSU.apk", "Magisk.apk",
        nullptr
    };
    for (int i = 0; hidden[i]; i++) {
        if (strstr(path, hidden[i])) return true;
    }
    return false;
}

// 构造过滤掉 hook 特征库的 maps 临时文件
FILE* build_filtered_maps() {
    ensure_real_funcs();
    if (!real_fopen || !real_fgets) return nullptr;

    FILE* real = real_fopen("/proc/self/maps", "r");
    if (!real) return nullptr;

    FILE* fake = tmpfile();
    if (!fake) {
        fclose(real);
        return nullptr;
    }

    char line[512];
    const char* blacklist[] = {
        "lsposed", "xposed", "riru", "zygisk", "edxposed",
        "frida", "substrate", "libDalvikLoader", "libAndroidCydia",
        "magisk", "ksu", "kernelsu", "supersu", "superuser",
        "libnative-bypass", "libbytehook", "xalsace", "qq_hook",
        nullptr
    };

    while (real_fgets(line, sizeof(line), real)) {
        bool filter = false;
        for (int i = 0; blacklist[i]; i++) {
            if (strstr(line, blacklist[i])) { filter = true; break; }
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
    if (!real_fopen || !real_fgets) return nullptr;

    FILE* real = real_fopen("/proc/mounts", "r");
    if (!real) real = real_fopen("/proc/self/mounts", "r");
    if (!real) return nullptr;

    FILE* fake = tmpfile();
    if (!fake) {
        fclose(real);
        return nullptr;
    }

    char line[512];
    const char* blacklist[] = {
        "magisk", "core/mirror", "overlay", "ksu", "apatch",
        "lsposed", "shamiko", "/data/adb", nullptr
    };

    while (real_fgets(line, sizeof(line), real)) {
        bool filter = false;
        for (int i = 0; blacklist[i]; i++) {
            if (strstr(line, blacklist[i])) { filter = true; break; }
        }
        if (!filter) fputs(line, fake);
    }
    fclose(real);
    rewind(fake);
    return fake;
}

// fopen 代理：重定向 /proc/self/maps, /proc/mounts
static FILE* fake_fopen(const char* path, const char* mode) {
    BYTEHOOK_STACK_SCOPE();

    if (path) {
        if (is_sensitive_path(path)) {
            errno = ENOENT;
            return nullptr;
        }
        if (strcmp(path, "/proc/self/maps") == 0 ||
            (strstr(path, "/proc/") && strstr(path, "/maps"))) {
            LOGI("Intercepted fopen maps: %s", path);
            FILE* fake = build_filtered_maps();
            if (fake) return fake;
        }
        if (strcmp(path, "/proc/mounts") == 0 ||
            strcmp(path, "/proc/self/mounts") == 0 ||
            strcmp(path, "/proc/self/mountinfo") == 0) {
            LOGI("Intercepted fopen mounts: %s", path);
            FILE* fake = build_filtered_mounts();
            if (fake) return fake;
        }
    }
    return BYTEHOOK_CALL_PREV(fake_fopen, path, mode);
}

// open 代理：隐藏敏感文件，重定向 maps 与 mounts
static int fake_open(const char* pathname, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = static_cast<mode_t>(va_arg(args, int));
        va_end(args);
    }

    if (pathname) {
        if (is_sensitive_path(pathname)) {
            errno = ENOENT;
            return -1;
        }
        if (strcmp(pathname, "/proc/self/maps") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/maps"))) {
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
            FILE* fake = build_filtered_mounts();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
    }
    return BYTEHOOK_CALL_PREV(fake_open, pathname, flags, mode);
}

// openat 代理：隐藏敏感文件，重定向 maps 与 mounts
static int fake_openat(int dirfd, const char* pathname, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = static_cast<mode_t>(va_arg(args, int));
        va_end(args);
    }

    if (pathname) {
        if (is_sensitive_path(pathname)) {
            errno = ENOENT;
            return -1;
        }
        if (strcmp(pathname, "/proc/self/maps") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/maps"))) {
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
            FILE* fake = build_filtered_mounts();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
    }
    return BYTEHOOK_CALL_PREV(fake_openat, dirfd, pathname, flags, mode);
}

// fgets 代理：伪造 TracerPid 为 0
static char* fake_fgets(char* s, int size, FILE* stream) {
    BYTEHOOK_STACK_SCOPE();

    char* result = BYTEHOOK_CALL_PREV(fake_fgets, s, size, stream);
    if (result && s && strncmp(s, "TracerPid:", 10) == 0) {
        snprintf(s, size, "TracerPid:\t0\n");
    }
    return result;
}

// readlink 代理：隐藏进程真实路径
static ssize_t fake_readlink(const char* path, char* buf, size_t bufsiz) {
    BYTEHOOK_STACK_SCOPE();

    if (path && strcmp(path, "/proc/self/exe") == 0) {
        const char* fake_path = "/system/bin/app_process64";
        size_t len = strlen(fake_path);
        if (len > bufsiz) len = bufsiz;
        memcpy(buf, fake_path, len);
        return (ssize_t)len;
    }
    return BYTEHOOK_CALL_PREV(fake_readlink, path, buf, bufsiz);
}

// access 代理：隐藏敏感文件
static int fake_access(const char* pathname, int mode) {
    BYTEHOOK_STACK_SCOPE();

    if (is_sensitive_path(pathname)) {
        LOGD("Hidden path access: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(fake_access, pathname, mode);
}

static int fake_faccessat(int dirfd, const char* pathname, int mode, int flags) {
    BYTEHOOK_STACK_SCOPE();

    if (is_sensitive_path(pathname)) {
        LOGD("Hidden path faccessat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(fake_faccessat, dirfd, pathname, mode, flags);
}

// stat / lstat / fstatat 代理：隐藏敏感文件
static int fake_stat(const char* pathname, struct stat* statbuf) {
    BYTEHOOK_STACK_SCOPE();

    if (is_sensitive_path(pathname)) {
        LOGD("Hidden path stat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(fake_stat, pathname, statbuf);
}

static int fake_lstat(const char* pathname, struct stat* statbuf) {
    BYTEHOOK_STACK_SCOPE();

    if (is_sensitive_path(pathname)) {
        LOGD("Hidden path lstat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(fake_lstat, pathname, statbuf);
}

static int fake_fstatat(int dirfd, const char* pathname, struct stat* statbuf, int flags) {
    BYTEHOOK_STACK_SCOPE();

    if (is_sensitive_path(pathname)) {
        LOGD("Hidden path fstatat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(fake_fstatat, dirfd, pathname, statbuf, flags);
}

// 系统属性检查点代理：伪造正常发布版系统环境属性
static int fake_system_property_get(const char* name, char* value) {
    BYTEHOOK_STACK_SCOPE();
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
    return BYTEHOOK_CALL_PREV(fake_system_property_get, name, value);
}

static const prop_info* fake_system_property_find(const char* name) {
    BYTEHOOK_STACK_SCOPE();
    if (name) {
        if (strstr(name, "magisk") || strstr(name, "ksu") || strstr(name, "apatch")) {
            return nullptr;
        }
    }
    return BYTEHOOK_CALL_PREV(fake_system_property_find, name);
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
    bytehook_hook_all(nullptr, "access", (void*)fake_access, nullptr, nullptr);
    bytehook_hook_all(nullptr, "faccessat", (void*)fake_faccessat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "stat", (void*)fake_stat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "stat64", (void*)fake_stat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "lstat", (void*)fake_lstat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "lstat64", (void*)fake_lstat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "fstatat", (void*)fake_fstatat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "fstatat64", (void*)fake_fstatat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "__system_property_get", (void*)fake_system_property_get, nullptr, nullptr);
    bytehook_hook_all(nullptr, "__system_property_find", (void*)fake_system_property_find, nullptr, nullptr);

    LOGI("libc hooks installed (filesystem, maps, mounts, and properties)");
}

} // namespace hook_libc
