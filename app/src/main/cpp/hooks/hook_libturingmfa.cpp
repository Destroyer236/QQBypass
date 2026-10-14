#include "hook_libturingmfa.h"
#include "hook_libc.h"
#include "../utils/log.h"
#include <bytehook.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

namespace {

typedef long (*real_syscall_t)(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6);
static real_syscall_t original_real_syscall_mfa = nullptr;

/**
 * libturingmfa.so (Turing Multi-Factor Authentication & Face ID engine)
 * 内部自带 real_syscall 汇编实现 (svc #0)，在人脸核身与多因子验证期间
 * 经由 real_syscall@plt 直接发起底层系统调用：
 * - 0x1658c: syscall 56 (__NR_openat) 扫描 /proc/self/maps，随后 fdopen 逐行匹配 Hook 特征
 * - 0xe8c4: syscall 56 (__NR_openat) 嗅探敏感路径及 /proc/mounts
 * - syscall 79 (__NR_newfstatat): 探测 su / magisk / ksu 等文件元数据
 * - syscall 198 (socket), 206 (sendto), 207 (recvfrom): 认证数据传输
 *
 * 策略：拦截 openat 与 newfstatat 的敏感路径探测与 maps/mounts 扫描，重定向至已清洗的虚拟映射；
 * 对网络通信及其他正常 syscall 100% 原样放行，确保认证流程顺畅履约。
 */
static long hooked_mfa_real_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    // 56: __NR_openat
    if (number == 56) {
        const char* path = (const char*)a2;
        if (path) {
            if (hook_libc::is_sensitive_path(path)) {
                LOGD("libturingmfa: real_syscall openat blocked sensitive: %s", path);
                errno = ENOENT;
                return -1;
            }
            if (strcmp(path, "/proc/self/maps") == 0 ||
                (strstr(path, "/proc/") && strstr(path, "/maps"))) {
                LOGI("libturingmfa: real_syscall openat maps redirected: %s", path);
                FILE* fake = hook_libc::build_filtered_maps();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    return fd;
                }
            }
            if (strcmp(path, "/proc/mounts") == 0 ||
                strcmp(path, "/proc/self/mounts") == 0 ||
                strcmp(path, "/proc/self/mountinfo") == 0) {
                LOGI("libturingmfa: real_syscall openat mounts redirected: %s", path);
                FILE* fake = hook_libc::build_filtered_mounts();
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
        if (path && hook_libc::is_sensitive_path(path)) {
            LOGD("libturingmfa: real_syscall newfstatat blocked sensitive: %s", path);
            errno = ENOENT;
            return -1;
        }
    }

    // 网络通信及其他 syscall (198 socket, 206 sendto, 207 recvfrom 等) 原样放行
    if (original_real_syscall_mfa) {
        return original_real_syscall_mfa(number, a1, a2, a3, a4, a5, a6);
    }
    return -1;
}

/**
 * 拦截 libturingmfa.so 的 strstr 敏感关键字匹配，消除内存与模块特征检测
 */
static char* fake_mfa_strstr(const char* haystack, const char* needle) {
    BYTEHOOK_STACK_SCOPE();
    char* result = BYTEHOOK_CALL_PREV(fake_mfa_strstr, haystack, needle);
    if (result && needle) {
        const char* sensitive[] = {
            "lsposed", "xposed", "riru", "zygisk", "magisk", "frida", "KSU", "ksu", "apatch", "shamiko",
            "dexkit", "libdexkit", "flatbuffers", "sandhook", "yahfa", "epic", "pine", "taichi", "liblspd",
            "qqbypass", "xalsace", "libnative-bypass", "libbytehook", nullptr
        };
        for (int i = 0; sensitive[i]; i++) {
            if (strcasecmp(needle, sensitive[i]) == 0 || strstr(needle, sensitive[i])) {
                LOGD("libturingmfa: Blocked strstr match: %s", needle);
                return nullptr;
            }
        }
    }
    return result;
}

} // namespace

void install_turingmfa_hooks() {
    LOGI("Installing libturingmfa hooks (ByteHook)...");

    // 1. Hook real_syscall in libturingmfa.so
    bytehook_stub_t stub = bytehook_hook_single(
        "libturingmfa.so",
        nullptr,
        "real_syscall",
        (void*)hooked_mfa_real_syscall,
        nullptr,
        (void**)&original_real_syscall_mfa
    );

    if (stub == nullptr) {
        LOGW("libturingmfa.so not loaded yet; registered for automatic hook on load");
    } else {
        LOGI("libturingmfa real_syscall hook installed successfully");
    }

    // 2. Hook strstr in libturingmfa.so
    bytehook_hook_single(
        "libturingmfa.so",
        nullptr,
        "strstr",
        (void*)fake_mfa_strstr,
        nullptr,
        nullptr
    );

    LOGI("libturingmfa hooks installed (maps, sensitive paths, strstr sanitized; network allowed)");
}
