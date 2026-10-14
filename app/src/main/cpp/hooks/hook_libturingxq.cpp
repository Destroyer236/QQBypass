#include "hook_libturingxq.h"
#include "hook_libc.h"
#include "../utils/log.h"
#include <bytehook.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

namespace hook_libturingxq {

typedef long (*real_syscall_t)(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6);
static real_syscall_t original_real_syscall = nullptr;

/**
 * libturingxq.so 内部自带 real_syscall 汇编实现 (svc #0)，
 * 并在内部通过 real_syscall@plt 绕过 libc 直接发起底层系统调用：
 * - 0x38 (56, __NR_openat): 探测 /proc/self/maps 及 root/magisk 敏感路径
 * - 0x4f (79, __NR_newfstatat): 探测文件元数据
 * - 0xc6 (198, socket), 0xce (206, sendto), 0xcf (207, recvfrom): 网络通信
 *
 * 策略：拦截 openat 与 newfstatat 的敏感路径探测与 maps/mounts 扫描，
 * 对网络指令及其他正常 syscall 完全放行，确保合规与正常业务通信。
 */
static long hooked_real_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    // 56: __NR_openat
    if (number == 56) {
        const char* path = (const char*)a2;
        if (path) {
            if (hook_libc::is_sensitive_path(path)) {
                LOGD("libturingxq: real_syscall openat blocked sensitive: %s", path);
                errno = ENOENT;
                return -1;
            }
            if (strcmp(path, "/proc/self/maps") == 0 ||
                (strstr(path, "/proc/") && strstr(path, "/maps"))) {
                LOGI("libturingxq: real_syscall openat maps redirected: %s", path);
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
                LOGI("libturingxq: real_syscall openat mounts redirected: %s", path);
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
            LOGD("libturingxq: real_syscall newfstatat blocked sensitive: %s", path);
            errno = ENOENT;
            return -1;
        }
    }

    // 网络及其他 syscall (198 socket, 206 sendto, 207 recvfrom 等) 原样放行
    if (original_real_syscall) {
        return original_real_syscall(number, a1, a2, a3, a4, a5, a6);
    }
    return -1;
}

void install_hooks() {
    LOGI("Installing libturingxq direct syscall hooks (ByteHook)...");

    bytehook_stub_t stub = bytehook_hook_single(
        "libturingxq.so",
        nullptr,
        "real_syscall",
        (void*)hooked_real_syscall,
        nullptr,
        (void**)&original_real_syscall
    );

    if (stub == nullptr) {
        LOGW("libturingxq.so not loaded yet; registering global real_syscall hook fallback");
        bytehook_hook_all(
            nullptr,
            "real_syscall",
            (void*)hooked_real_syscall,
            nullptr,
            (void**)&original_real_syscall
        );
    } else {
        LOGI("libturingxq real_syscall hook installed successfully");
    }
}

} // namespace hook_libturingxq
