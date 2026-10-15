#include "hook_libturingmfa.h"
#include "hook_libc.h"
#include "../utils/log.h"
#include <bytehook.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <dlfcn.h>

#include "../utils/safe_bytehook.h"

namespace {

typedef long (*real_syscall_t)(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6);
static real_syscall_t original_syscall_mfa = nullptr;
static real_syscall_t original_real_syscall_mfa = nullptr;
static char* (*real_mfa_strstr_ptr)(const char*, const char*) = nullptr;

/**
 * libturingmfa.so (Turing Multi-Factor Authentication & Face ID engine)
 * 内部既有 real_syscall 汇编实现，也有对 libc.so 的 syscall@plt 调用。
 * 在人脸核身与多因子验证期间：
 * - 0x1658c: syscall 56 (__NR_openat) 扫描 /proc/self/maps，随后 fdopen 逐行匹配 Hook 特征
 * - 0x13d90: syscall 79 (__NR_newfstatat) 探测 su / magisk / ksu 等文件元数据
 * - 0x13f78: syscall 56 (__NR_openat) 扫描敏感路径
 * - 0xe8c4: syscall 56 (__NR_openat) 嗅探敏感路径及 /proc/mounts
 * - syscall 198 (socket), 206 (sendto), 207 (recvfrom): 认证数据传输
 *
 * 策略：统一通过 hook_libc::fake_syscall 进行敏感路径阻断与 maps/mounts 虚拟清洗，
 * 保证人脸认证与网络通信正常放行。
 */
static long hooked_mfa_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    long ret = hook_libc::fake_syscall(number, a1, a2, a3, a4, a5, a6);
    if (ret != -1 || (number != 56 && number != 79 && number != 48 && number != 439 && number != 78)) {
        return ret;
    }
    if (original_syscall_mfa) {
        return original_syscall_mfa(number, a1, a2, a3, a4, a5, a6);
    }
    return ret;
}

static long hooked_mfa_real_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    long ret = hook_libc::fake_syscall(number, a1, a2, a3, a4, a5, a6);
    if (ret != -1 || (number != 56 && number != 79 && number != 48 && number != 439 && number != 78)) {
        return ret;
    }
    if (original_real_syscall_mfa) {
        return original_real_syscall_mfa(number, a1, a2, a3, a4, a5, a6);
    }
    return ret;
}

/**
 * 拦截 libturingmfa.so 的 strstr 敏感关键字匹配，消除内存与模块特征检测
 */
static char* fake_mfa_strstr(const char* haystack, const char* needle) {
    SAFE_BYTEHOOK_SCOPE();
    char* result = real_mfa_strstr_ptr ? real_mfa_strstr_ptr(haystack, needle) : BYTEHOOK_CALL_PREV(fake_mfa_strstr, haystack, needle);
    if (result && needle) {
        const char* sensitive[] = {
            "lsposed", "xposed", "riru", "zygisk", "magisk", "frida", "KSU", "ksu", "apatch", "shamiko",
            "dexkit", "libdexkit", "flatbuffers", "sandhook", "yahfa", "epic", "pine", "taichi", "liblspd",
            "qqbypass", "xalsace", "libnative-bypass", "libbytehook", "bytehook", "trampoline",
            "qauxv", "io.github.qauxv", "libqauxv", "cc.ioctl", "qnotified", nullptr
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

    // 1. Hook syscall in libturingmfa.so
    bytehook_stub_t s1 = bytehook_hook_single(
        "libturingmfa.so",
        nullptr,
        "syscall",
        (void*)hooked_mfa_syscall,
        nullptr,
        (void**)&original_syscall_mfa
    );

    // 2. Hook real_syscall in libturingmfa.so
    bytehook_stub_t s2 = bytehook_hook_single(
        "libturingmfa.so",
        nullptr,
        "real_syscall",
        (void*)hooked_mfa_real_syscall,
        nullptr,
        (void**)&original_real_syscall_mfa
    );

    // 3. Hook strstr in libturingmfa.so
    bytehook_hook_single(
        "libturingmfa.so",
        nullptr,
        "strstr",
        (void*)fake_mfa_strstr,
        nullptr,
        nullptr
    );

    if (s1 != nullptr || s2 != nullptr) {
        LOGI("libturingmfa syscall/real_syscall hook installed successfully");
    } else {
        LOGW("libturingmfa.so not loaded yet; registered for automatic hook on load");
    }
}

void install_turingmfa_hooks_for_handle(void* handle, HookFunType hook_func) {
    if (!handle || !hook_func) return;
    LOGI("Installing libturingmfa inline hooks for handle...");

    void* sym_syscall = dlsym(handle, "syscall");
    if (sym_syscall) {
        hook_func(sym_syscall, (void*)hooked_mfa_syscall, (void**)&original_syscall_mfa);
        LOGI("libturingmfa: inline hooked syscall");
    }

    void* sym_real_syscall = dlsym(handle, "real_syscall");
    if (sym_real_syscall) {
        hook_func(sym_real_syscall, (void*)hooked_mfa_real_syscall, (void**)&original_real_syscall_mfa);
        LOGI("libturingmfa: inline hooked real_syscall");
    }

    void* sym_strstr = dlsym(handle, "strstr");
    if (sym_strstr) {
        hook_func(sym_strstr, (void*)fake_mfa_strstr, (void**)&real_mfa_strstr_ptr);
        LOGI("libturingmfa: inline hooked strstr");
    }
}
