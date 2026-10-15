#include "hook_libturingxq.h"
#include "hook_libc.h"
#include "../utils/log.h"
#include "../utils/safe_bytehook.h"
#include <bytehook.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <dlfcn.h>

namespace hook_libturingxq {

typedef long (*real_syscall_t)(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6);
static real_syscall_t original_syscall = nullptr;
static real_syscall_t original_real_syscall = nullptr;
static char* (*real_xq_strstr_ptr)(const char*, const char*) = nullptr;

static long hooked_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    long ret = hook_libc::fake_syscall(number, a1, a2, a3, a4, a5, a6);
    if (ret != -1 || (number != 56 && number != 79 && number != 48 && number != 439 && number != 78)) {
        return ret;
    }
    if (original_syscall) {
        return original_syscall(number, a1, a2, a3, a4, a5, a6);
    }
    return ret;
}

static long hooked_real_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    long ret = hook_libc::fake_syscall(number, a1, a2, a3, a4, a5, a6);
    if (ret != -1 || (number != 56 && number != 79 && number != 48 && number != 439 && number != 78)) {
        return ret;
    }
    if (original_real_syscall) {
        return original_real_syscall(number, a1, a2, a3, a4, a5, a6);
    }
    return ret;
}

static char* fake_xq_strstr(const char* haystack, const char* needle) {
    SAFE_BYTEHOOK_SCOPE();
    char* result = real_xq_strstr_ptr ? real_xq_strstr_ptr(haystack, needle) : BYTEHOOK_CALL_PREV(fake_xq_strstr, haystack, needle);
    if (result && needle) {
        const char* sensitive[] = {
            "lsposed", "xposed", "riru", "zygisk", "magisk", "frida", "KSU", "ksu", "apatch", "shamiko",
            "dexkit", "libdexkit", "flatbuffers", "sandhook", "yahfa", "epic", "pine", "taichi", "liblspd",
            "qqbypass", "xalsace", "libnative-bypass", "libbytehook", "bytehook", "trampoline",
            "qauxv", "io.github.qauxv", "libqauxv", "cc.ioctl", "qnotified", nullptr
        };
        for (int i = 0; sensitive[i]; i++) {
            if (strcasecmp(needle, sensitive[i]) == 0 || strstr(needle, sensitive[i])) {
                LOGD("libturingxq: Blocked strstr match: %s", needle);
                return nullptr;
            }
        }
    }
    return result;
}

void install_hooks() {
    LOGI("Installing libturingxq direct syscall hooks (ByteHook)...");

    bytehook_hook_single(
        "libturingxq.so",
        nullptr,
        "syscall",
        (void*)hooked_syscall,
        nullptr,
        (void**)&original_syscall
    );

    bytehook_hook_single(
        "libturingxq.so",
        nullptr,
        "real_syscall",
        (void*)hooked_real_syscall,
        nullptr,
        (void**)&original_real_syscall
    );

    bytehook_hook_single(
        "libturingxq.so",
        nullptr,
        "strstr",
        (void*)fake_xq_strstr,
        nullptr,
        nullptr
    );

    LOGI("libturingxq hooks installed (syscall, real_syscall, strstr)");
}

void install_hooks_for_handle(void* handle, HookFunType hook_func) {
    if (!handle || !hook_func) return;
    LOGI("Installing libturingxq inline hooks for handle...");

    void* sym_syscall = dlsym(handle, "syscall");
    if (sym_syscall) {
        hook_func(sym_syscall, (void*)hooked_syscall, (void**)&original_syscall);
        LOGI("libturingxq: inline hooked syscall");
    }

    void* sym_real_syscall = dlsym(handle, "real_syscall");
    if (sym_real_syscall) {
        hook_func(sym_real_syscall, (void*)hooked_real_syscall, (void**)&original_real_syscall);
        LOGI("libturingxq: inline hooked real_syscall");
    }

    void* sym_strstr = dlsym(handle, "strstr");
    if (sym_strstr) {
        hook_func(sym_strstr, (void*)fake_xq_strstr, (void**)&real_xq_strstr_ptr);
        LOGI("libturingxq: inline hooked strstr");
    }
}

} // namespace hook_libturingxq
