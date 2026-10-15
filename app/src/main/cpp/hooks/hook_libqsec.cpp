#include <jni.h>
#include <dlfcn.h>
#include <string.h>
#include "../utils/log.h"
#include "bytehook.h"

// QSec 反 hook 检测函数的原始指针
static void* (*original_dlopen)(const char*, int) = nullptr;
static void* (*original_dlsym)(void*, const char*) = nullptr;
static int (*original_dladdr)(const void*, Dl_info*) = nullptr;

/**
 * Hook dlopen - 防止 QSec 检测 ByteHook 等 hook 框架
 */
static void* hooked_dlopen(const char* filename, int flag) {
    if (filename) {
        // 拦截对 hook 框架的检测
        if (strcasestr(filename, "bytehook") ||
            strcasestr(filename, "xposed") ||
            strcasestr(filename, "lsposed") ||
            strcasestr(filename, "liblspd") ||
            strcasestr(filename, "substrate") ||
            strcasestr(filename, "dexkit") ||
            strcasestr(filename, "libdexkit") ||
            strcasestr(filename, "sandhook") ||
            strcasestr(filename, "yahfa") ||
            strcasestr(filename, "epic") ||
            strcasestr(filename, "pine") ||
            strcasestr(filename, "taichi") ||
            strcasestr(filename, "qqbypass") ||
            strcasestr(filename, "xalsace")) {
            LOGI("QSec dlopen blocked: %s", filename);
            return nullptr;
        }
    }
    return original_dlopen(filename, flag);
}

/**
 * Hook dlsym - 防止符号表扫描检测
 */
static void* hooked_dlsym(void* handle, const char* symbol) {
    if (symbol) {
        // 拦截对 hook 相关符号的查询（指定精确框架名，避免误杀正常函数）
        if (strcasestr(symbol, "bytehook") ||
            strcasestr(symbol, "xposed") ||
            strcasestr(symbol, "lsposed") ||
            strcasestr(symbol, "sandhook") ||
            strcasestr(symbol, "yahfa") ||
            strcasestr(symbol, "pine") ||
            strcasestr(symbol, "dexkit") ||
            strcasestr(symbol, "epic") ||
            strcasestr(symbol, "dobby") ||
            strcasestr(symbol, "riru") ||
            strcasestr(symbol, "zygisk") ||
            strcasestr(symbol, "qauxv")) {
            LOGI("QSec dlsym blocked: %s", symbol);
            return nullptr;
        }
    }
    return original_dlsym(handle, symbol);
}

/**
 * Hook dladdr - 防止地址反查检测 hook 框架
 */
static int hooked_dladdr(const void* addr, Dl_info* info) {
    int ret = original_dladdr(addr, info);

    if (ret != 0 && info && info->dli_fname) {
        const char* fname = info->dli_fname;
        // 如果查到的是 hook 框架，伪装成系统库
        if (strcasestr(fname, "bytehook") ||
            strcasestr(fname, "native-bypass") ||
            strcasestr(fname, "xposed") ||
            strcasestr(fname, "lsposed") ||
            strcasestr(fname, "liblspd") ||
            strcasestr(fname, "dexkit") ||
            strcasestr(fname, "libdexkit") ||
            strcasestr(fname, "sandhook") ||
            strcasestr(fname, "yahfa") ||
            strcasestr(fname, "epic") ||
            strcasestr(fname, "pine") ||
            strcasestr(fname, "taichi") ||
            strcasestr(fname, "qqbypass") ||
            strcasestr(fname, "xalsace") ||
            strcasestr(fname, "qauxv") ||
            strcasestr(fname, "io.github.qauxv") ||
            strcasestr(fname, "libqauxv") ||
            strcasestr(fname, "cc.ioctl") ||
            strcasestr(fname, "qnotified")) {
            LOGI("QSec dladdr spoofed: %s -> libc.so", info->dli_fname);
#if defined(__aarch64__) || defined(__x86_64__)
            info->dli_fname = "/system/lib64/libc.so";
#else
            info->dli_fname = "/system/lib/libc.so";
#endif
            info->dli_fbase = nullptr;
            info->dli_sname = nullptr;
            info->dli_saddr = nullptr;
        }
    }

    return ret;
}

/**
 * 安装 libQSec 的 hook
 */
void install_qsec_hooks() {
    LOGI("Installing libQSec hooks (ByteHook)...");

    // Hook dlopen
    bytehook_stub_t stub = bytehook_hook_single(
        "libQSec.so",
        nullptr,
        "dlopen",
        (void*)hooked_dlopen,
        nullptr,
        (void**)&original_dlopen
    );
    if (stub == nullptr) {
        LOGE("Failed to hook libQSec dlopen");
    }

    // Hook dlsym
    stub = bytehook_hook_single(
        "libQSec.so",
        nullptr,
        "dlsym",
        (void*)hooked_dlsym,
        nullptr,
        (void**)&original_dlsym
    );
    if (stub == nullptr) {
        LOGE("Failed to hook libQSec dlsym");
    }

    // Hook dladdr
    stub = bytehook_hook_single(
        "libQSec.so",
        nullptr,
        "dladdr",
        (void*)hooked_dladdr,
        nullptr,
        (void**)&original_dladdr
    );
    if (stub == nullptr) {
        LOGE("Failed to hook libQSec dladdr");
    }

    LOGI("libQSec hooks installed");
}
