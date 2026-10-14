#include <jni.h>
#include <dlfcn.h>
#include <string>
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
        std::string name(filename);
        // 拦截对 hook 框架的检测
        if (name.find("bytehook") != std::string::npos ||
            name.find("xposed") != std::string::npos ||
            name.find("lsposed") != std::string::npos ||
            name.find("liblspd") != std::string::npos ||
            name.find("substrate") != std::string::npos ||
            name.find("dexkit") != std::string::npos ||
            name.find("libdexkit") != std::string::npos ||
            name.find("sandhook") != std::string::npos ||
            name.find("yahfa") != std::string::npos ||
            name.find("epic") != std::string::npos ||
            name.find("pine") != std::string::npos ||
            name.find("taichi") != std::string::npos ||
            name.find("qqbypass") != std::string::npos ||
            name.find("xalsace") != std::string::npos) {
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
        std::string sym(symbol);
        // 拦截对 hook 相关符号的查询（指定精确框架名，避免误杀正常函数）
        if (sym.find("bytehook") != std::string::npos ||
            sym.find("xposed") != std::string::npos ||
            sym.find("lsposed") != std::string::npos ||
            sym.find("sandhook") != std::string::npos ||
            sym.find("yahfa") != std::string::npos ||
            sym.find("pine") != std::string::npos ||
            sym.find("dexkit") != std::string::npos ||
            sym.find("epic") != std::string::npos ||
            sym.find("dobby") != std::string::npos ||
            sym.find("riru") != std::string::npos ||
            sym.find("zygisk") != std::string::npos) {
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
        std::string fname(info->dli_fname);
        // 如果查到的是 hook 框架，伪装成系统库
        if (fname.find("bytehook") != std::string::npos ||
            fname.find("native-bypass") != std::string::npos ||
            fname.find("xposed") != std::string::npos ||
            fname.find("lsposed") != std::string::npos ||
            fname.find("liblspd") != std::string::npos ||
            fname.find("dexkit") != std::string::npos ||
            fname.find("libdexkit") != std::string::npos ||
            fname.find("sandhook") != std::string::npos ||
            fname.find("yahfa") != std::string::npos ||
            fname.find("epic") != std::string::npos ||
            fname.find("pine") != std::string::npos ||
            fname.find("taichi") != std::string::npos ||
            fname.find("qqbypass") != std::string::npos ||
            fname.find("xalsace") != std::string::npos) {
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
