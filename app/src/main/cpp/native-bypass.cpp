#include <jni.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <bytehook.h>
#include "utils/log.h"
#include "hooks/hook_libc.h"
#include "hooks/hook_libfekit.h"
#include "hooks/hook_libturingxq.h"
#include "hooks/hook_libmsf.h"
#include "hooks/hook_libqsec.h"
#include "hooks/hook_libmsfkernel.h"
#include "hooks/hook_libturingmfa.h"

/**
 * Native Bypass Module for QQ Enhanced Bypass (Dual Engine: LSPosed NativeHook + ByteHook)
 *
 * This module provides dual-layer native protection against QQ & Tencent risk detection:
 * - Engine 1: LSPosed NativeHook (Inline hooking directly into libc and security SOs at instruction level)
 * - Engine 2: ByteHook (Automatic PLT/GOT hooking across library linkage boundaries)
 *
 * Key targets:
 * - libc: File I/O interception (/proc/self/maps, /proc/self/status, mounts, syscalls)
 * - libfekit.so: Root/Xposed detection
 * - libturingxq.so: ART integrity checks and risk reporting
 * - libMSFKernel.so: qimei36 fingerprint injection (QQ 9.3.50+)
 * - libQSec.so: Anti-hook detection (dlopen/dlsym/dladdr)
 * - libturingmfa.so: Multi-factor authentication & face ID engine (syscall & real_syscall interception)
 * - libMSF hooks: Signature verification (experimental)
 */

typedef void (*NativeOnModuleLoaded)(const char *name, void *handle);

typedef struct {
    uint32_t version;
    HookFunType hook_func;
    void* unhook_func;
} NativeAPIEntries;

#include "utils/safe_bytehook.h"

NativeAPIEntries g_lsposed_api = {0, nullptr, nullptr};
bool g_lsposed_initialized = false;
bool g_bytehook_hooks_installed = false;
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * LSPosed dlopen notification callback
 */
static void on_module_loaded(const char* name, void* handle) {
    if (!name || !handle) return;
    LOGI("[LSPosedNative] on_module_loaded: %s", name);

    if (g_lsposed_api.hook_func) {
        if (strstr(name, "libturingmfa.so")) {
            LOGI("[LSPosedNative] Detected libturingmfa.so -> applying inline hooks");
            install_turingmfa_hooks_for_handle(handle, g_lsposed_api.hook_func);
        } else if (strstr(name, "libfekit.so")) {
            LOGI("[LSPosedNative] Detected libfekit.so -> applying inline hooks");
            hook_libfekit::install_hooks_for_handle(handle, g_lsposed_api.hook_func);
        } else if (strstr(name, "libturingxq.so")) {
            LOGI("[LSPosedNative] Detected libturingxq.so -> applying inline hooks");
            hook_libturingxq::install_hooks_for_handle(handle, g_lsposed_api.hook_func);
        }
    }
}

/**
 * LSPosed Native Hook Entry Point (native_init)
 * Exported with default visibility so LSPosed framework loader can resolve and call it.
 */
extern "C" __attribute__((visibility("default"))) __attribute__((used))
NativeOnModuleLoaded native_init(const NativeAPIEntries *entries) {
    LOGI("=== LSPosed Native Hook Entry Point Called (native_init) ===");
    if (!entries) {
        LOGE("native_init: entries pointer is null");
        return nullptr;
    }

    LOGI("LSPosed Native API version: %u, hook_func: %p", entries->version, (void*)entries->hook_func);
    g_lsposed_api = *entries;
    g_lsposed_initialized = true;

    // 1. Immediately inline-hook libc primitives at the lowest instruction level
    if (g_lsposed_api.hook_func) {
        hook_libc::install_inline_hooks(g_lsposed_api.hook_func);
    }

    // 2. Return on_module_loaded callback to intercept future dlopened security SOs
    return on_module_loaded;
}

/**
 * Install all hooks via ByteHook in a background thread
 */
static void* install_hooks_thread(void* arg) {
    (void)arg;
    LOGI("=== Native Bypass Module (ByteHook Engine) Starting ===");
    LOGI("Process: %d", getpid());

    pthread_mutex_lock(&g_init_mutex);

    if (g_bytehook_hooks_installed) {
        pthread_mutex_unlock(&g_init_mutex);
        return nullptr;
    }

    // 初始化 ByteHook（AUTOMATIC 模式：自动 hook 后续加载的库）
    int bh_ret = bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false);
    if (bh_ret != 0) {
        LOGE("bytehook_init failed: %d", bh_ret);
        pthread_mutex_unlock(&g_init_mutex);
        return nullptr;
    }
    LOGI("ByteHook initialized (AUTOMATIC mode)");

    // Install hooks in order of importance
    LOGI("Installing ByteHook hooks...");

    // 1. libc hooks (highest priority - intercept file I/O & syscalls)
    hook_libc::install_hooks();

    // 2. libfekit.so hooks (root/xposed detection)
    hook_libfekit::install_hooks();

    // 3. libturingxq.so hooks (ART integrity and risk reporting)
    hook_libturingxq::install_hooks();

    // 4. QQ 9.3.50+ extended hooks
    install_qsec_hooks();        // Anti-hook detection
    install_msfkernel_hooks();   // qimei36 fingerprint injection
    install_turingmfa_hooks();   // Multi-factor authentication & face verification

    // 5. libMSF hooks (signature verification bypass)
    hook_libmsf::install_hooks();

    g_bytehook_hooks_installed = true;
    LOGI("=== All ByteHook Native Hooks Installed Successfully ===");

    pthread_mutex_unlock(&g_init_mutex);

    return nullptr;
}

/**
 * Initialize native hooks (called from Java layer)
 */
extern "C" JNIEXPORT void JNICALL
Java_io_github_xalsace_qqbypass_NativeBypass_initNativeHooksNative(JNIEnv* env, jclass clazz) {
    (void)env;
    (void)clazz;
    LOGI("initNativeHooks called from Java layer");

    if (g_lsposed_initialized) {
        LOGI("LSPosed NativeHook is active! Skipping ByteHook to prevent conflicts.");
        return;
    }

    if (g_bytehook_hooks_installed) {
        LOGW("ByteHook native hooks already installed");
        return;
    }

    // Install hooks in background thread to avoid blocking main thread
    pthread_t thread;
    if (pthread_create(&thread, nullptr, install_hooks_thread, nullptr) == 0) {
        pthread_detach(thread);
        LOGI("ByteHook installation thread started");
    } else {
        LOGE("Failed to create hook installation thread");
    }
}

/**
 * Check if hooks are installed
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_io_github_xalsace_qqbypass_NativeBypass_isHooksInstalledNative(JNIEnv* env, jclass clazz) {
    (void)env;
    (void)clazz;
    return (g_bytehook_hooks_installed || g_lsposed_initialized);
}

/**
 * Get hook status message
 */
extern "C" JNIEXPORT jstring JNICALL
Java_io_github_xalsace_qqbypass_NativeBypass_getHookStatusNative(JNIEnv* env, jclass clazz) {
    (void)clazz;
    char status_buf[256];
    snprintf(status_buf, sizeof(status_buf),
             "Native hooks installed: LSPosed InlineHook=%s, ByteHook PLT=%s",
             g_lsposed_initialized ? "active" : "standby",
             g_bytehook_hooks_installed ? "active" : "standby");
    return env->NewStringUTF(status_buf);
}

/**
 * Notify Native layer about Java detection event (Java → Native communication)
 */
extern "C" JNIEXPORT void JNICALL
Java_io_github_xalsace_qqbypass_NativeBypass_notifyDetectionNative(
    JNIEnv* env, jclass clazz, jstring event, jstring data) {
    (void)clazz;

    const char* event_str = env->GetStringUTFChars(event, nullptr);
    const char* data_str = env->GetStringUTFChars(data, nullptr);

    LOGI("[Java→Native] Detection event: %s, data: %s", event_str, data_str);

    // Handle different events
    if (strcmp(event_str, "file_blocked") == 0) {
        LOGD("Java layer blocked file access: %s", data_str);
    } else if (strcmp(event_str, "package_blocked") == 0) {
        LOGD("Java layer blocked package query: %s", data_str);
    } else if (strcmp(event_str, "class_blocked") == 0) {
        LOGD("Java layer blocked class load: %s", data_str);
    }

    env->ReleaseStringUTFChars(event, event_str);
    env->ReleaseStringUTFChars(data, data_str);
}
