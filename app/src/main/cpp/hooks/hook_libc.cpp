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
#include <dirent.h>
#include <signal.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include "hook_libqimei.h"

#ifndef ST_RDONLY
#define ST_RDONLY 1
#endif

namespace hook_libc {

// 真实函数指针（支持 LSPosed inline hook backup 与 dlsym 回退）
static FILE* (*real_fopen_ptr)(const char*, const char*) = nullptr;
static char* (*real_fgets_ptr)(char*, int, FILE*) = nullptr;
static char* (*real_fgets_chk_ptr)(char*, int, size_t, FILE*) = nullptr;
static int (*real_open_ptr)(const char*, int, mode_t) = nullptr;
static int (*real_openat_ptr)(int, const char*, int, mode_t) = nullptr;
static int (*real_open_2_ptr)(const char*, int) = nullptr;
static int (*real_openat_2_ptr)(int, const char*, int) = nullptr;
static DIR* (*real_opendir_ptr)(const char*) = nullptr;
static struct dirent* (*real_readdir_ptr)(DIR*) = nullptr;
static struct dirent64* (*real_readdir64_ptr)(DIR*) = nullptr;
static int (*real_readdir_r_ptr)(DIR*, struct dirent*, struct dirent**) = nullptr;
static int (*real_readdir64_r_ptr)(DIR*, struct dirent64*, struct dirent64**) = nullptr;
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
typedef void (*prop_read_cb_t)(void* cookie, const char* name, const char* value, uint32_t serial);
static void (*real_system_property_read_callback_ptr)(const prop_info*, prop_read_cb_t, void*) = nullptr;
static int (*real_system_property_read_ptr)(const prop_info*, char*, char*) = nullptr;
static FILE* (*real_popen_ptr)(const char*, const char*) = nullptr;
static int (*real_pclose_ptr)(FILE*) = nullptr;
static int (*real_statfs_ptr)(const char*, struct statfs*) = nullptr;
static int (*real_statfs64_ptr)(const char*, struct statfs64*) = nullptr;
static int (*real_fstatfs_ptr)(int, struct statfs*) = nullptr;
static int (*real_fstatfs64_ptr)(int, struct statfs64*) = nullptr;
static int (*real_uname_ptr)(struct utsname*) = nullptr;
static void* (*real_dlopen_ptr)(const char*, int) = nullptr;
static void* (*real_android_dlopen_ext_ptr)(const char*, int, const void*) = nullptr;
typedef long (*syscall_func_t)(long, void*, void*, void*, void*, void*, void*);
static syscall_func_t real_syscall_ptr = nullptr;
static int (*real_kill_ptr)(pid_t, int) = nullptr;
static int (*real_tkill_ptr)(pid_t, int) = nullptr;
static int (*real_tgkill_ptr)(pid_t, pid_t, int) = nullptr;
static int (*real_raise_ptr)(int) = nullptr;

static void ensure_real_funcs() {
    if (!real_fopen_ptr) real_fopen_ptr = (FILE* (*)(const char*, const char*))dlsym(RTLD_DEFAULT, "fopen");
    if (!real_fgets_ptr) real_fgets_ptr = (char* (*)(char*, int, FILE*))dlsym(RTLD_DEFAULT, "fgets");
    if (!real_fgets_chk_ptr) real_fgets_chk_ptr = (char* (*)(char*, int, size_t, FILE*))dlsym(RTLD_DEFAULT, "__fgets_chk");
    if (!real_open_ptr) real_open_ptr = (int (*)(const char*, int, mode_t))dlsym(RTLD_DEFAULT, "open");
    if (!real_openat_ptr) real_openat_ptr = (int (*)(int, const char*, int, mode_t))dlsym(RTLD_DEFAULT, "openat");
    if (!real_open_2_ptr) real_open_2_ptr = (int (*)(const char*, int))dlsym(RTLD_DEFAULT, "__open_2");
    if (!real_openat_2_ptr) real_openat_2_ptr = (int (*)(int, const char*, int))dlsym(RTLD_DEFAULT, "__openat_2");
    if (!real_opendir_ptr) real_opendir_ptr = (DIR* (*)(const char*))dlsym(RTLD_DEFAULT, "opendir");
    if (!real_readdir_ptr) real_readdir_ptr = (struct dirent* (*)(DIR*))dlsym(RTLD_DEFAULT, "readdir");
    if (!real_readdir64_ptr) real_readdir64_ptr = (struct dirent64* (*)(DIR*))dlsym(RTLD_DEFAULT, "readdir64");
    if (!real_readdir_r_ptr) real_readdir_r_ptr = (int (*)(DIR*, struct dirent*, struct dirent**))dlsym(RTLD_DEFAULT, "readdir_r");
    if (!real_readdir64_r_ptr) real_readdir64_r_ptr = (int (*)(DIR*, struct dirent64*, struct dirent64**))dlsym(RTLD_DEFAULT, "readdir64_r");
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
    if (!real_system_property_read_callback_ptr) real_system_property_read_callback_ptr = (void (*)(const prop_info*, prop_read_cb_t, void*))dlsym(RTLD_DEFAULT, "__system_property_read_callback");
    if (!real_system_property_read_ptr) real_system_property_read_ptr = (int (*)(const prop_info*, char*, char*))dlsym(RTLD_DEFAULT, "__system_property_read");
    if (!real_popen_ptr) real_popen_ptr = (FILE* (*)(const char*, const char*))dlsym(RTLD_DEFAULT, "popen");
    if (!real_pclose_ptr) real_pclose_ptr = (int (*)(FILE*))dlsym(RTLD_DEFAULT, "pclose");
    if (!real_statfs_ptr) real_statfs_ptr = (int (*)(const char*, struct statfs*))dlsym(RTLD_DEFAULT, "statfs");
    if (!real_statfs64_ptr) real_statfs64_ptr = (int (*)(const char*, struct statfs64*))dlsym(RTLD_DEFAULT, "statfs64");
    if (!real_fstatfs_ptr) real_fstatfs_ptr = (int (*)(int, struct statfs*))dlsym(RTLD_DEFAULT, "fstatfs");
    if (!real_fstatfs64_ptr) real_fstatfs64_ptr = (int (*)(int, struct statfs64*))dlsym(RTLD_DEFAULT, "fstatfs64");
    if (!real_uname_ptr) real_uname_ptr = (int (*)(struct utsname*))dlsym(RTLD_DEFAULT, "uname");
    if (!real_dlopen_ptr) real_dlopen_ptr = (void* (*)(const char*, int))dlsym(RTLD_DEFAULT, "dlopen");
    if (!real_android_dlopen_ext_ptr) real_android_dlopen_ext_ptr = (void* (*)(const char*, int, const void*))dlsym(RTLD_DEFAULT, "android_dlopen_ext");
    if (!real_syscall_ptr) real_syscall_ptr = (syscall_func_t)dlsym(RTLD_DEFAULT, "syscall");
    if (!real_kill_ptr) real_kill_ptr = (int (*)(pid_t, int))dlsym(RTLD_DEFAULT, "kill");
    if (!real_tkill_ptr) real_tkill_ptr = (int (*)(pid_t, int))dlsym(RTLD_DEFAULT, "tkill");
    if (!real_tgkill_ptr) real_tgkill_ptr = (int (*)(pid_t, pid_t, int))dlsym(RTLD_DEFAULT, "tgkill");
    if (!real_raise_ptr) real_raise_ptr = (int (*)(int))dlsym(RTLD_DEFAULT, "raise");
}

static bool is_caller_security_dso(void* return_address) {
    if (!return_address) return false;
    Dl_info info;
    if (dladdr(return_address, &info) && info.dli_fname) {
        const char* f = info.dli_fname;
        if (strcasestr(f, "libfekit") || strcasestr(f, "libturing") ||
            strcasestr(f, "libqqdid") || strcasestr(f, "libmsf") ||
            strcasestr(f, "libqsec") || strcasestr(f, "libsec") ||
            strcasestr(f, "libtears") || strcasestr(f, "libbeacon") ||
            strcasestr(f, "libwtlogin") || strcasestr(f, "libmsaoaidsec") ||
            strcasestr(f, "libqzone_check") || strcasestr(f, "libdexloader") ||
            strcasestr(f, "libtsmqqsc") || strcasestr(f, "libbugly") ||
            strcasestr(f, "libandroid_desensitization") ||
            strcasestr(f, "libqqPerfNativeTool") || strcasestr(f, "libshadowhook") ||
            strcasestr(f, "librmonitor") || strcasestr(f, "libqimei") ||
            strcasestr(f, "libkcsdk") || strcasestr(f, "libnativefilescan") ||
            strcasestr(f, "libunusedcodecheck") || strcasestr(f, "libthreadsuspend") ||
            strcasestr(f, "libmatrix") || strcasestr(f, "liblogcathook") ||
            strcasestr(f, "libcuckoo") || strcasestr(f, "libwechat") ||
            strcasestr(f, "libtmsdk")) {
            return true;
        }
    }
    return false;
}

static bool is_caller_qa(void* return_address) {
    if (!return_address) return false;
    Dl_info info;
    if (dladdr(return_address, &info) && info.dli_fname) {
        const char* f = info.dli_fname;
        if (strstr(f, "qauxv") || strstr(f, "qa_dyn_lib") || strstr(f, "libqauxv") || strstr(f, "io.github.qauxv") ||
            strstr(f, "libmmkv") || strstr(f, "libjavacore") || strstr(f, "libopenjdk") ||
            strstr(f, "libart") || strstr(f, "liblspd") || strstr(f, "libxposed") ||
            strstr(f, "qqbypass") || strstr(f, "libnative-bypass") || strstr(f, "dexkit") ||
            strstr(f, "liblspatch") || strstr(f, "lspatch") || strstr(f, "libpine") || strstr(f, "libsandhook") ||
            strstr(f, "libcnm") || strstr(f, "liball-jni") || strstr(f, "moe.ono") || strstr(f, "ono") || strstr(f, "lzlnb")) {
            return true;
        }
    }
    return false;
}

static bool is_qa_private_path(const char* path) {
    if (!path || !path[0]) return false;
    // CRITICAL: NEVER consider /data/app/ as a QA private hidden path
    if (strstr(path, "/data/app/")) return false;
    return strcasestr(path, "qa_mmkv") != nullptr ||
           strcasestr(path, "tmp_qa_") != nullptr ||
           strcasestr(path, "qa_dyn_lib") != nullptr ||
           strcasestr(path, "qa_misc") != nullptr ||
           strcasestr(path, "libqauxv") != nullptr ||
           strcasestr(path, "libqauxv-core0") != nullptr ||
           strcasestr(path, "libqauxv-core1") != nullptr ||
           strcasestr(path, "qnotified") != nullptr ||
           strcasestr(path, "global_config") != nullptr ||
           strcasestr(path, "oat_inline_deopt_cache") != nullptr ||
           strcasestr(path, "last_use_emoticon_time") != nullptr ||
           strcasestr(path, "sDumpTG_") != nullptr ||
           strcasestr(path, "qauxv_") != nullptr ||
           strcasestr(path, "ono_mmkv") != nullptr ||
           strcasestr(path, "ono_hcb_") != nullptr ||
           strcasestr(path, "ono_bubble_cache") != nullptr ||
           strcasestr(path, "ono_image_tag") != nullptr ||
           strcasestr(path, "ono_need_find_method") != nullptr ||
           strcasestr(path, "moe.ono") != nullptr ||
           strcasestr(path, "/ONO") != nullptr ||
           strcasestr(path, "sesearchcache") != nullptr ||
           strcasestr(path, "files/.se") != nullptr ||
           strcasestr(path, ".se") != nullptr ||
           strcasestr(path, "kc.dat") != nullptr ||
           strcasestr(path, ".sys_cache") != nullptr ||
           strcasestr(path, "config/pz") != nullptr ||
           strcasestr(path, "libcnm") != nullptr ||
           strcasestr(path, "liball-jni") != nullptr;
}

static bool is_mt_private_path(const char* path) {
    if (!path || !path[0]) return false;
    return strcasestr(path, "bin.mt.") != nullptr ||
           strcasestr(path, "bin.mt") != nullptr ||
           strcasestr(path, "/MT2") != nullptr ||
           strcasestr(path, "/sdcard/MT2") != nullptr ||
           strcasestr(path, "/storage/emulated/0/MT2") != nullptr;
}

bool is_sensitive_path(const char* path) {
    if (!path) return false;
    const char* hidden[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/data/local/tmp/su", "/data/local/tmp/frida", "re.frida.server",
        "/system/xposed", "/data/adb",
        "libriru", "libzygisk",
        "Superuser.apk", "SuperSU.apk", "Magisk.apk",
        "/system/bin/install-recovery.sh", "/system/etc/install-recovery.sh",
        "/system/bin/debuggerd", "/system/bin/debuggerd64", "/system/bin/ddexe",
        "/sys/fs/selinux/enforce",
        "dexkit", "libdexkit", "flatbuffers", "sandhook", "yahfa",
        "epic", "pine", "taichi", "liblspd", "lsposed", "edxposed",
        "qqbypass", "libnative-bypass", "libbytehook", "xalsace",
        "zygisk_lsposed", "zygisksu",
        "top.nkbe.npatch", "npatch", "org.lsposed.manager", "lspilot",
        "bytehook", "native-bypass", "apatch", "fusehide", "simplehook",
        "libchecker", "shizuku", "vtools", "bin.mt", "bin.mt.plus", "bin.mt.termex",
        "thanos", "termux", "duckusb",
        "me.weishu.kernelsu", "me.bmax.apatch", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.noshufou.android.su", "com.kingroot.kinguser",
        "com.kingo.root", "com.smedialink.oneclickroot", "com.zhiqupk.root.global",
        "com.shuame.rootgenius", "com.applisto.appcloner", ".android_system_config.prop",
        "ku.sud", "shuamesu", "libbugly_shadowhook", "libshadowhook_nothing",
        "busybox", "sudo", "bdsu", "sutemp", ".su", "com.topjohnwu.magisk", "topjohnwu",
        "libqqPerfNativeTool", "libandroid_desensitization", "libshadowhook",
        "init.svc.microvirtd", "config.prop", "/.android",
        "/data/data/io.github.qauxv", "/data/user/0/io.github.qauxv",
        "mountify", "tricky_store", "metamodule", "ksud", "zygisksu",
        nullptr
    };
    for (int i = 0; hidden[i]; i++) {
        if (strcasestr(path, hidden[i])) return true;
    }
    return false;
}

static inline bool is_security_hidden_path(const char* path, void* return_address) {
    if (!path) return false;

    // 1. NEVER block installed APKs in /data/app/ (including QAuxiliary and system packages)
    if (strstr(path, "/data/app/")) {
        return false;
    }

    // 2. LSPatch private files & cache:
    // If called by Tencent security DSO, block it completely!
    if (strcasestr(path, "lspatch")) {
        if (is_caller_security_dso(return_address)) {
            return true;
        }
        if (is_caller_qa(return_address)) {
            return false;
        }
        // Direct probe of lspatch root folder in cache/files (not ART loading files in origin/)
        if ((strstr(path, "/cache/lspatch") && !strstr(path, "/cache/lspatch/origin/")) ||
            (strstr(path, "/files/lspatch") && !strstr(path, "/files/lspatch/origin/"))) {
            return true;
        }
        return false;
    }

    // 3. Sensitive root/xposed paths
    if (is_sensitive_path(path)) {
        if (is_caller_qa(return_address)) {
            return false;
        }
        return true;
    }

    // 4. MT Manager private paths
    if (is_mt_private_path(path)) {
        if (is_caller_qa(return_address)) {
            return false;
        }
        return true;
    }

    // 5. QAuxiliary private files (qa_mmkv, tmp_qa_, qa_dyn_lib, qa_misc):
    // Only block when called by Tencent security DSOs!
    // QA itself, MMKV, and Java runtime MUST have full access!
    // Directory scans (readdir/getdents64) already hide these from general scans!
    if (is_qa_private_path(path)) {
        if (is_caller_security_dso(return_address)) {
            return true;
        }
        if (is_caller_qa(return_address)) {
            return false;
        }
        return false;
    }

    return false;
}

static bool is_sensitive_name_for_caller(const char* name, void* return_address) {
    if (!name || !name[0]) return false;
    // CRITICAL: Module callers must have full access to their own files and configs!
    if (is_caller_qa(return_address)) {
        return false;
    }
    if (strcmp(name, "su") == 0 ||
        strcmp(name, "magisk") == 0 ||
        strcmp(name, "magiskd") == 0 ||
        strcmp(name, "ksud") == 0 ||
        strcmp(name, "daemonsu") == 0 ||
        strcmp(name, "supersu") == 0 ||
        strcmp(name, "superuser") == 0 ||
        strcmp(name, "busybox") == 0 ||
        strcmp(name, "sudo") == 0 ||
        strcmp(name, "bdsu") == 0 ||
        strcmp(name, "sutemp") == 0 ||
        strcmp(name, "shuamesu") == 0 ||
        strcmp(name, "ku.sud") == 0) {
        return true;
    }
    const char* root_patterns[] = {
        "magisk", "lsposed", "xposed", "edxposed", "dexkit",
        "sandhook", "yahfa", "epic", "pine", "taichi",
        "liblspd", "qqbypass", "native-bypass", "bytehook",
        "shamiko", "apatch", "npatch", "lspilot", "fusehide",
        "simplehook", "libchecker", "shizuku", "vtools",
        "bin.mt", "mt2", "singleneuron", "bytebuddy",
        "thanos", "termux", "duckusb", "lspatch",
        "org.lsposed.lspatch", "moe.ono", "ono_mmkv", "ono_hcb_",
        "ono_bubble_cache", "ono_image_tag", "ono_need_find_method", "ONO",
        "lzlnb", "libcnm", "liball-jni", "cnm0",
        "sesearchcache", "kc.dat", ".se", ".sys_cache",
        "global_config", "oat_inline_deopt_cache", "last_use_emoticon_time",
        "sDumpTG_", "qauxv", "qa_mmkv", "tmp_qa_", "qnotified",
        "kernelsu", "apatch", "supersu", "superuser", "kingroot", "kinguser",
        "oneclickroot", "rootgenius", "shuamesu", "appcloner", "microvirtd",
        "bdsu", "sutemp", "sudo", "config.prop", "init.svc.microvirtd",
        nullptr
    };
    for (int i = 0; root_patterns[i]; i++) {
        if (strcasestr(name, root_patterns[i])) return true;
    }

    if (is_qa_private_path(name)) {
        return true;
    }
    return false;
}

bool is_sensitive_name(const char* name) {
    return is_sensitive_name_for_caller(name, nullptr);
}

static bool is_root_pid(const char* pid_str) {
    if (!pid_str || !pid_str[0]) return false;
    // Check comm
    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", pid_str);
    int fd = -1;
    if (real_open_ptr) fd = real_open_ptr(comm_path, O_RDONLY, 0);
    else fd = open(comm_path, O_RDONLY);
    if (fd >= 0) {
        char buf[128];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            if (buf[n - 1] == '\n') buf[n - 1] = '\0';
            if (strcmp(buf, "magiskd") == 0 || strcmp(buf, "ksud") == 0 ||
                strcmp(buf, "su") == 0 || strcmp(buf, "daemonsu") == 0 ||
                strcmp(buf, "frida-server") == 0 ||
                strstr(buf, "bin.mt") || strstr(buf, "mt.plus") ||
                strstr(buf, "qauxv") || strstr(buf, "lsposed") ||
                strstr(buf, "lspatch") || strstr(buf, "moe.ono") ||
                strstr(buf, "lzlnb") || strstr(buf, "npatch")) {
                return true;
            }
        }
    }
    // Check cmdline
    char cmd_path[64];
    snprintf(cmd_path, sizeof(cmd_path), "/proc/%s/cmdline", pid_str);
    if (real_open_ptr) fd = real_open_ptr(cmd_path, O_RDONLY, 0);
    else fd = open(cmd_path, O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            if (strstr(buf, "bin.mt") || strstr(buf, "io.github.qauxv") ||
                strstr(buf, "org.lsposed.manager") || strstr(buf, "top.nkbe.npatch") ||
                strstr(buf, "magisk") || strstr(buf, "ksud") || strstr(buf, "daemonsu") ||
                strstr(buf, "lspatch") || strstr(buf, "moe.ono") || strstr(buf, "lzlnb")) {
                return true;
            }
        }
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
        "zygisk_lsposed", "zygisksu", "/data/adb",
        "bin.mt.", "bin.mt.plus", "bin.mt.manager", "bin.mt.termex", "MT2",
        "top.nkbe.npatch", "npatch", "org.lsposed.manager", "lspilot",
        "bytehook", "trampoline", "native-bypass", "apatch", "libxposed",
        "fusehide", "simplehook", "libchecker", "shizuku", "vtools", "thanos", "termux",
        "qauxv", "io.github.qauxv", "libqauxv", "libqauxv-core0", "libqauxv-core1",
        "cc.ioctl", "qnotified", "bytebuddy", "net.bytebuddy", "singleneuron", "timeline",
        "qa_mmkv", "qa_dyn_lib", "tmp_qa_",
        "lspatch", "liblspatch", "org.lsposed.lspatch",
        "moe.ono", "ono_mmkv", "ono_hcb_",
        "lzlnb", "libcnm", "liball-jni", "cnm0",
        "sesearchcache", "kc.dat", ".se",
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

// 构造过滤掉 hook 特征库与 rwxp 蹦床的 smaps 临时文件
FILE* build_filtered_smaps() {
    ensure_real_funcs();
    if (!real_fopen_ptr || !real_fgets_ptr) return nullptr;

    FILE* real = real_fopen_ptr("/proc/self/smaps", "r");
    if (!real) real = real_fopen_ptr("/proc/self/maps", "r");
    if (!real) return nullptr;

    FILE* fake = create_memory_file("smaps");
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
        "zygisk_lsposed", "zygisksu", "/data/adb",
        "bin.mt.", "bin.mt.plus", "bin.mt.manager", "bin.mt.termex", "MT2",
        "top.nkbe.npatch", "npatch", "org.lsposed.manager", "lspilot",
        "bytehook", "trampoline", "native-bypass", "apatch", "libxposed",
        "fusehide", "simplehook", "libchecker", "shizuku", "vtools", "thanos", "termux",
        "qauxv", "io.github.qauxv", "libqauxv", "libqauxv-core0", "libqauxv-core1",
        "cc.ioctl", "qnotified", "bytebuddy", "net.bytebuddy", "singleneuron", "timeline",
        "qa_mmkv", "qa_dyn_lib", "tmp_qa_",
        "lspatch", "liblspatch", "org.lsposed.lspatch",
        "moe.ono", "ono_mmkv", "ono_hcb_",
        "lzlnb", "libcnm", "liball-jni", "cnm0",
        "sesearchcache", "kc.dat", ".se",
        nullptr
    };

    bool filtering_current_block = false;
    while (real_fgets_ptr(line, sizeof(line), real)) {
        char* dash = strchr(line, '-');
        if (dash && (strstr(line, " r") || strstr(line, " -"))) {
            filtering_current_block = false;
            for (int i = 0; blacklist[i]; i++) {
                if (strcasestr(line, blacklist[i])) {
                    filtering_current_block = true;
                    break;
                }
            }
            if (!filtering_current_block && strstr(line, "rwxp") && strstr(line, "[anon:") && !strstr(line, "dalvik")) {
                filtering_current_block = true;
            }
        }

        if (!filtering_current_block) {
            fputs(line, fake);
        }
    }
    fclose(real);
    rewind(fake);
    return fake;
}

// 构造过滤掉 root / magisk / loop 挂载点的 mounts 临时文件
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
        "/dev/block/loop", "magisk", "core/mirror", "core/img", "/data/adb",
        "modules", "ksu", "apatch", "overlay", "lsposed", "lspatch",
        "moe.ono", "ono_mmkv", "lzlnb", "cnm",
        "mountify", "tricky_store", "metamodule", "ksud", "zygisksu",
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

// 构造过滤掉 root / loop 设备 / 模块 / overlay 挂载的 mountinfo 虚拟文件
FILE* build_filtered_mountinfo() {
    ensure_real_funcs();
    if (!real_fopen_ptr || !real_fgets_ptr) return nullptr;

    FILE* real = real_fopen_ptr("/proc/self/mountinfo", "r");
    if (!real) real = real_fopen_ptr("/proc/mountinfo", "r");
    if (!real) return nullptr;

    FILE* fake = create_memory_file("mountinfo");
    if (!fake) {
        fclose(real);
        return nullptr;
    }

    char line[2048];
    const char* blacklist[] = {
        "/dev/block/loop", "magisk", "core/mirror", "core/img", "/data/adb",
        "modules", "ksu", "apatch", "overlay", "lsposed", "lspatch",
        "moe.ono", "ono_mmkv", "lzlnb", "cnm",
        "mountify", "tricky_store", "metamodule", "ksud", "zygisksu",
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

// 构造过滤掉 Xposed / LSPosed / Zygisk / Magisk / KernelSU unix domain socket 的 net/unix 虚拟文件
FILE* build_filtered_net_unix() {
    ensure_real_funcs();
    if (!real_fopen_ptr || !real_fgets_ptr) return nullptr;

    FILE* real = real_fopen_ptr("/proc/net/unix", "r");
    if (!real) return nullptr;

    FILE* fake = create_memory_file("net_unix");
    if (!fake) {
        fclose(real);
        return nullptr;
    }

    char line[1024];
    const char* blacklist[] = {
        "lsp", "lspbridge", "lsp_dex2oat", "lsposed", "xposed",
        "zn_", "zygisk", "magisk", "ksu", "ksud", "apatch", "daemonsu",
        "qauxv", "ono", "lzlnb", "cnm", "frida", "mountify", "tricky_store",
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

static bool is_proc_net_unix_path(const char* path) {
    if (!path) return false;
    return (strcmp(path, "/proc/net/unix") == 0 ||
            strcmp(path, "/proc/self/net/unix") == 0 ||
            strcmp(path, "/proc/thread-self/net/unix") == 0 ||
            (strncmp(path, "/proc/", 6) == 0 && strstr(path, "/net/unix")));
}

// 构造沙箱默认 SELinux context 虚拟文件，防止 Turing 检测到 permissive 或 root domain
FILE* build_filtered_selinux_attr() {
    FILE* fake = create_memory_file("attr_current");
    if (!fake) return nullptr;
    fputs("u:r:untrusted_app:s0:c512,c768\n", fake);
    rewind(fake);
    return fake;
}

static bool is_proc_mountinfo_path(const char* path) {
    if (!path) return false;
    return (strcmp(path, "/proc/self/mountinfo") == 0 ||
            strcmp(path, "/proc/thread-self/mountinfo") == 0 ||
            (strncmp(path, "/proc/", 6) == 0 && strstr(path, "/mountinfo")));
}

static bool is_proc_mounts_path(const char* path) {
    if (!path) return false;
    return (strcmp(path, "/proc/mounts") == 0 ||
            strcmp(path, "/proc/self/mounts") == 0 ||
            strcmp(path, "/proc/thread-self/mounts") == 0 ||
            (strncmp(path, "/proc/", 6) == 0 && strstr(path, "/mounts")));
}

static bool is_proc_attr_current_path(const char* path) {
    if (!path) return false;
    return (strcmp(path, "/proc/self/attr/current") == 0 ||
            strcmp(path, "/proc/thread-self/attr/current") == 0 ||
            (strncmp(path, "/proc/", 6) == 0 && strstr(path, "/attr/current")));
}

static bool is_proc_cgroup_path(const char* path) {
    if (!path) return false;
    return (strcmp(path, "/proc/self/cgroup") == 0 ||
            strcmp(path, "/proc/thread-self/cgroup") == 0 ||
            (strncmp(path, "/proc/", 6) == 0 && strstr(path, "/cgroup")));
}

static bool is_sensitive_prop_name(const char* name) {
    if (!name) return false;
    const char* props[] = {
        "magisk", "ksu", "apatch", "microvirtd",
        ".android_system_config.prop",
        "vbox", "qemu", "goldfish", "nox",
        "genymotion", "bluestacks", "bignox",
        "droid4x", "andy", "ttVM", nullptr
    };
    for (int i = 0; props[i]; i++) {
        if (strcasestr(name, props[i])) return true;
    }
    return false;
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

// 构造过滤掉 container/docker/root/termux 标志的 cgroup 虚拟文件
FILE* build_filtered_cgroup() {
    ensure_real_funcs();
    if (!real_fopen_ptr || !real_fgets_ptr) return nullptr;

    FILE* real = real_fopen_ptr("/proc/self/cgroup", "r");
    if (!real) return nullptr;

    FILE* fake = create_memory_file("cgroup");
    if (!fake) {
        fclose(real);
        return nullptr;
    }

    char line[512];
    const char* blacklist[] = {
        "termux", "docker", "lxc", "container", "magisk", "root", "daemon",
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

// ==================== 统一 Hook 实现 ====================

FILE* fake_fopen(const char* pathname, const char* mode) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();

    if (is_security_hidden_path(pathname, __builtin_return_address(0))) {
        LOGD("Hidden path fopen: %s", pathname);
        errno = ENOENT;
        return nullptr;
    }

    if (pathname) {
        if (strncmp(pathname, "/proc/", 6) == 0) {
            const char* pid_start = pathname + 6;
            const char* slash = strchr(pid_start, '/');
            if (slash && pid_start[0] >= '0' && pid_start[0] <= '9') {
                char pid_buf[32];
                size_t pid_len = slash - pid_start;
                if (pid_len < sizeof(pid_buf)) {
                    memcpy(pid_buf, pid_start, pid_len);
                    pid_buf[pid_len] = '\0';
                    if (is_root_pid(pid_buf)) {
                        errno = ENOENT;
                        return nullptr;
                    }
                }
            }
        }
        if (strstr(pathname, "smaps")) {
            LOGI("Intercepted fopen smaps: %s", pathname);
            FILE* fake = build_filtered_smaps();
            if (fake) return fake;
        }
        else if (strcmp(pathname, "/proc/self/maps") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/maps"))) {
            LOGI("Intercepted fopen maps: %s", pathname);
            FILE* fake = build_filtered_maps();
            if (fake) return fake;
        }
        if (is_proc_mountinfo_path(pathname)) {
            LOGI("Intercepted fopen mountinfo: %s", pathname);
            FILE* fake = build_filtered_mountinfo();
            if (fake) return fake;
        }
        if (is_proc_mounts_path(pathname)) {
            LOGI("Intercepted fopen mounts: %s", pathname);
            FILE* fake = build_filtered_mounts();
            if (fake) return fake;
        }
        if (is_proc_net_unix_path(pathname)) {
            LOGI("Intercepted fopen net/unix: %s", pathname);
            FILE* fake = build_filtered_net_unix();
            if (fake) return fake;
        }
        if (is_proc_attr_current_path(pathname)) {
            LOGI("Intercepted fopen attr/current: %s", pathname);
            FILE* fake = build_filtered_selinux_attr();
            if (fake) return fake;
        }
        if (is_proc_cgroup_path(pathname)) {
            LOGI("Intercepted fopen cgroup: %s", pathname);
            FILE* fake = build_filtered_cgroup();
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

static char* fake_fgets_chk(char* s, int size, size_t buflen, FILE* stream) {
    SAFE_BYTEHOOK_SCOPE();
    (void)buflen;
    if (real_fgets_chk_ptr) return real_fgets_chk_ptr(s, size, buflen, stream);
    return fake_fgets(s, size, stream);
}

int fake_open(const char* pathname, int flags, ...) {
    SAFE_BYTEHOOK_SCOPE();

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (is_security_hidden_path(pathname, __builtin_return_address(0))) {
        LOGD("Hidden path open: %s", pathname);
        errno = ENOENT;
        return -1;
    }

    if (pathname) {
        if (strncmp(pathname, "/proc/", 6) == 0) {
            const char* pid_start = pathname + 6;
            const char* slash = strchr(pid_start, '/');
            if (slash && pid_start[0] >= '0' && pid_start[0] <= '9') {
                char pid_buf[32];
                size_t pid_len = slash - pid_start;
                if (pid_len < sizeof(pid_buf)) {
                    memcpy(pid_buf, pid_start, pid_len);
                    pid_buf[pid_len] = '\0';
                    if (is_root_pid(pid_buf)) {
                        errno = ENOENT;
                        return -1;
                    }
                }
            }
        }
        if (strstr(pathname, "smaps")) {
            LOGI("Intercepted open smaps: %s", pathname);
            FILE* fake = build_filtered_smaps();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        else if (strcmp(pathname, "/proc/self/maps") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/maps"))) {
            LOGI("Intercepted open maps: %s", pathname);
            FILE* fake = build_filtered_maps();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (is_proc_mountinfo_path(pathname)) {
            LOGI("Intercepted open mountinfo: %s", pathname);
            FILE* fake = build_filtered_mountinfo();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (is_proc_mounts_path(pathname)) {
            LOGI("Intercepted open mounts: %s", pathname);
            FILE* fake = build_filtered_mounts();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (is_proc_net_unix_path(pathname)) {
            LOGI("Intercepted open net/unix: %s", pathname);
            FILE* fake = build_filtered_net_unix();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (is_proc_attr_current_path(pathname)) {
            LOGI("Intercepted open attr/current: %s", pathname);
            FILE* fake = build_filtered_selinux_attr();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (is_proc_cgroup_path(pathname)) {
            LOGI("Intercepted open cgroup: %s", pathname);
            FILE* fake = build_filtered_cgroup();
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

int fake_openat(int dirfd, const char* pathname, int flags, ...) {
    SAFE_BYTEHOOK_SCOPE();

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (is_security_hidden_path(pathname, __builtin_return_address(0))) {
        LOGD("Hidden path openat: %s", pathname);
        errno = ENOENT;
        return -1;
    }

    if (pathname) {
        if (strncmp(pathname, "/proc/", 6) == 0) {
            const char* pid_start = pathname + 6;
            const char* slash = strchr(pid_start, '/');
            if (slash && pid_start[0] >= '0' && pid_start[0] <= '9') {
                char pid_buf[32];
                size_t pid_len = slash - pid_start;
                if (pid_len < sizeof(pid_buf)) {
                    memcpy(pid_buf, pid_start, pid_len);
                    pid_buf[pid_len] = '\0';
                    if (is_root_pid(pid_buf)) {
                        errno = ENOENT;
                        return -1;
                    }
                }
            }
        }
        if (strstr(pathname, "smaps")) {
            LOGI("Intercepted openat smaps: %s", pathname);
            FILE* fake = build_filtered_smaps();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        else if (strcmp(pathname, "/proc/self/maps") == 0 ||
            (strstr(pathname, "/proc/") && strstr(pathname, "/maps"))) {
            LOGI("Intercepted openat maps: %s", pathname);
            FILE* fake = build_filtered_maps();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (is_proc_mountinfo_path(pathname)) {
            LOGI("Intercepted openat mountinfo: %s", pathname);
            FILE* fake = build_filtered_mountinfo();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (is_proc_mounts_path(pathname)) {
            LOGI("Intercepted openat mounts: %s", pathname);
            FILE* fake = build_filtered_mounts();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (is_proc_net_unix_path(pathname)) {
            LOGI("Intercepted openat net/unix: %s", pathname);
            FILE* fake = build_filtered_net_unix();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (is_proc_attr_current_path(pathname)) {
            LOGI("Intercepted openat attr/current: %s", pathname);
            FILE* fake = build_filtered_selinux_attr();
            if (fake) {
                int fd = dup(fileno(fake));
                fclose(fake);
                return fd;
            }
        }
        if (is_proc_cgroup_path(pathname)) {
            LOGI("Intercepted openat cgroup: %s", pathname);
            FILE* fake = build_filtered_cgroup();
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

static int fake_open_2(const char* pathname, int flags) {
    return fake_open(pathname, flags, 0);
}

static int fake_openat_2(int dirfd, const char* pathname, int flags) {
    return fake_openat(dirfd, pathname, flags, 0);
}

DIR* fake_opendir(const char* name) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    if (is_security_hidden_path(name, __builtin_return_address(0))) {
        LOGD("Hidden opendir: %s", name);
        errno = ENOENT;
        return nullptr;
    }
    if (real_opendir_ptr) return real_opendir_ptr(name);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_opendir, name);
    return opendir(name);
}

struct dirent* fake_readdir(DIR* dirp) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    void* ret_addr = __builtin_return_address(0);
    struct dirent* entry = nullptr;
    while (true) {
        if (real_readdir_ptr) entry = real_readdir_ptr(dirp);
        else if (g_bytehook_hooks_installed) entry = BYTEHOOK_CALL_PREV(fake_readdir, dirp);
        else entry = readdir(dirp);

        if (!entry) break;

        if (is_sensitive_name_for_caller(entry->d_name, ret_addr)) {
            continue;
        }
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
            if (is_root_pid(entry->d_name)) {
                continue;
            }
        }
        break;
    }
    return entry;
}

static struct dirent64* fake_readdir64(DIR* dirp) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    void* ret_addr = __builtin_return_address(0);
    struct dirent64* entry = nullptr;
    while (true) {
        if (real_readdir64_ptr) entry = real_readdir64_ptr(dirp);
        else if (g_bytehook_hooks_installed) entry = BYTEHOOK_CALL_PREV(fake_readdir64, dirp);
        else entry = readdir64(dirp);

        if (!entry) break;

        if (is_sensitive_name_for_caller(entry->d_name, ret_addr)) {
            continue;
        }
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
            if (is_root_pid(entry->d_name)) {
                continue;
            }
        }
        break;
    }
    return entry;
}

static int fake_readdir_r(DIR* dirp, struct dirent* entry, struct dirent** result) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    void* ret_addr = __builtin_return_address(0);
    while (true) {
        int ret = 0;
        if (real_readdir_r_ptr) ret = real_readdir_r_ptr(dirp, entry, result);
        else if (g_bytehook_hooks_installed) ret = BYTEHOOK_CALL_PREV(fake_readdir_r, dirp, entry, result);
        else ret = readdir_r(dirp, entry, result);

        if (ret != 0 || !result || !*result) return ret;

        if (is_sensitive_name_for_caller((*result)->d_name, ret_addr)) {
            continue;
        }
        if ((*result)->d_name[0] >= '0' && (*result)->d_name[0] <= '9') {
            if (is_root_pid((*result)->d_name)) {
                continue;
            }
        }
        return 0;
    }
}

static int fake_readdir64_r(DIR* dirp, struct dirent64* entry, struct dirent64** result) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    void* ret_addr = __builtin_return_address(0);
    while (true) {
        int ret = 0;
        if (real_readdir64_r_ptr) ret = real_readdir64_r_ptr(dirp, entry, result);
        else if (g_bytehook_hooks_installed) ret = BYTEHOOK_CALL_PREV(fake_readdir64_r, dirp, entry, result);
        else ret = readdir64_r(dirp, entry, result);

        if (ret != 0 || !result || !*result) return ret;

        if (is_sensitive_name_for_caller((*result)->d_name, ret_addr)) {
            continue;
        }
        if ((*result)->d_name[0] >= '0' && (*result)->d_name[0] <= '9') {
            if (is_root_pid((*result)->d_name)) {
                continue;
            }
        }
        return 0;
    }
}

static ssize_t sanitize_readlink_buffer(char* buf, size_t bufsiz, ssize_t ret) {
    if (ret <= 0 || !buf || (size_t)ret >= bufsiz) return ret;
    buf[ret] = '\0';
    if (strstr(buf, "memfd:maps")) {
        const char* rep = "/proc/self/maps";
        size_t rlen = strlen(rep);
        if (bufsiz > rlen) {
            strncpy(buf, rep, bufsiz);
            return rlen;
        }
    } else if (strstr(buf, "memfd:smaps")) {
        const char* rep = "/proc/self/smaps";
        size_t rlen = strlen(rep);
        if (bufsiz > rlen) {
            strncpy(buf, rep, bufsiz);
            return rlen;
        }
    } else if (strstr(buf, "memfd:status")) {
        const char* rep = "/proc/self/status";
        size_t rlen = strlen(rep);
        if (bufsiz > rlen) {
            strncpy(buf, rep, bufsiz);
            return rlen;
        }
    } else if (strstr(buf, "memfd:mounts")) {
        const char* rep = "/proc/mounts";
        size_t rlen = strlen(rep);
        if (bufsiz > rlen) {
            strncpy(buf, rep, bufsiz);
            return rlen;
        }
    } else if (strstr(buf, "memfd:mountinfo")) {
        const char* rep = "/proc/self/mountinfo";
        size_t rlen = strlen(rep);
        if (bufsiz > rlen) {
            strncpy(buf, rep, bufsiz);
            return rlen;
        }
    } else if (strstr(buf, "memfd:attr_current")) {
        const char* rep = "/proc/self/attr/current";
        size_t rlen = strlen(rep);
        if (bufsiz > rlen) {
            strncpy(buf, rep, bufsiz);
            return rlen;
        }
    } else if (strstr(buf, "memfd:wchan")) {
        const char* rep = "/proc/self/wchan";
        size_t rlen = strlen(rep);
        if (bufsiz > rlen) {
            strncpy(buf, rep, bufsiz);
            return rlen;
        }
    } else if (strstr(buf, "memfd:cgroup")) {
        const char* rep = "/proc/self/cgroup";
        size_t rlen = strlen(rep);
        if (bufsiz > rlen) {
            strncpy(buf, rep, bufsiz);
            return rlen;
        }
    }
    return ret;
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

    if (is_security_hidden_path(pathname, __builtin_return_address(0))) {
        errno = ENOENT;
        return -1;
    }

    ssize_t ret;
    if (real_readlink_ptr) ret = real_readlink_ptr(pathname, buf, bufsiz);
    else if (g_bytehook_hooks_installed) ret = BYTEHOOK_CALL_PREV(fake_readlink, pathname, buf, bufsiz);
    else ret = (ssize_t)syscall(__NR_readlinkat, AT_FDCWD, pathname, buf, bufsiz);

    return sanitize_readlink_buffer(buf, bufsiz, ret);
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

    if (is_security_hidden_path(pathname, __builtin_return_address(0))) {
        errno = ENOENT;
        return -1;
    }

    ssize_t ret;
    if (real_readlinkat_ptr) ret = real_readlinkat_ptr(dirfd, pathname, buf, bufsiz);
    else if (g_bytehook_hooks_installed) ret = BYTEHOOK_CALL_PREV(fake_readlinkat, dirfd, pathname, buf, bufsiz);
    else ret = (ssize_t)syscall(__NR_readlinkat, dirfd, pathname, buf, bufsiz);

    return sanitize_readlink_buffer(buf, bufsiz, ret);
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
            "lsposed", "dexkit", "libdexkit",
            "lspatch", "liblspatch", "libriru", "libzygisk",
            "libapatch", "liball-jni", "moe.ono", "libcnm",
            "substrate", "cydia", "xposed", nullptr
        };
        for (int i = 0; hidden[i]; i++) {
            if (strcasestr(info->dli_fname, hidden[i])) {
                LOGD("Hidden dladdr library: %s", info->dli_fname);
                info->dli_fname = "/system/lib64/libc.so";
                info->dli_fbase = nullptr;
                info->dli_sname = nullptr;
                info->dli_saddr = nullptr;
                return result;
            }
        }
        const char* qa_mt_hidden[] = {
            "libqauxv", "libqauxv-core0", "libqauxv-core1", "qauxv",
            "bin.mt", "npatch", "bytebuddy", "lspilot", nullptr
        };
        for (int i = 0; qa_mt_hidden[i]; i++) {
            if (strcasestr(info->dli_fname, qa_mt_hidden[i])) {
                if (!is_caller_qa(__builtin_return_address(0))) {
                    LOGD("Hidden dladdr QA/MT library: %s", info->dli_fname);
                    info->dli_fname = "/system/lib64/libc.so";
                    info->dli_fbase = nullptr;
                    info->dli_sname = nullptr;
                    info->dli_saddr = nullptr;
                    return result;
                }
            }
        }
        if (is_caller_security_dso(__builtin_return_address(0))) {
            const char* sec_hidden[] = {
                "libbugly_shadowhook", "libshadowhook", "librmonitor_base",
                "librmonitor", "libqqPerfNativeTool", "libandroid_desensitization",
                "librmonitor_memory", "libBugly-rqd", "libBugly_Native", "libBugly",
                nullptr
            };
            for (int i = 0; sec_hidden[i]; i++) {
                if (strcasestr(info->dli_fname, sec_hidden[i])) {
                    LOGD("Hidden dladdr security library for security DSO caller: %s", info->dli_fname);
                    info->dli_fname = "/system/lib64/libc.so";
                    info->dli_fbase = nullptr;
                    info->dli_sname = nullptr;
                    info->dli_saddr = nullptr;
                    return result;
                }
            }
        }
    }
    return result;
}

struct dl_iterate_cookie {
    int (*callback)(struct dl_phdr_info*, size_t, void*);
    void* data;
    void* caller_addr;
};

static int dl_iterate_callback_wrapper(struct dl_phdr_info* info, size_t size, void* data) {
    auto* cookie = static_cast<dl_iterate_cookie*>(data);
    if (info && info->dlpi_name) {
        const char* hidden[] = {
            "libnative-bypass", "libbytehook", "xalsace",
            "lsposed", "dexkit", "libdexkit",
            "lspatch", "liblspatch", "libriru", "libzygisk",
            "libapatch", "liball-jni", "moe.ono", "libcnm",
            "substrate", "cydia", "xposed", nullptr
        };
        for (int i = 0; hidden[i]; i++) {
            if (strcasestr(info->dlpi_name, hidden[i])) {
                LOGD("Hidden library in dl_iterate_phdr: %s", info->dlpi_name);
                return 0; // 跳过此条目
            }
        }
        const char* qa_mt_hidden[] = {
            "libqauxv", "libqauxv-core0", "libqauxv-core1", "qauxv",
            "bin.mt", "npatch", "bytebuddy", "lspilot", nullptr
        };
        for (int i = 0; qa_mt_hidden[i]; i++) {
            if (strcasestr(info->dlpi_name, qa_mt_hidden[i])) {
                if (!is_caller_qa(cookie->caller_addr)) {
                    LOGD("Hidden QA/MT library in dl_iterate_phdr: %s", info->dlpi_name);
                    return 0;
                }
            }
        }
        if (is_caller_security_dso(cookie->caller_addr)) {
            const char* sec_hidden[] = {
                "libbugly_shadowhook", "libshadowhook", "librmonitor_base",
                "librmonitor", "libqqPerfNativeTool", "libandroid_desensitization",
                "librmonitor_memory", "libBugly-rqd", "libBugly_Native", "libBugly",
                nullptr
            };
            for (int i = 0; sec_hidden[i]; i++) {
                if (strcasestr(info->dlpi_name, sec_hidden[i])) {
                    LOGD("Hidden security library in dl_iterate_phdr: %s", info->dlpi_name);
                    return 0;
                }
            }
        }
    }
    return cookie->callback(info, size, cookie->data);
}

static int fake_dl_iterate_phdr(int (*callback)(struct dl_phdr_info*, size_t, void*), void* data) {
    SAFE_BYTEHOOK_SCOPE();
    dl_iterate_cookie cookie{callback, data, __builtin_return_address(0)};
    if (real_dl_iterate_phdr_ptr) return real_dl_iterate_phdr_ptr(dl_iterate_callback_wrapper, &cookie);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_dl_iterate_phdr, dl_iterate_callback_wrapper, &cookie);
    return dl_iterate_phdr(dl_iterate_callback_wrapper, &cookie);
}

int fake_access(const char* pathname, int mode) {
    SAFE_BYTEHOOK_SCOPE();
    if (is_security_hidden_path(pathname, __builtin_return_address(0))) {
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
    if (is_security_hidden_path(pathname, __builtin_return_address(0))) {
        LOGD("Hidden path faccessat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    if (real_faccessat_ptr) return real_faccessat_ptr(dirfd, pathname, mode, flags);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_faccessat, dirfd, pathname, mode, flags);
    return (int)syscall(__NR_faccessat, dirfd, pathname, mode, flags);
}

int fake_stat(const char* pathname, struct stat* statbuf) {
    SAFE_BYTEHOOK_SCOPE();
    if (is_security_hidden_path(pathname, __builtin_return_address(0))) {
        LOGD("Hidden path stat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    if (real_stat_ptr) return real_stat_ptr(pathname, statbuf);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_stat, pathname, statbuf);
    return (int)syscall(__NR_newfstatat, AT_FDCWD, pathname, statbuf, 0);
}

int fake_lstat(const char* pathname, struct stat* statbuf) {
    SAFE_BYTEHOOK_SCOPE();
    if (is_security_hidden_path(pathname, __builtin_return_address(0))) {
        LOGD("Hidden path lstat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    if (real_lstat_ptr) return real_lstat_ptr(pathname, statbuf);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_lstat, pathname, statbuf);
    return (int)syscall(__NR_newfstatat, AT_FDCWD, pathname, statbuf, AT_SYMLINK_NOFOLLOW);
}

int fake_fstatat(int dirfd, const char* pathname, struct stat* statbuf, int flags) {
    SAFE_BYTEHOOK_SCOPE();
    if (is_security_hidden_path(pathname, __builtin_return_address(0))) {
        LOGD("Hidden path fstatat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    if (real_fstatat_ptr) return real_fstatat_ptr(dirfd, pathname, statbuf, flags);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_fstatat, dirfd, pathname, statbuf, flags);
    return (int)syscall(__NR_newfstatat, dirfd, pathname, statbuf, flags);
}

int fake_system_property_get(const char* name, char* value) {
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
    if (strcmp(name, "ro.boot.vbmeta.device_state") == 0) {
        strcpy(value, "locked");
        return strlen("locked");
    }
    if (strcmp(name, "ro.boot.verifiedbootstate") == 0) {
        strcpy(value, "green");
        return strlen("green");
    }
    if (strcmp(name, "persist.sys.adb.engineermode") == 0) {
        strcpy(value, "0");
        return 1;
    }
    if (strcmp(name, "sys.usb.config") == 0 || strcmp(name, "sys.usb.state") == 0 || strcmp(name, "persist.sys.usb.config") == 0) {
        strcpy(value, "none");
        return strlen("none");
    }
    if (strcmp(name, "init.svc.adbd") == 0) {
        strcpy(value, "stopped");
        return strlen("stopped");
    }
    if (is_sensitive_prop_name(name)) {
        value[0] = '\0';
        return 0;
    }
    if (real_system_property_get_ptr) return real_system_property_get_ptr(name, value);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_system_property_get, name, value);
    return __system_property_get(name, value);
}

const prop_info* fake_system_property_find(const char* name) {
    SAFE_BYTEHOOK_SCOPE();
    if (name) {
        if (is_sensitive_prop_name(name)) {
            return nullptr;
        }
    }
    if (real_system_property_find_ptr) return real_system_property_find_ptr(name);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_system_property_find, name);
    return __system_property_find(name);
}

struct PropCallbackCookie {
    void (*orig_callback)(void* cookie, const char* name, const char* value, uint32_t serial);
    void* orig_cookie;
};

static void prop_read_callback_wrapper(void* cookie, const char* name, const char* value, uint32_t serial) {
    auto* pcc = static_cast<PropCallbackCookie*>(cookie);
    if (!name || !value) {
        if (pcc && pcc->orig_callback) pcc->orig_callback(pcc->orig_cookie, name, value, serial);
        return;
    }
    const char* spoof_val = value;
    if (strcmp(name, "ro.debuggable") == 0) spoof_val = "0";
    else if (strcmp(name, "ro.secure") == 0) spoof_val = "1";
    else if (strcmp(name, "ro.build.tags") == 0) spoof_val = "release-keys";
    else if (strcmp(name, "ro.boot.flash.locked") == 0) spoof_val = "1";
    else if (strcmp(name, "ro.boot.vbmeta.device_state") == 0) spoof_val = "locked";
    else if (strcmp(name, "ro.boot.verifiedbootstate") == 0) spoof_val = "green";
    else if (strcmp(name, "persist.sys.adb.engineermode") == 0) spoof_val = "0";
    else if (strcmp(name, "sys.usb.config") == 0 || strcmp(name, "sys.usb.state") == 0 || strcmp(name, "persist.sys.usb.config") == 0) spoof_val = "none";
    else if (strcmp(name, "init.svc.adbd") == 0) spoof_val = "stopped";
    else if (is_sensitive_prop_name(name)) spoof_val = "";

    if (pcc && pcc->orig_callback) {
        pcc->orig_callback(pcc->orig_cookie, name, spoof_val, serial);
    }
}

static void fake_system_property_read_callback(const prop_info* pi, void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial), void* cookie) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    PropCallbackCookie pcc{callback, cookie};
    if (real_system_property_read_callback_ptr) {
        real_system_property_read_callback_ptr(pi, prop_read_callback_wrapper, &pcc);
    } else if (g_bytehook_hooks_installed) {
        BYTEHOOK_CALL_PREV(fake_system_property_read_callback, pi, prop_read_callback_wrapper, &pcc);
    } else {
        typedef void (*pfn_read_cb)(const prop_info*, void (*)(void*, const char*, const char*, uint32_t), void*);
        pfn_read_cb fn = (pfn_read_cb)dlsym(RTLD_DEFAULT, "__system_property_read_callback");
        if (fn) fn(pi, prop_read_callback_wrapper, &pcc);
    }
}

int fake_system_property_read(const prop_info* pi, char* name, char* value) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    int ret = 0;
    if (real_system_property_read_ptr) {
        ret = real_system_property_read_ptr(pi, name, value);
    } else {
        typedef int (*pfn_read)(const prop_info*, char*, char*);
        pfn_read fn = (pfn_read)dlsym(RTLD_DEFAULT, "__system_property_read");
        if (fn) ret = fn(pi, name, value);
    }
    if (ret > 0 && name && value) {
        if (strcmp(name, "ro.debuggable") == 0) strcpy(value, "0");
        else if (strcmp(name, "ro.secure") == 0) strcpy(value, "1");
        else if (strcmp(name, "ro.build.tags") == 0) strcpy(value, "release-keys");
        else if (strcmp(name, "ro.boot.flash.locked") == 0) strcpy(value, "1");
        else if (strcmp(name, "ro.boot.vbmeta.device_state") == 0) strcpy(value, "locked");
        else if (strcmp(name, "ro.boot.verifiedbootstate") == 0) strcpy(value, "green");
        else if (strcmp(name, "persist.sys.adb.engineermode") == 0) strcpy(value, "0");
        else if (strcmp(name, "sys.usb.config") == 0 || strcmp(name, "sys.usb.state") == 0 || strcmp(name, "persist.sys.usb.config") == 0) strcpy(value, "none");
        else if (strcmp(name, "init.svc.adbd") == 0) strcpy(value, "stopped");
        else if (is_sensitive_prop_name(name)) value[0] = '\0';
    }
    return ret;
}

FILE* fake_popen(const char* command, const char* type) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    if (command) {
        if (strstr(command, "which su") || strstr(command, "which ksu") ||
            strstr(command, "which magisk") || strstr(command, "which apatch") ||
            strstr(command, "pm list packages") || strstr(command, "ls /data") ||
            strstr(command, "busybox")) {
            LOGI("fake_popen blocked command: %s", command);
            errno = ENOENT;
            return nullptr;
        }
        if (strstr(command, "getprop")) {
            if (strstr(command, "ro.build.tags")) {
                FILE* f = tmpfile();
                if (f) { fputs("release-keys\n", f); rewind(f); return f; }
            }
            if (strstr(command, "ro.debuggable")) {
                FILE* f = tmpfile();
                if (f) { fputs("0\n", f); rewind(f); return f; }
            }
            if (strstr(command, "ro.secure")) {
                FILE* f = tmpfile();
                if (f) { fputs("1\n", f); rewind(f); return f; }
            }
            if (strstr(command, "sys.usb.config")) {
                FILE* f = tmpfile();
                if (f) { fputs("none\n", f); rewind(f); return f; }
            }
        }
        if (strstr(command, "mount")) {
            LOGI("fake_popen mount redirected");
            return build_filtered_mounts();
        }
    }
    if (real_popen_ptr) return real_popen_ptr(command, type);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_popen, command, type);
    return popen(command, type);
}

int fake_pclose(FILE* stream) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    if (real_pclose_ptr) {
        int ret = real_pclose_ptr(stream);
        if (ret == -1 && errno == ECHILD) {
            fclose(stream);
            return 0;
        }
        return ret;
    }
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_pclose, stream);
    return pclose(stream);
}

int fake_statfs(const char* path, struct statfs* buf) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    int ret = 0;
    if (real_statfs_ptr) ret = real_statfs_ptr(path, buf);
    else if (g_bytehook_hooks_installed) ret = BYTEHOOK_CALL_PREV(fake_statfs, path, buf);
    else ret = statfs(path, buf);
    if (ret == 0 && buf) {
        if (buf->f_type == 0x794c7630) {
            buf->f_type = 0xef53;
        }
        if (path && (strncmp(path, "/system", 7) == 0 || strncmp(path, "/vendor", 7) == 0)) {
            buf->f_flags |= ST_RDONLY;
        }
    }
    return ret;
}

static int fake_statfs64(const char* path, struct statfs64* buf) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    int ret = 0;
    if (real_statfs64_ptr) ret = real_statfs64_ptr(path, buf);
    else if (g_bytehook_hooks_installed) ret = BYTEHOOK_CALL_PREV(fake_statfs64, path, buf);
    else ret = statfs64(path, buf);
    if (ret == 0 && buf) {
        if (buf->f_type == 0x794c7630) {
            buf->f_type = 0xef53;
        }
        if (path && (strncmp(path, "/system", 7) == 0 || strncmp(path, "/vendor", 7) == 0)) {
            buf->f_flags |= ST_RDONLY;
        }
    }
    return ret;
}

static int fake_fstatfs(int fd, struct statfs* buf) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    int ret = 0;
    if (real_fstatfs_ptr) ret = real_fstatfs_ptr(fd, buf);
    else if (g_bytehook_hooks_installed) ret = BYTEHOOK_CALL_PREV(fake_fstatfs, fd, buf);
    else ret = fstatfs(fd, buf);
    if (ret == 0 && buf) {
        if (buf->f_type == 0x794c7630) {
            buf->f_type = 0xef53;
        }
    }
    return ret;
}

static int fake_fstatfs64(int fd, struct statfs64* buf) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    int ret = 0;
    if (real_fstatfs64_ptr) ret = real_fstatfs64_ptr(fd, buf);
    else if (g_bytehook_hooks_installed) ret = BYTEHOOK_CALL_PREV(fake_fstatfs64, fd, buf);
    else ret = fstatfs64(fd, buf);
    if (ret == 0 && buf) {
        if (buf->f_type == 0x794c7630) {
            buf->f_type = 0xef53;
        }
    }
    return ret;
}

static int fake_uname(struct utsname* buf) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    int ret = 0;
    if (real_uname_ptr) ret = real_uname_ptr(buf);
    else if (g_bytehook_hooks_installed) ret = BYTEHOOK_CALL_PREV(fake_uname, buf);
    else ret = uname(buf);
    if (ret == 0 && buf) {
        char* p = nullptr;
        if ((p = strstr(buf->release, "-kernelsu")) != nullptr) *p = '\0';
        if ((p = strstr(buf->release, "-ksu")) != nullptr) *p = '\0';
        if ((p = strstr(buf->release, "-apatch")) != nullptr) *p = '\0';
        if ((p = strstr(buf->release, "-dirty")) != nullptr) *p = '\0';
        if ((p = strstr(buf->version, "kernelsu")) != nullptr) strncpy(p, "generic ", 8);
        if ((p = strstr(buf->version, "apatch")) != nullptr) strncpy(p, "generic", 7);
    }
    return ret;
}

static void* fake_dlopen(const char* filename, int flags) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    void* handle = nullptr;
    if (real_dlopen_ptr) handle = real_dlopen_ptr(filename, flags);
    else if (g_bytehook_hooks_installed) handle = BYTEHOOK_CALL_PREV(fake_dlopen, filename, flags);
    else handle = dlopen(filename, flags);
    if (handle && filename && strstr(filename, "libqimei.so")) {
        hook_libqimei::patch_libqimei_in_memory();
    }
    return handle;
}

static void* fake_android_dlopen_ext(const char* filename, int flags, const void* extinfo) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    void* handle = nullptr;
    if (real_android_dlopen_ext_ptr) handle = real_android_dlopen_ext_ptr(filename, flags, extinfo);
    else if (g_bytehook_hooks_installed) handle = BYTEHOOK_CALL_PREV(fake_android_dlopen_ext, filename, flags, extinfo);
    else {
        typedef void* (*pfn_ext)(const char*, int, const void*);
        pfn_ext fn = (pfn_ext)dlsym(RTLD_DEFAULT, "android_dlopen_ext");
        if (fn) handle = fn(filename, flags, extinfo);
    }
    if (handle && filename && strstr(filename, "libqimei.so")) {
        hook_libqimei::patch_libqimei_in_memory();
    }
    return handle;
}

static bool is_anti_tamper_kill(pid_t tgid, pid_t tid, int sig, void* return_address) {
    (void)tid;
    pid_t self_pid = getpid();
    bool targets_self = (tgid == self_pid || tgid == 0 || tgid == -1);

    // 1. Userspace self-directed crash/abort signals: SIGSEGV (11), SIGBUS (7), SIGILL (4), SIGFPE (8), SIGTRAP (5)
    // Legitimate code NEVER sends SIGSEGV/SIGBUS/SIGILL to itself via kill/tgkill!
    // This is exclusively Tencent security DSO anti-tamper self-harm/suicide to terminate threads like thread_sp_norma!
    if (targets_self && (sig == SIGSEGV || sig == SIGBUS || sig == SIGILL || sig == SIGFPE || sig == SIGTRAP)) {
        LOGI("Neutralized self-directed crash signal (sig=%d, tgid=%d, tid=%d) to prevent thread/process kill", sig, tgid, tid);
        return true;
    }

    // 2. Tencent security DSOs intentionally terminating the process (SIGKILL, SIGTERM, SIGABRT)
    if (targets_self && is_caller_security_dso(return_address)) {
        if (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT) {
            LOGI("Neutralized security DSO suicide signal (sig=%d, tgid=%d, tid=%d)", sig, tgid, tid);
            return true;
        }
    }

    return false;
}

static int fake_kill(pid_t pid, int sig) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    if (is_anti_tamper_kill(pid, 0, sig, __builtin_return_address(0))) {
        return 0;
    }
    if (real_kill_ptr) return real_kill_ptr(pid, sig);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_kill, pid, sig);
#ifdef __NR_kill
    return (int)syscall(__NR_kill, pid, sig);
#else
    return 0;
#endif
}

static int fake_tkill(pid_t tid, int sig) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    if (is_anti_tamper_kill(getpid(), tid, sig, __builtin_return_address(0))) {
        return 0;
    }
    if (real_tkill_ptr) return real_tkill_ptr(tid, sig);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_tkill, tid, sig);
#ifdef __NR_tkill
    return (int)syscall(__NR_tkill, tid, sig);
#else
    return 0;
#endif
}

static int fake_tgkill(pid_t tgid, pid_t tid, int sig) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    if (is_anti_tamper_kill(tgid, tid, sig, __builtin_return_address(0))) {
        return 0;
    }
    if (real_tgkill_ptr) return real_tgkill_ptr(tgid, tid, sig);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_tgkill, tgid, tid, sig);
#ifdef __NR_tgkill
    return (int)syscall(__NR_tgkill, tgid, tid, sig);
#else
    return 0;
#endif
}

static int fake_raise(int sig) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();
    if (is_anti_tamper_kill(getpid(), gettid(), sig, __builtin_return_address(0))) {
        return 0;
    }
    if (real_raise_ptr) return real_raise_ptr(sig);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_raise, sig);
    return fake_tgkill(getpid(), gettid(), sig);
}

long fake_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    SAFE_BYTEHOOK_SCOPE();
    ensure_real_funcs();

    // 56: __NR_openat, 437: __NR_openat2, 322: __NR_openat on arm
    if (number == 56 || number == 437 || number == 322) {
        const char* path = (const char*)a2;
        if (path) {
            if (is_security_hidden_path(path, __builtin_return_address(0))) {
                LOGD("fake_syscall: openat blocked sensitive: %s", path);
                errno = ENOENT;
                return -1;
            }
            if (strncmp(path, "/proc/", 6) == 0) {
                const char* pid_start = path + 6;
                const char* slash = strchr(pid_start, '/');
                if (slash && pid_start[0] >= '0' && pid_start[0] <= '9') {
                    char pid_buf[32];
                    size_t pid_len = slash - pid_start;
                    if (pid_len < sizeof(pid_buf)) {
                        memcpy(pid_buf, pid_start, pid_len);
                        pid_buf[pid_len] = '\0';
                        if (is_root_pid(pid_buf)) {
                            errno = ENOENT;
                            return -1;
                        }
                    }
                }
            }
            if (strstr(path, "smaps")) {
                LOGI("fake_syscall: openat smaps redirected: %s", path);
                FILE* fake = build_filtered_smaps();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    return fd;
                }
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
            if (is_proc_mountinfo_path(path)) {
                LOGI("fake_syscall: openat mountinfo redirected: %s", path);
                FILE* fake = build_filtered_mountinfo();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    return fd;
                }
            }
            if (is_proc_mounts_path(path)) {
                LOGI("fake_syscall: openat mounts redirected: %s", path);
                FILE* fake = build_filtered_mounts();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    return fd;
                }
            }
            if (is_proc_net_unix_path(path)) {
                LOGI("fake_syscall: openat net/unix redirected: %s", path);
                FILE* fake = build_filtered_net_unix();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    return fd;
                }
            }
            if (is_proc_attr_current_path(path)) {
                LOGI("fake_syscall: openat attr/current redirected: %s", path);
                FILE* fake = build_filtered_selinux_attr();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    return fd;
                }
            }
            if (is_proc_cgroup_path(path)) {
                LOGI("fake_syscall: openat cgroup redirected: %s", path);
                FILE* fake = build_filtered_cgroup();
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
        if (path && is_security_hidden_path(path, __builtin_return_address(0))) {
            LOGD("fake_syscall: newfstatat blocked sensitive: %s", path);
            errno = ENOENT;
            return -1;
        }
    }
    // 48 / 439: __NR_faccessat, __NR_faccessat2
    else if (number == 48 || number == 439) {
        const char* path = (const char*)a2;
        if (path && is_security_hidden_path(path, __builtin_return_address(0))) {
            LOGD("fake_syscall: faccessat blocked sensitive: %s", path);
            errno = ENOENT;
            return -1;
        }
    }
    // 78: __NR_readlinkat
    else if (number == 78) {
        const char* path = (const char*)a2;
        if (path && is_security_hidden_path(path, __builtin_return_address(0))) {
            LOGD("fake_syscall: readlinkat blocked sensitive: %s", path);
            errno = ENOENT;
            return -1;
        }
        return fake_readlinkat((int)(uintptr_t)a1, path, (char*)a3, (size_t)(uintptr_t)a4);
    }
#ifdef __NR_getdents64
    // 61: __NR_getdents64
    else if (number == __NR_getdents64) {
        long ret = 0;
        if (real_syscall_ptr) {
            ret = real_syscall_ptr(number, a1, a2, a3, a4, a5, a6);
        } else {
            ret = syscall(number, a1, a2, a3, a4, a5, a6);
        }
        if (ret > 0 && a2) {
            struct linux_dirent64 {
                uint64_t        d_ino;
                int64_t         d_off;
                unsigned short  d_reclen;
                unsigned char   d_type;
                char            d_name[];
            };
            char* buf = (char*)a2;
            long pos = 0;
            char* write_ptr = buf;
            long new_ret = 0;
            void* ret_addr = __builtin_return_address(0);
            while (pos < ret) {
                struct linux_dirent64* dent = (struct linux_dirent64*)(buf + pos);
                unsigned short reclen = dent->d_reclen;
                if (reclen == 0) break;
                bool hide = false;
                if (is_sensitive_name_for_caller(dent->d_name, ret_addr)) {
                    hide = true;
                } else if (dent->d_name[0] >= '0' && dent->d_name[0] <= '9') {
                    if (is_root_pid(dent->d_name)) {
                        hide = true;
                    }
                }
                if (!hide) {
                    if (write_ptr != (char*)dent) {
                        memmove(write_ptr, dent, reclen);
                    }
                    write_ptr += reclen;
                    new_ret += reclen;
                }
                pos += reclen;
            }
            return new_ret;
        }
        return ret;
    }
#endif
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
#ifdef __NR_kill
    else if (number == __NR_kill) {
        pid_t pid = (pid_t)(uintptr_t)a1;
        int sig = (int)(uintptr_t)a2;
        if (is_anti_tamper_kill(pid, 0, sig, __builtin_return_address(0))) {
            return 0;
        }
    }
#endif
#ifdef __NR_tkill
    else if (number == __NR_tkill) {
        pid_t tid = (pid_t)(uintptr_t)a1;
        int sig = (int)(uintptr_t)a2;
        if (is_anti_tamper_kill(getpid(), tid, sig, __builtin_return_address(0))) {
            return 0;
        }
    }
#endif
#ifdef __NR_tgkill
    else if (number == __NR_tgkill) {
        pid_t tgid = (pid_t)(uintptr_t)a1;
        pid_t tid = (pid_t)(uintptr_t)a2;
        int sig = (int)(uintptr_t)a3;
        if (is_anti_tamper_kill(tgid, tid, sig, __builtin_return_address(0))) {
            return 0;
        }
    }
#endif

    if (real_syscall_ptr) {
        return real_syscall_ptr(number, a1, a2, a3, a4, a5, a6);
    }
    return syscall(number, a1, a2, a3, a4, a5, a6);
}

static long fake_ptrace(int request, pid_t pid, void* addr, void* data) {
    SAFE_BYTEHOOK_SCOPE();
    if (request == 0 /* PTRACE_TRACEME */) {
        LOGI("fake_ptrace: PTRACE_TRACEME neutralized");
        return 0;
    }
    typedef long (*ptrace_func_t)(int, pid_t, void*, void*);
    static ptrace_func_t real_ptrace_ptr = nullptr;
    if (!real_ptrace_ptr) real_ptrace_ptr = (ptrace_func_t)dlsym(RTLD_DEFAULT, "ptrace");
    if (real_ptrace_ptr) return real_ptrace_ptr(request, pid, addr, data);
    if (g_bytehook_hooks_installed) return BYTEHOOK_CALL_PREV(fake_ptrace, request, pid, addr, data);
    return syscall(__NR_ptrace, request, pid, addr, data);
}

void install_hooks() {
    LOGI("Installing libc hooks (ByteHook)...");
    ensure_real_funcs();

    bytehook_hook_all(nullptr, "fopen", (void*)fake_fopen, nullptr, nullptr);
    bytehook_hook_all(nullptr, "fopen64", (void*)fake_fopen, nullptr, nullptr);
    bytehook_hook_all(nullptr, "open", (void*)fake_open, nullptr, nullptr);
    bytehook_hook_all(nullptr, "open64", (void*)fake_open, nullptr, nullptr);
    bytehook_hook_all(nullptr, "__open_2", (void*)fake_open_2, nullptr, nullptr);
    bytehook_hook_all(nullptr, "openat", (void*)fake_openat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "openat64", (void*)fake_openat, nullptr, nullptr);
    bytehook_hook_all(nullptr, "__openat_2", (void*)fake_openat_2, nullptr, nullptr);
    bytehook_hook_all(nullptr, "opendir", (void*)fake_opendir, nullptr, nullptr);
    bytehook_hook_all(nullptr, "readdir", (void*)fake_readdir, nullptr, nullptr);
    bytehook_hook_all(nullptr, "readdir64", (void*)fake_readdir64, nullptr, nullptr);
    bytehook_hook_all(nullptr, "readdir_r", (void*)fake_readdir_r, nullptr, nullptr);
    bytehook_hook_all(nullptr, "readdir64_r", (void*)fake_readdir64_r, nullptr, nullptr);
    bytehook_hook_all(nullptr, "fgets", (void*)fake_fgets, nullptr, nullptr);
    bytehook_hook_all(nullptr, "__fgets_chk", (void*)fake_fgets_chk, nullptr, nullptr);
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
    bytehook_hook_all(nullptr, "ptrace", (void*)fake_ptrace, nullptr, nullptr);
    bytehook_hook_all(nullptr, "kill", (void*)fake_kill, nullptr, nullptr);
    bytehook_hook_all(nullptr, "tkill", (void*)fake_tkill, nullptr, nullptr);
    bytehook_hook_all(nullptr, "tgkill", (void*)fake_tgkill, nullptr, nullptr);
    bytehook_hook_all(nullptr, "raise", (void*)fake_raise, nullptr, nullptr);
    bytehook_hook_all(nullptr, "__system_property_get", (void*)fake_system_property_get, nullptr, nullptr);
    bytehook_hook_all(nullptr, "__system_property_find", (void*)fake_system_property_find, nullptr, nullptr);
    bytehook_hook_all(nullptr, "__system_property_read_callback", (void*)fake_system_property_read_callback, nullptr, nullptr);
    bytehook_hook_all(nullptr, "__system_property_read", (void*)fake_system_property_read, nullptr, nullptr);
    bytehook_hook_all(nullptr, "popen", (void*)fake_popen, nullptr, nullptr);
    bytehook_hook_all(nullptr, "pclose", (void*)fake_pclose, nullptr, nullptr);
    bytehook_hook_all(nullptr, "statfs", (void*)fake_statfs, nullptr, nullptr);
    bytehook_hook_all(nullptr, "statfs64", (void*)fake_statfs64, nullptr, nullptr);
    bytehook_hook_all(nullptr, "fstatfs", (void*)fake_fstatfs, nullptr, nullptr);
    bytehook_hook_all(nullptr, "fstatfs64", (void*)fake_fstatfs64, nullptr, nullptr);
    bytehook_hook_all(nullptr, "uname", (void*)fake_uname, nullptr, nullptr);
    bytehook_hook_all(nullptr, "dlopen", (void*)fake_dlopen, nullptr, nullptr);
    bytehook_hook_all(nullptr, "android_dlopen_ext", (void*)fake_android_dlopen_ext, nullptr, nullptr);

    LOGI("libc hooks installed (filesystem, maps, mounts, syscalls, and properties)");
}

} // namespace hook_libc
