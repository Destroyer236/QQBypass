#ifndef NATIVE_BYPASS_HOOK_LIBC_H
#define NATIVE_BYPASS_HOOK_LIBC_H

#include <stdio.h>

typedef int (*HookFunType)(void *func, void *replace, void **backup);

namespace hook_libc {

/**
 * Hook libc functions to intercept file I/O
 * - fopen: redirect /proc/self/maps and /proc/self/status
 * - readlink: hide /proc/self/exe path
 * - access: hide suspicious files
 * - syscall: intercept openat, newfstatat, faccessat, readlinkat
 */
void install_hooks();
void install_inline_hooks(HookFunType hook_func);

bool is_sensitive_path(const char* path);
FILE* build_filtered_maps();
FILE* build_filtered_mounts();

long fake_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6);

} // namespace hook_libc

#endif // NATIVE_BYPASS_HOOK_LIBC_H
