#ifndef NATIVE_BYPASS_HOOK_LIBFEKIT_H
#define NATIVE_BYPASS_HOOK_LIBFEKIT_H

#include "hook_libc.h"

namespace hook_libfekit {

/**
 * Hook libfekit.so detection functions
 * - Root detection (Magisk/KernelSU checks)
 * - Maps scanning
 * - CheckJNI integrity verification
 * - Package manager queries
 */
void install_hooks();
void install_hooks_for_handle(void* handle, HookFunType hook_func);

} // namespace hook_libfekit

#endif // NATIVE_BYPASS_HOOK_LIBFEKIT_H
