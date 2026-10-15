#ifndef HOOK_LIBTURINGMFA_H
#define HOOK_LIBTURINGMFA_H

#include "hook_libc.h"

/**
 * Install hooks for libturingmfa.so
 *
 * Blocks risk reporting & anti-tamper detection:
 * - syscall & real_syscall: openat, newfstatat, maps redirection
 * - strstr: memory & hook framework keyword neutralization
 */
void install_turingmfa_hooks();

#endif // HOOK_LIBTURINGMFA_H
