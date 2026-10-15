#ifndef NATIVE_BYPASS_SAFE_BYTEHOOK_H
#define NATIVE_BYPASS_SAFE_BYTEHOOK_H

#include <bytehook.h>

extern bool g_bytehook_hooks_installed;
extern bool g_lsposed_initialized;

#ifdef __cplusplus
struct SafeBytehookScope {
    void* ret_addr;
    SafeBytehookScope(void* ret) : ret_addr(ret) {}
    ~SafeBytehookScope() {
        if (g_bytehook_hooks_installed && bytehook_get_mode() == BYTEHOOK_MODE_AUTOMATIC) {
            bytehook_pop_stack(ret_addr);
        }
    }
};
#define SAFE_BYTEHOOK_SCOPE() SafeBytehookScope __safe_bh_scope(__builtin_return_address(0))
#else
#define SAFE_BYTEHOOK_SCOPE() do {} while(0)
#endif

#endif // NATIVE_BYPASS_SAFE_BYTEHOOK_H
