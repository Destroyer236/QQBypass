#pragma once
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

namespace hook_libqimei {

void install_hooks();
void patch_libqimei_in_memory();

} // namespace hook_libqimei
