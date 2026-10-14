#include <jni.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "../utils/log.h"
#include "bytehook.h"

void install_turingmfa_hooks() {
    LOGI("libturingmfa: Network request interception disabled, allowing normal requests");
}
