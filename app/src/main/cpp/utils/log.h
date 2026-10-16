#ifndef NATIVE_BYPASS_LOG_H
#define NATIVE_BYPASS_LOG_H

#include <android/log.h>

#define TAG "QQNativeBypass"

// 确保模块日志不写入系统 logcat，防止被 QQ/Bugly/APM 抓取上传
#define LOGD(...) ((void)0)
#define LOGI(...) ((void)0)
#define LOGW(...) ((void)0)
#define LOGE(...) ((void)0)

#endif // NATIVE_BYPASS_LOG_H
