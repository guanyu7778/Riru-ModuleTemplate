#pragma once
#include <errno.h>
#include "android/log.h"
#define LOG_TAG    "YQFIN"
#ifdef DEBUG
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#else
#define LOGD(...)
#endif
#define LOGV(...)  __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))
namespace riru {
    extern const int moduleVersionCode;
    extern const char* const moduleVersionName;
    extern const int moduleApiVersion;
    extern const int moduleMinApiVersion;
    constexpr const char* kZygoteNiceName = "zygote64";
    constexpr const char* nextLoadSo = "/data/local/yqfin.so";
}
