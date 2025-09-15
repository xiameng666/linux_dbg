// 修改后的 log.h

#ifndef LINUX_DBG_LOG_H
#define LINUX_DBG_LOG_H

#include <cstdio>
#include <cstring>
#include <errno.h>

// 日志级别
enum LogLevel {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARNING = 2,
    LOG_ERROR = 3
};

// 全局日志级别控制
extern LogLevel g_log_level;

// 初始化日志级别（在main.cpp中调用）
inline void init_log_level(LogLevel level = LOG_INFO) {
    g_log_level = level;
}

// 日志宏定义 - 添加级别检查
#define LOGI(fmt, ...) \
    do { \
        if (g_log_level <= LOG_INFO) { \
            printf("[INFO] " fmt "\n", ##__VA_ARGS__); \
        } \
    } while(0)

#define LOGD(fmt, ...) \
    do { \
        if (g_log_level <= LOG_DEBUG) { \
            printf("[DEBUG] " fmt "\n", ##__VA_ARGS__); \
        } \
    } while(0)

#define LOGW(fmt, ...) \
    do { \
        if (g_log_level <= LOG_WARNING) { \
            printf("[WARN] " fmt "\n", ##__VA_ARGS__); \
        } \
    } while(0)

#define LOGE(fmt, ...) \
    do { \
        if (g_log_level <= LOG_ERROR) { \
            fprintf(stderr, "[ERROR] %s:%d - " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        } \
    } while(0)

#define LOG_ENTER(fmt, ...) \
    do { \
        if (g_log_level <= LOG_DEBUG) { \
            LOGD("------->>> %s " fmt, __FUNCTION__, ##__VA_ARGS__); \
        } \
    } while(0)

#endif //LINUX_DBG_LOG_H