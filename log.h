//
// Created by XiaM on 2025/9/9.
//

#ifndef LINUX_DBG_LOG_H
#define LINUX_DBG_LOG_H

#include <android/log.h>
#include <cstdio>

#ifndef LOG_TAG
#define LOG_TAG "linux_dbg"
#endif

#define LOG(...) do { printf(__VA_ARGS__); printf("\n"); } while(0)
#define LOGD(...) //do { printf("----> %s", __FUNC_NAME__);printf(__VA_ARGS__); printf("\n"); } while(0) //  ((void)0)//
#define LOGE(...)  do { printf(__VA_ARGS__); printf("\n"); } while(0)

// function entry logging
#if defined(__GNUC__)
#define __FUNC_NAME__ __PRETTY_FUNCTION__
#else
#define __FUNC_NAME__ __func__
#endif

#define LOG_ENTER(...) // do { printf("----> %s", __FUNC_NAME__); printf(__VA_ARGS__); printf("\n");} while(0) //


/*
LOG_LEVEL: 0=OFF, 1=E, 2=W, 3=I, 4=D, 5=V
#ifndef LOG_LEVEL
#define LOG_LEVEL 5
#endif

#if LOG_LEVEL >= 5
#define LOGV(...) __android_log_print(ANDROID_LOG_DEBUG,   LOG_TAG, __VA_ARGS__)
#else
#define LOGV(...) ((void)0)
#endif

#if LOG_LEVEL >= 4
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,   LOG_TAG, __VA_ARGS__)
#else
#define LOGD(...) ((void)0)
#endif

#if LOG_LEVEL >= 3
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,    LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#endif

#if LOG_LEVEL >= 2
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,    LOG_TAG, __VA_ARGS__)
#else
#define LOGW(...) ((void)0)
#endif

#if LOG_LEVEL >= 1
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,   LOG_TAG, __VA_ARGS__)
#else
#define LOGE(...) ((void)0)
#endif
 */


#endif //LINUX_DBG_LOG_H
