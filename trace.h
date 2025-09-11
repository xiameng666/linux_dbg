//
// Created by XiaM on 2025/9/11.
//

#ifndef LINUX_DBG_TRACE_H
#define LINUX_DBG_TRACE_H
#include <cstdio>
#include <string>
#include "log.h"

class Trace{
private:
    uintptr_t begin_ = 0, end_ = 0;
    bool enabled_ = false;

    FILE* fp_ = nullptr;
public:

    void start(uintptr_t begin, uintptr_t end);

    void close();

    void log_step(pid_t pid);
};
#endif //LINUX_DBG_TRACE_H
