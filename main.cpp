//
// Created by XiaM on 2025/9/11.
//

#include "dbg_core.h"
#include "dbg_command.h"
#include <iostream>
#include <cstring>
#include <csignal>
#include "log.h"

LogLevel g_log_level = LOG_INFO;

void usage(const char* prog) {
    std::cout << "Usage:\n";
    std::cout << "  " << prog << " <pid>         - Attach to process by PID\n";
    std::cout << "  " << prog << " <process_name> - Attach to process by name\n";
    exit(1);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage(argv[0]);
    }

    pid_t target_pid = -1;

    // 判断参数是PID还是进程名
    char* endptr;
    long pid_val = strtol(argv[1], &endptr, 10);
    if (*endptr == '\0') {
        target_pid = (pid_t)pid_val;
        LOGI("Attach to PID: %d", target_pid);
    } else {
        target_pid = get_process_pid(argv[1]);
        if (target_pid == -1) {
            return 1;
        }
        LOGI("Found process '%s'  PID: %d", argv[1], target_pid);
    }

    if (attach_process(target_pid) == -1) {
        return 1;
    }

    command_loop(target_pid);

    return 0;
}