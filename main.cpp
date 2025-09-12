#include <cstdio>

#include "dbg_command.h"

int main(int argc, char* argv[]){

    if (argc < 2) {
        printf("usage: %s <process_name> \n", argv[0]);
        return 1;
    }
    
    const char* process_name = argv[1];

    pid_t pid = get_process_pid(process_name);

    attach_process(pid);

    // 启动时不需要等待信号
    g_pcb.need_wait_signal = false;

    command_loop(pid);

    resume_process(pid);

    return 0;
}