#include <cstdio>

#include "dbg_command.h"



int main(){

    pid_t pid = get_process_pid("dbgtest");

    attach_process(pid);

    // 启动时不需要等待信号，处于空闲状态等待用户命令
    g_pcb.need_wait_signal = false;

    command_loop(pid);

    resume_process(pid);

    return 0;
}