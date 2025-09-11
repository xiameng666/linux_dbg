#include <cstdio>

#include "dbg_command.h"



int main(){

    pid_t pid = get_process_pid("dbgtest");

    attach_process(pid);

    g_pcb.need_wait_signal = true;

    command_loop(pid);

    resume_process(pid);

    return 0;
}