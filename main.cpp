#include <cstdio>
#include "dbg.h"

int main(){

    pid_t pid = get_process_pid("test_target");

    attach_process(pid);
    parse_thread_signal(pid);

    command_loop(pid);

    resume_process(pid);


    return 0;
}