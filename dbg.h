//
// Created by XiaM on 2025/9/9.
//

#ifndef LINUX_DBG_H
#define LINUX_DBG_H

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <string>
#include "log.h"

void command_loop(pid_t pid);

long attach_process(pid_t pid);
long detach_process(pid_t pid);
long resume_process(pid_t pid);
int suspend_process(pid_t pid);
void parse_thread_signal(pid_t pid);

// 单步调试
long step_into(pid_t pid);
long step_over(pid_t pid);

// 寄存器
long get_reg(pid_t pid, const char* reg_name, uint64_t* value);
long set_reg(pid_t pid, const char* reg_name, uint64_t value);
bool print_all_regs(pid_t pid); 
void print_single_reg(const std::string& reg_name, uint64_t value);

//
long step_into(pid_t pid);

// pidof XXX
pid_t get_process_pid(const char* process_name);

//按空格分割字符到数组
std::vector<std::string> split_space(const std::string& s);
#endif //LINUX_DBG_H
