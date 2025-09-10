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
#include "MapControl.h"
#include <sstream>
#include <cstdio>
#include <string>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <iostream>
#include <iomanip>
#include <unordered_map>
#include <linux/uio.h>
#include <linux/elf.h>
#include <sys/uio.h>
#include <algorithm>

void command_loop(pid_t pid);

long attach_process(pid_t pid);
long detach_process(pid_t pid);
long resume_process(pid_t pid);
int suspend_process(pid_t pid);
void parse_thread_signal(pid_t pid);

//
long step_into(pid_t pid);
long step_over(pid_t pid);

//
bool bp_set(pid_t pid,void* address);
bool bp_clear(pid_t pid, size_t index);
void bp_show();
void print_singel_bp(size_t index);

struct breakpoint{
    void* address;
    uint32_t origin_inst;
};
static std::vector<breakpoint> g_bp_vec;

// 寄存器
long get_reg(pid_t pid, const char* reg_name, uint64_t* value);
long set_reg(pid_t pid, const char* reg_name, uint64_t value);
bool print_all_regs(pid_t pid); 
void print_single_reg(const std::string& reg_name, uint64_t value);

//
ssize_t write_memory_ptrace(pid_t pid, void *target_address, void *write_data, size_t len);
ssize_t read_memory_ptrace(pid_t pid, void *target_address, size_t len, void *save_buffer);
ssize_t read_memory_vm(pid_t pid, void* target_address, size_t len, void* save_buffer);
ssize_t write_memory_vm(pid_t pid, void* target_address, void* write_data, size_t len);

//
void disasm_lines(pid_t pid, void* target_addr = nullptr, size_t line = 5);

//解析map数据并存储
void parse_map(pid_t pid);

// pidof XXX
pid_t get_process_pid(const char* process_name);

//按空格分割字符到数组
std::vector<std::string> split_space(const std::string& s);
#endif //LINUX_DBG_H
