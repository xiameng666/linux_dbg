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
#include "capstone/capstone.h"

// 全局状态：记录上次反汇编的地址，用于连续反汇编
extern uint64_t g_last_disasm_addr;
// 临时禁用的断点地址
extern void* g_temp_disabled_bp;

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
void bp_temp_disable(pid_t pid, void* address);  // 临时禁用断点
void bp_restore_temp_disabled(pid_t pid);  // 恢复临时禁用的断点

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
void disasm(const uint8_t *code ,size_t code_size, uint64_t address,bool isbp = false);
void disasm_lines(pid_t pid, void* target_addr = nullptr, size_t line = 5, bool is_continue = false);

uint8_t get_inst_type(pid_t pid,void* address);

//解析map数据并存储
void parse_map(pid_t pid);

// pidof XXX
pid_t get_process_pid(const char* process_name);

//按空格分割字符到数组
std::vector<std::string> split_space(const std::string& s);

// 十六进制转储函数
void hexdump(const void* data, size_t size, uintptr_t base_addr = 0);




#endif //LINUX_DBG_H
