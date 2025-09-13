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
 

// 命令类型枚举（保留用于命令识别）
enum class CommandType {
    NONE = 0,
    STEP_INTO,
    STEP_OVER,
    CONTINUE,
    TRACE
};

// 调试器状态枚举（新的状态机设计）
enum class DebuggerState {
    IDLE = 0,           // 空闲：等待用户命令
    CONTINUE,           // 运行：程序正在执行，等待断点
    STEP,               // 单步：执行一条指令
    TRACE_WAIT_START,   // trace：等待命中起始断点
    TRACE_ACTIVE        // trace：自动单步直到结束
};

struct PCB{
    //被调进程pid
    pid_t pid = -1;

    // 记录上次反汇编的地址，用于连续反汇编
    uint64_t last_disasm_addr = 0;

    // 单步遇到断点 临时禁用的断点地址
    void* temp_disabled_bp = nullptr;

    // trace 状态
    uintptr_t trace_begin = 0;
    uintptr_t trace_end = 0;
    bool trace_ever_into= false; //是否进入过trace区间
    FILE* trace_fp = nullptr;
    
    // 信号等待控制
    bool need_wait_signal = false; //是否需要等待进程信号
    
    // 当前执行的命令类型
    CommandType current_command = CommandType::NONE;
    
    // 新的调试器状态机
    DebuggerState debugger_state = DebuggerState::IDLE;
};
extern PCB g_pcb;

long attach_process(pid_t pid);
long detach_process(pid_t pid);
long resume_process(pid_t pid);
int suspend_process(pid_t pid);

//void parse_thread_signal(pid_t pid);
//void handle_command_signal(pid_t pid, uint64_t pc, int sig, siginfo_t info);

// 新的状态机信号处理
void parse_signal(pid_t pid);
void handle_idle_signal(pid_t pid, uint64_t pc, int sig, siginfo_t info);
void handle_continue_signal(pid_t pid, uint64_t pc, int sig, siginfo_t info);
void handle_step_signal(pid_t pid, uint64_t pc, int sig, siginfo_t info);
void handle_trace_wait_start_signal(pid_t pid, uint64_t pc, int sig, siginfo_t info);  // 等待trace起始断点
void handle_trace_signal_new(pid_t pid, uint64_t pc, int sig, siginfo_t info);

//
long step_into(pid_t pid);
long step_over(pid_t pid);

//
bool bp_set(pid_t pid,void* address);
bool bp_set_temp_for_step_over(pid_t pid, void* address);  // 设置步过操作的临时断点
bool bp_clear(pid_t pid, size_t index);
void bp_show();
void print_singel_bp(size_t index);
void bp_temp_disable(pid_t pid, void* address);  // 临时禁用断点
void bp_restore_temp_disabled(pid_t pid);  // 恢复临时禁用的断点
/*
bool bp_is_at_address(void* address);  // 检查指定地址是否有断点
bool bp_is_temp_for_step_over(void* address);  // 检查是否是步过的临时断点
void bp_clear_all_temp_for_step_over(pid_t pid);  // 清除所有步过的临时断点
void bp_trace_disable_all(pid_t pid);  // trace开始时禁用所有断点
void bp_trace_enable_all(pid_t pid);   // trace结束时启用所有断点
 */

struct breakpoint{
    void* address;
    uint32_t origin_inst;
    bool is_temp = false;  // 是否是步过操作的临时断点
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

//capstone反汇编 返回流
std::string disasm(const uint8_t *code ,size_t code_size, uint64_t address,bool isbp = false);
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

void trace_start(uintptr_t begin, uintptr_t end);
void trace_reset();
void trace_log_step(pid_t pid);
// 全局当前调试进程PID
extern pid_t g_current_pid;



#endif //LINUX_DBG_H
