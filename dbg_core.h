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

// 调试器状态
enum class DebuggerState {
    IDLE,               // 空闲，等待命令
    RUNNING,            // 运行中（执行g命令后）
    STEPPING,           // 单步中（执行s命令后）
    STEP_OVER,          // 步过中（执行n命令后）
    TRACE_WAIT_START,   // 等待到达trace起始点
    TRACE_ACTIVE        // 正在trace中
};

// 停止原因
enum class StopReason {
    NONE,
    USER_BREAKPOINT,    // 用户设置的断点
    TEMP_BREAKPOINT,    // 临时断点（步过或trace用）
    SINGLE_STEP,        // 单步完成
    SIGNAL_STOP,        // SIGSTOP信号
    EXCEPTION,          // 异常信号
    PROCESS_EXIT        // 进程退出
};

// 断点结构
struct Breakpoint {
    void* address;
    uint32_t origin_inst;
    bool is_temp = false;      // 是否是临时断点
    bool is_enabled = true;    // 是否启用
};

// 进程控制块
struct PCB {
    pid_t pid = -1;

    // 调试器状态
    DebuggerState state = DebuggerState::IDLE;
    bool need_wait_signal = false;

    // 断点管理
    void* temp_disabled_bp = nullptr;  // 临时禁用的断点地址（穿越断点用）
    void* step_over_bp = nullptr;      // 步过的临时断点地址

    // Trace状态
    uintptr_t trace_begin = 0;
    uintptr_t trace_end = 0;
    bool trace_started = false;
    FILE* trace_fp = nullptr;

    // 反汇编状态
    uint64_t last_disasm_addr = 0;

    // 上次停止原因
    StopReason last_stop_reason = StopReason::NONE;
};

extern PCB g_pcb;
extern std::vector<Breakpoint> g_bp_vec;

// 核心调试函数
long attach_process(pid_t pid);
long detach_process(pid_t pid);
long resume_process(pid_t pid);
int suspend_process(pid_t pid);
long step_into(pid_t pid);
long step_over(pid_t pid);

// 信号处理
void parse_signal(pid_t pid);
StopReason analyze_stop_reason(pid_t pid, int status, siginfo_t& info);
void handle_stop_event(pid_t pid, StopReason reason, uint64_t pc);

// 各状态下的停止处理
void handle_idle_stop(pid_t pid, StopReason reason, uint64_t pc);
void handle_running_stop(pid_t pid, StopReason reason, uint64_t pc);
void handle_stepping_stop(pid_t pid, StopReason reason, uint64_t pc);
void handle_step_over_stop(pid_t pid, StopReason reason, uint64_t pc);
void handle_trace_wait_stop(pid_t pid, StopReason reason, uint64_t pc);
void handle_trace_active_stop(pid_t pid, StopReason reason, uint64_t pc);

// 断点管理
bool bp_set(pid_t pid, void* address);
bool bp_set_temp(pid_t pid, void* address);
bool bp_clear(pid_t pid, size_t index);
bool bp_clear_temp(pid_t pid, void* address);
void bp_show();
void bp_temp_disable(pid_t pid, void* address);
void bp_restore_temp_disabled(pid_t pid);
bool has_breakpoint_at(void* address);
bool is_temp_breakpoint(void* address);
void clear_all_temp_breakpoints(pid_t pid);

// 寄存器操作
long get_reg(pid_t pid, const char* reg_name, uint64_t* value);
long set_reg(pid_t pid, const char* reg_name, uint64_t value);
bool print_all_regs(pid_t pid);
void print_single_reg(const std::string& reg_name, uint64_t value);

// 内存操作
ssize_t write_memory_ptrace(pid_t pid, void *target_address, void *write_data, size_t len);
ssize_t read_memory_ptrace(pid_t pid, void *target_address, size_t len, void *save_buffer);
ssize_t read_memory_vm(pid_t pid, void* target_address, size_t len, void* save_buffer);
ssize_t write_memory_vm(pid_t pid, void* target_address, void* write_data, size_t len);

// 反汇编
std::string disasm(const uint8_t *code, size_t code_size, uint64_t address, bool isbp = false);
void disasm_lines(pid_t pid, void* target_addr = nullptr, size_t line = 5, bool is_continue = false);
uint8_t get_inst_type(pid_t pid, void* address);

// Trace功能
void trace_start(uintptr_t begin, uintptr_t end);
void trace_reset();
void trace_log_step(pid_t pid);

// 工具函数
void parse_map(pid_t pid);
pid_t get_process_pid(const char* process_name);
std::vector<std::string> split_space(const std::string& s);
void hexdump(const void* data, size_t size, uintptr_t base_addr = 0);
const char* state_to_string(DebuggerState state);
const char* stop_reason_to_string(StopReason reason);

#endif //LINUX_DBG_H