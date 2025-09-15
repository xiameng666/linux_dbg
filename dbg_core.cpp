//
// Created by XiaM on 2025/9/9.
//
#include "dbg_core.h"

PCB g_pcb;
std::vector<Breakpoint> g_bp_vec;

static const std::unordered_map<std::string, size_t> reg_map = {
        // 通用寄存器
        {"x0",  offsetof(struct user_regs_struct, regs[0])},
        {"x1",  offsetof(struct user_regs_struct, regs[1])},
        {"x2",  offsetof(struct user_regs_struct, regs[2])},
        {"x3",  offsetof(struct user_regs_struct, regs[3])},
        {"x4",  offsetof(struct user_regs_struct, regs[4])},
        {"x5",  offsetof(struct user_regs_struct, regs[5])},
        {"x6",  offsetof(struct user_regs_struct, regs[6])},
        {"x7",  offsetof(struct user_regs_struct, regs[7])},
        {"x8",  offsetof(struct user_regs_struct, regs[8])},
        {"x9",  offsetof(struct user_regs_struct, regs[9])},
        {"x10", offsetof(struct user_regs_struct, regs[10])},
        {"x11", offsetof(struct user_regs_struct, regs[11])},
        {"x12", offsetof(struct user_regs_struct, regs[12])},
        {"x13", offsetof(struct user_regs_struct, regs[13])},
        {"x14", offsetof(struct user_regs_struct, regs[14])},
        {"x15", offsetof(struct user_regs_struct, regs[15])},
        {"x16", offsetof(struct user_regs_struct, regs[16])},
        {"x17", offsetof(struct user_regs_struct, regs[17])},
        {"x18", offsetof(struct user_regs_struct, regs[18])},
        {"x19", offsetof(struct user_regs_struct, regs[19])},
        {"x20", offsetof(struct user_regs_struct, regs[20])},
        {"x21", offsetof(struct user_regs_struct, regs[21])},
        {"x22", offsetof(struct user_regs_struct, regs[22])},
        {"x23", offsetof(struct user_regs_struct, regs[23])},
        {"x24", offsetof(struct user_regs_struct, regs[24])},
        {"x25", offsetof(struct user_regs_struct, regs[25])},
        {"x26", offsetof(struct user_regs_struct, regs[26])},
        {"x27", offsetof(struct user_regs_struct, regs[27])},
        {"x28", offsetof(struct user_regs_struct, regs[28])},
        {"x29", offsetof(struct user_regs_struct, regs[29])}, // FP
        {"x30", offsetof(struct user_regs_struct, regs[30])}, // LR
        {"fp",  offsetof(struct user_regs_struct, regs[29])},
        {"lr",  offsetof(struct user_regs_struct, regs[30])},
        {"sp",   offsetof(struct user_regs_struct, sp)},
        {"pc",   offsetof(struct user_regs_struct, pc)},
        {"pstate", offsetof(struct user_regs_struct, pstate)},
};

const char* state_to_string(DebuggerState state) {
    switch (state) {
        case DebuggerState::IDLE: return "IDLE";
        case DebuggerState::RUNNING: return "RUNNING";
        case DebuggerState::STEPPING: return "STEPPING";
        case DebuggerState::STEP_OVER: return "STEP_OVER";
        case DebuggerState::TRACE_WAIT_START: return "TRACE_WAIT_START";
        case DebuggerState::TRACE_ACTIVE: return "TRACE_ACTIVE";
        default: return "UNKNOWN";
    }
}

const char* stop_reason_to_string(StopReason reason) {
    switch (reason) {
        case StopReason::NONE: return "NONE";
        case StopReason::USER_BREAKPOINT: return "USER_BREAKPOINT";
        case StopReason::TEMP_BREAKPOINT: return "TEMP_BREAKPOINT";
        case StopReason::SINGLE_STEP: return "SINGLE_STEP";
        case StopReason::SIGNAL_STOP: return "SIGNAL_STOP";
        case StopReason::EXCEPTION: return "EXCEPTION";
        case StopReason::PROCESS_EXIT: return "PROCESS_EXIT";
        default: return "UNKNOWN";
    }
}

// ==================== 基础调试操作 ====================

long attach_process(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);

    long result = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (result == -1) {
        LOGE("PTRACE_ATTACH failed: %s", strerror(errno));
        return -1;
    }

    g_pcb.pid = pid;
    g_pcb.state = DebuggerState::IDLE;
    g_pcb.need_wait_signal = true;  // 需要等待初始SIGSTOP

    return result;
}

long detach_process(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);

    // 清理所有断点
    clear_all_temp_breakpoints(pid);
    for (int i = g_bp_vec.size() - 1; i >= 0; i--) {
        if (!g_bp_vec[i].is_temp) {
            bp_clear(pid, i);
        }
    }

    long result = ptrace(PTRACE_DETACH, pid, NULL, NULL);
    if (result == -1) {
        LOGE("PTRACE_DETACH failed: %s", strerror(errno));
    }

    g_pcb.state = DebuggerState::IDLE;
    return result;
}

long resume_process(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);

    long result = ptrace(PTRACE_CONT, pid, NULL, NULL);
    if (result == -1) {
        LOGE("PTRACE_CONT failed: %s", strerror(errno));
        return result;
    }

    g_pcb.state = DebuggerState::RUNNING;
    g_pcb.need_wait_signal = true;
    return result;
}

int suspend_process(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);
    return kill(pid, SIGSTOP);
}

long step_into(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);

    long result = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    if (result == -1) {
        LOGE("PTRACE_SINGLESTEP failed: %s", strerror(errno));
        return result;
    }

    g_pcb.state = DebuggerState::STEPPING;
    g_pcb.need_wait_signal = true;
    return result;
}

long step_over(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);

    uint64_t pc_value;
    if (get_reg(pid, "pc", &pc_value) != 0) {
        LOGE("Failed to get PC register");
        return -1;
    }

    uint8_t inst_type = get_inst_type(pid, (void*)pc_value);

    if (inst_type == CS_GRP_CALL) {
        // 是调用指令，在返回地址设置临时断点
        uintptr_t return_addr = pc_value + 4;
        LOGD("Step over: 检测到调用指令, set temp bp at 0x%lx", return_addr);

        if (!bp_set_temp(pid, (void*)return_addr)) {
            LOGE("Failed to set temp breakpoint for step over");
            return -1;
        }

        g_pcb.step_over_bp = (void*)return_addr;
        g_pcb.state = DebuggerState::STEP_OVER;
        long result = ptrace(PTRACE_CONT, pid, NULL, NULL);
        g_pcb.need_wait_signal = true;
        //return resume_process(pid);
        return result;
    } else {
        // 非调用指令，直接单步
        LOGD("Step over: not a call, use single step");
        return step_into(pid);
    }
}

// ==================== 信号处理 ====================

void parse_signal(pid_t pid) {
    LOG_ENTER("(pid=%d, state=%s)", pid, state_to_string(g_pcb.state));

    int status;
    if (waitpid(pid, &status, WUNTRACED) == -1) {
        LOGE("waitpid failed: %s", strerror(errno));
        g_pcb.need_wait_signal = false;
        return;
    }

    // 进程退出检查
    if (WIFEXITED(status)) {
        LOGI("Process exit ,code: %d", WEXITSTATUS(status));
        g_pcb.state = DebuggerState::IDLE;
        g_pcb.need_wait_signal = false;
        return;
    }

    if (WIFSIGNALED(status)) {
        LOGI("Process terminate ,signal: %d", WTERMSIG(status));
        g_pcb.state = DebuggerState::IDLE;
        g_pcb.need_wait_signal = false;
        return;
    }

    if (!WIFSTOPPED(status)) {
        return;
    }

    // 获取详细信号信息
    siginfo_t info{};
    ptrace(PTRACE_GETSIGINFO, pid, 0, &info);

    // 获取当前PC
    uint64_t pc = 0;
    get_reg(pid, "pc", &pc);

    // 分析停止原因
    StopReason reason = analyze_stop_reason(pid, status, info);
    g_pcb.last_stop_reason = reason;

    LOGD("State=%s, PC=0x%lx, StopReason=%s",
         state_to_string(g_pcb.state), pc, stop_reason_to_string(reason));

    // 处理停止事件
    handle_stop_event(pid, reason, pc);
}

StopReason analyze_stop_reason(pid_t pid, int status, siginfo_t& info) {
    if (!WIFSTOPPED(status)) {
        return StopReason::NONE;
    }

    int sig = WSTOPSIG(status);
    uint64_t pc = 0;
    get_reg(pid, "pc", &pc);

    if (sig == SIGTRAP) {
        // ARM64的断点PC不需要回退
        void* bp_addr = (void*)pc;

        switch (info.si_code) {
            case TRAP_BRKPT:
                // 检查是否是我们设置的断点
                if (is_temp_breakpoint(bp_addr)) {
                    return StopReason::TEMP_BREAKPOINT;
                } else if (has_breakpoint_at(bp_addr)) {
                    return StopReason::USER_BREAKPOINT;
                }
                return StopReason::EXCEPTION;

            case TRAP_HWBKPT:
            case TRAP_TRACE:
                return StopReason::SINGLE_STEP;

            default:
                return StopReason::EXCEPTION;
        }
    } else if (sig == SIGSTOP) {
        return StopReason::SIGNAL_STOP;
    } else {
        LOGD("Received signal: %d", sig);
        return StopReason::EXCEPTION;
    }
}

void handle_stop_event(pid_t pid, StopReason reason, uint64_t pc) {
    switch (g_pcb.state) {
        case DebuggerState::IDLE:
            handle_idle_stop(pid, reason, pc);
            break;

        case DebuggerState::RUNNING:
            handle_running_stop(pid, reason, pc);
            break;

        case DebuggerState::STEPPING:
            handle_stepping_stop(pid, reason, pc);
            break;

        case DebuggerState::STEP_OVER:
            handle_step_over_stop(pid, reason, pc);
            break;

        case DebuggerState::TRACE_WAIT_START:
            handle_trace_wait_stop(pid, reason, pc);
            break;

        case DebuggerState::TRACE_ACTIVE:
            handle_trace_active_stop(pid, reason, pc);
            break;
    }
}

// ==================== 各状态的停止处理 ====================

void handle_idle_stop(pid_t pid, StopReason reason, uint64_t pc) {
    // IDLE状态一般只有 初始attach的SIGSTOP
    if (reason == StopReason::SIGNAL_STOP) {
        LOGI("SIGNAL_STOP");
    }
    g_pcb.need_wait_signal = false;
}

void handle_running_stop(pid_t pid, StopReason reason, uint64_t pc) {
    switch (reason) {
        case StopReason::USER_BREAKPOINT:
            LOGI("命中断点 at 0x%lx", pc);
            // 显示断点位置的指令
            disasm_lines(pid, (void*)pc, 1, false);
            g_pcb.state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
            break;

        case StopReason::TEMP_BREAKPOINT:
            // 步过遇到临时断点：先清除临时断点，再反汇编原始指令
            LOGW("handle_running_stop:  temp breakpoint");
            bp_clear_temp(pid, (void*)pc);
            disasm_lines(pid, (void*)pc, 1, false);
            g_pcb.state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
            break;

        case StopReason::SIGNAL_STOP:
            LOGI("handle_running_stop: SIGSTOP");
            g_pcb.state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
            break;

        case StopReason::EXCEPTION:
            LOGI("handle_running_stop:  exception at 0x%lx", pc);
            g_pcb.state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
            break;

        default:
            break;
    }
}

void handle_stepping_stop(pid_t pid, StopReason reason, uint64_t pc) {
    // 恢复之前临时禁用的断点
    if (g_pcb.temp_disabled_bp) {
        bp_restore_temp_disabled(pid);
    }

    switch (reason) {
        case StopReason::SINGLE_STEP:
            // 单步完成，显示当前指令
            disasm_lines(pid, (void*)pc, 1, false);
            g_pcb.state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
            break;

        case StopReason::USER_BREAKPOINT:
            // 单步时遇到断点（可能是单步进入了有断点的地址）
            LOGI("步入中遇到用户断点 at 0x%lx", pc);
            disasm_lines(pid, (void*)pc, 1, false);
            g_pcb.state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
            break;

        case StopReason::EXCEPTION:
            LOGI("handle_stepping_stop: Exceptionp at 0x%lx", pc);
            g_pcb.state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
            break;

        default:
            break;
    }
}

void handle_step_over_stop(pid_t pid, StopReason reason, uint64_t pc) {
    switch (reason) {
        case StopReason::TEMP_BREAKPOINT:
            // 步过完成，删除临时断点
            if (g_pcb.step_over_bp) {
                bp_clear_temp(pid, g_pcb.step_over_bp);
                g_pcb.step_over_bp = nullptr;
            }
            disasm_lines(pid, (void*)pc, 1, false);
            g_pcb.state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
            break;

        case StopReason::USER_BREAKPOINT:
            LOGI("步过中遇到用户断点 at 0x%lx", pc);
            // 清理步过的临时断点
            if (g_pcb.step_over_bp) {
                bp_clear_temp(pid, g_pcb.step_over_bp);
                g_pcb.step_over_bp = nullptr;
            }
            disasm_lines(pid, (void*)pc, 1, false);
            g_pcb.state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
            break;

        case StopReason::SINGLE_STEP:
            // 如果是非调用指令的步过，会收到单步信号
            disasm_lines(pid, (void*)pc, 1, false);
            g_pcb.state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
            break;

        case StopReason::EXCEPTION:
            LOGI("handle_step_over_stop：Exception at 0x%lx", pc);
            // 清理步过的临时断点
            if (g_pcb.step_over_bp) {
                bp_clear_temp(pid, g_pcb.step_over_bp);
                g_pcb.step_over_bp = nullptr;
            }
            g_pcb.state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
            break;

        default:
            break;
    }
}

void handle_trace_wait_stop(pid_t pid, StopReason reason, uint64_t pc) {
    switch (reason) {
        case StopReason::TEMP_BREAKPOINT:
            // 到达trace起始点
            if (pc == g_pcb.trace_begin) {
                LOGI("Reached trace start point: 0x%lx", pc);
                g_pcb.trace_started = true;
                // 删除起始点的临时断点
                bp_clear_temp(pid, (void*)pc);
                // 记录第一条指令
                trace_log_step(pid);
                // 开始单步trace
                g_pcb.state = DebuggerState::TRACE_ACTIVE;
                ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
                g_pcb.need_wait_signal = true;
            }
            break;

        case StopReason::USER_BREAKPOINT:
            // 到trace起始点前遇到断点
            LOGI("到trace起始点前遇到断点 at 0x%lx", pc);
            // 暂时先停下
            g_pcb.state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
            trace_reset();
            break;

        default:
            break;
    }
}

void handle_trace_active_stop(pid_t pid, StopReason reason, uint64_t pc) {
    switch (reason) {
        case StopReason::SINGLE_STEP:
            // 记录这一步
            trace_log_step(pid);

            // 检查是否到达结束点
            if (pc == g_pcb.trace_end) {
                LOGI("Trace完成 : 0x%lx -> 0x%lx", g_pcb.trace_begin, g_pcb.trace_end);
                trace_reset();
                g_pcb.state = DebuggerState::IDLE;
                g_pcb.need_wait_signal = false;
            } else {
                // 继续单步
                disasm_lines(pid, (void*)pc, 1, false);
                ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
                g_pcb.need_wait_signal = true;
            }
            break;

        case StopReason::USER_BREAKPOINT:
            // Trace过程中遇到断点，记录后继续
            LOGI("Trace过程中遇到断点 at 0x%lx, trace continue", pc);
            trace_log_step(pid);

            // 临时禁用断点，单步越过，再恢复
            bp_temp_disable(pid, (void*)pc);
            ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
            // 下次停止时会恢复断点
            g_pcb.need_wait_signal = true;
            break;

        case StopReason::EXCEPTION:
            LOGI("handle_trace_active_stop : Exception at 0x%lx", pc);
            trace_reset();
            g_pcb.state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
            break;

        default:
            break;
    }
}

// ==================== 断点管理 ====================

bool bp_set(pid_t pid, void* address) {
    LOG_ENTER("(pid=%d, address=%p)", pid, address);

    // 检查是否已存在
    for (auto& bp : g_bp_vec) {
        if (bp.address == address && !bp.is_temp) {
            LOGI("Breakpoint already exists at 0x%lx", (unsigned long)address);
            return true;
        }
    }

    uint32_t BRK = 0xD4200000;
    uint32_t orig = 0;

    if (read_memory_vm(pid, address, 4, &orig) != 4) {
        LOGE("Failed to read memory at 0x%lx", (unsigned long)address);
        return false;
    }

    if (write_memory_ptrace(pid, address, &BRK, 4) != 4) {
        LOGE("Failed to write BRK at 0x%lx", (unsigned long)address);
        return false;
    }

    Breakpoint newbp{address, orig, false, true};
    g_bp_vec.push_back(newbp);

    LOGI("Breakpoint set at 0x%lx (index=%zu)", (unsigned long)address, g_bp_vec.size() - 1);
    return true;
}

bool bp_set_temp(pid_t pid, void* address) {
    LOG_ENTER("(pid=%d, address=%p) [TEMP]", pid, address);

    // 检查是否已存在
    for (auto& bp : g_bp_vec) {
        if (bp.address == address) {
            if (!bp.is_temp) {
                // 如果是用户断点，不需要重复设置
                LOGD("breakpoint already at 0x%lx", (unsigned long)address);
                return true;
            } else {
                // 临时断点已存在
                return true;
            }
        }
    }

    uint32_t BRK = 0xD4200000;
    uint32_t orig = 0;

    if (read_memory_vm(pid, address, 4, &orig) != 4) {
        LOGE("Failed to read memory at 0x%lx", (unsigned long)address);
        return false;
    }

    if (write_memory_ptrace(pid, address, &BRK, 4) != 4) {
        LOGE("Failed to write BRK at 0x%lx", (unsigned long)address);
        return false;
    }

    Breakpoint newbp{address, orig, true, true};
    g_bp_vec.push_back(newbp);

    LOGD("temp breakpoint set at 0x%lx", (unsigned long)address);
    return true;
}

bool bp_clear(pid_t pid, size_t index) {
    LOG_ENTER("(pid=%d, index=%zu)", pid, index);

    if (index >= g_bp_vec.size()) {
        LOGE("无效索引: %zu", index);
        return false;
    }

    Breakpoint& bp = g_bp_vec[index];

    // 如果断点正在启用状态，恢复原始指令
    if (bp.is_enabled) {
        if (bp.address == g_pcb.temp_disabled_bp) {
            // 断点已被临时禁用，不需要恢复
            g_pcb.temp_disabled_bp = nullptr;
        } else {
            // 恢复
            if (write_memory_ptrace(pid, bp.address, &bp.origin_inst, 4) != 4) {
                LOGE("Failed to restore instruction at 0x%lx", (unsigned long)bp.address);
                return false;
            }
        }
    }

    g_bp_vec.erase(g_bp_vec.begin() + index);
    LOGI("Breakpoint cleared at index %zu", index);
    return true;
}

bool bp_clear_temp(pid_t pid, void* address) {
    for (int i = g_bp_vec.size() - 1; i >= 0; i--) {
        if (g_bp_vec[i].address == address && g_bp_vec[i].is_temp) {
            return bp_clear(pid, i);
        }
    }
    return false;
}

void bp_show() {
    LOG_ENTER("");

    if (g_bp_vec.empty()) {
        LOGI("No breakpoint");
        return;
    }

    printf("===== Breakpoints =====");
    for (size_t i = 0; i < g_bp_vec.size(); i++) {
        const auto& bp = g_bp_vec[i];
        if (!bp.is_temp) {
            printf("[%zu] 0x%016lx orig=0x%08x %s\n",
                   i,
                   (unsigned long)bp.address,
                   bp.origin_inst,
                   bp.is_enabled ? "enabled" : "disabled");
        }
    }

    // 显示临时断点
    bool has_temp = false;
    for (const auto& bp : g_bp_vec) {
        if (bp.is_temp) {
            if (!has_temp) {
                printf("===== Temp Breakpoints =====");
                has_temp = true;
            }
            printf("    0x%016lx [temp]\n", (unsigned long)bp.address);
        }
    }
}

void bp_temp_disable(pid_t pid, void* address) {
    LOG_ENTER("(pid=%d, address=%p)", pid, address);

    for (auto& bp : g_bp_vec) {
        if (bp.address == address && bp.is_enabled) {
            // 恢复原始指令
            if (write_memory_ptrace(pid, bp.address, &bp.origin_inst, 4) == 4) {
                bp.is_enabled = false;
                g_pcb.temp_disabled_bp = address;
                LOGD("临时禁用断点 at 0x%lx", (unsigned long)address);
            } else {
                LOGE("Failed to disable breakpoint at 0x%lx", (unsigned long)address);
            }
            break;
        }
    }
}

void bp_restore_temp_disabled(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);

    if (g_pcb.temp_disabled_bp == nullptr) {
        return;
    }

    for (auto& bp : g_bp_vec) {
        if (bp.address == g_pcb.temp_disabled_bp && !bp.is_enabled) {
            uint32_t BRK = 0xD4200000;
            if (write_memory_ptrace(pid, bp.address, &BRK, 4) == 4) {
                bp.is_enabled = true;
                LOGD("恢复断点 at 0x%lx", (unsigned long)bp.address);
            } else {
                LOGE("Failed to restore breakpoint at 0x%lx", (unsigned long)bp.address);
            }
            break;
        }
    }

    g_pcb.temp_disabled_bp = nullptr;
}

bool has_breakpoint_at(void* address) {
    for (const auto& bp : g_bp_vec) {
        if (bp.address == address && !bp.is_temp) {
            return true;
        }
    }
    return false;
}

bool is_temp_breakpoint(void* address) {
    for (const auto& bp : g_bp_vec) {
        if (bp.address == address && bp.is_temp) {
            return true;
        }
    }
    return false;
}

void clear_all_temp_breakpoints(pid_t pid) {
    for (int i = g_bp_vec.size() - 1; i >= 0; i--) {
        if (g_bp_vec[i].is_temp) {
            bp_clear(pid, i);
        }
    }
}

// ==================== 寄存器操作 ====================

long get_reg(pid_t pid, const char* reg_name, uint64_t* value) {
    user_regs_struct regs{};
    iovec iov{&regs, sizeof(user_regs_struct)};

    long result = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    if (result == -1) {
        LOGE("PTRACE_GETREGSET failed: %s", strerror(errno));
        return -1;
    }

    auto it = reg_map.find(reg_name);
    if (it == reg_map.end()) {
        LOGE("Unknown register: %s", reg_name);
        return -1;
    }

    *value = *reinterpret_cast<const uint64_t*>(
            reinterpret_cast<const char*>(&regs) + it->second);
    return 0;
}

long set_reg(pid_t pid, const char* reg_name, uint64_t value) {
    LOG_ENTER("(pid=%d, reg_name=%s, value=0x%lx)", pid, reg_name, value);

    user_regs_struct regs{};
    iovec iov{&regs, sizeof(user_regs_struct)};

    // 先读取当前寄存器
    long result = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    if (result == -1) {
        LOGE("PTRACE_GETREGSET failed: %s", strerror(errno));
        return -1;
    }

    auto it = reg_map.find(reg_name);
    if (it == reg_map.end()) {
        LOGE("Unknown register: %s", reg_name);
        return -1;
    }

    // 修改指定寄存器
    *reinterpret_cast<uint64_t*>(
            reinterpret_cast<char*>(&regs) + it->second) = value;

    // 写回寄存器
    result = ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    if (result == -1) {
        LOGE("PTRACE_SETREGSET failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

bool print_all_regs(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);

    user_regs_struct regs{};
    iovec iov{&regs, sizeof(user_regs_struct)};

    long result = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    if (result == -1) {
        LOGE("PTRACE_GETREGSET failed: %s", strerror(errno));
        return false;
    }

    std::cout << std::hex << std::setfill('0');

    // 显示通用寄存器
    for (int i = 0; i < 31; i++) {
        std::cout << "x" << std::setw(2) << i << "=0x"
                  << std::setw(16) << regs.regs[i];
        if ((i + 1) % 4 == 0) {
            std::cout << "\n";
        } else {
            std::cout << "  ";
        }
    }

    std::cout << "sp =0x" << std::setw(16) << regs.sp << "  ";
    std::cout << "pc =0x" << std::setw(16) << regs.pc << "  ";
    std::cout << "pstate=0x" << std::setw(8) << regs.pstate << "\n";

    std::cout << std::dec;
    return true;
}

void print_single_reg(const std::string& reg_name, uint64_t value) {
    std::cout << reg_name << " = 0x" << std::hex << std::setfill('0')
              << std::setw(16) << value;
    std::cout << " (" << std::dec << value << ")" << std::endl;
}

// ==================== 内存操作 ====================

ssize_t read_memory_vm(pid_t pid, void* target_address, size_t len, void* save_buffer) {
    iovec local{save_buffer, len};
    iovec remote{target_address, len};
    ssize_t result = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (result == -1) {
        LOGE("process_vm_readv failed: %s", strerror(errno));
    }
    return result;
}

ssize_t write_memory_vm(pid_t pid, void* target_address, void* write_data, size_t len) {
    LOG_ENTER("(pid=%d, target_address=%p, write_data=%p, len=%zu)",
              pid, target_address, write_data, len);

    iovec local{write_data, len};
    iovec remote{target_address, len};
    ssize_t result = process_vm_writev(pid, &local, 1, &remote, 1, 0);

    if (result != -1) {
        LOGI("Direct write succeeded: %zd bytes", result);
    } else {
        LOGE("process_vm_writev failed: %s", strerror(errno));
    }

    return result;
}

ssize_t write_memory_ptrace(pid_t pid, void* target_address, void* write_data, size_t len) {
    uint8_t* data = (uint8_t*)write_data;
    uintptr_t addr = (uintptr_t)target_address;
    size_t bytes_written = 0;

    while (bytes_written < len) {
        uintptr_t aligned_start = addr & ~(sizeof(long) - 1);
        size_t offset_in_word = addr - aligned_start;

        // 读取字长数据
        long orig_data = 0;
        if (read_memory_vm(pid, (void*)aligned_start, sizeof(long), &orig_data) != sizeof(long)) {
            LOGE("Failed to read memory at 0x%lx", aligned_start);
            return -1;
        }

        // 计算本次写入长度
        size_t copy_len = std::min(len - bytes_written, sizeof(long) - offset_in_word);

        // 修改需要的字节
        memcpy((uint8_t*)&orig_data + offset_in_word, data + bytes_written, copy_len);

        // 写回
        if (ptrace(PTRACE_POKETEXT, pid, (void*)aligned_start, (void*)orig_data) == -1) {
            LOGE("PTRACE_POKETEXT failed at 0x%lx: %s", aligned_start, strerror(errno));
            return -1;
        }

        bytes_written += copy_len;
        addr += copy_len;
    }

    return (ssize_t)bytes_written;
}

// ==================== 反汇编 ====================

std::string disasm(const uint8_t* code, size_t code_size, uint64_t address, bool isbp) {
    csh handle;
    cs_err error = cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle);
    if (error != CS_ERR_OK) {
        return std::string("cs_open failed: ") + cs_strerror(error);
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn;
    size_t count = cs_disasm(handle, code, code_size, address, 1, &insn);
    if (count == 0) {
        cs_err derr = cs_errno(handle);
        cs_close(&handle);
        return std::string("cs_disasm failed: ") + cs_strerror(derr);
    }

    std::ostringstream oss;
    uint32_t enc = 0;
    memcpy(&enc, code, sizeof(enc));
    oss << "0x" << std::hex << address << "  "
        << std::setfill('0') << std::setw(8) << std::hex << enc << "  "
        << insn[0].mnemonic << " " << insn[0].op_str;
    if (isbp) {
        oss << "  [Breakpoint]";
    }



    cs_free(insn, 1);
    cs_close(&handle);

    return oss.str();
}

void disasm_lines(pid_t pid, void* target_addr, size_t line, bool is_continue) {
    uint64_t pc_value = 0;

    if (target_addr != nullptr) {
        pc_value = (uint64_t)target_addr;
        g_pcb.last_disasm_addr = pc_value;
    } else if (is_continue && g_pcb.last_disasm_addr != 0) {
        pc_value = g_pcb.last_disasm_addr;
    } else {
        get_reg(pid, "pc", &pc_value);
        g_pcb.last_disasm_addr = pc_value;
    }

    for (size_t i = 0; i < line; i++) {
        uint8_t code[4] = {0};
        uint64_t current_addr = pc_value + (i * 4);

        if (read_memory_vm(pid, (void*)current_addr, sizeof(code), code) == sizeof(code)) {
            bool is_breakpoint = false;
            uint32_t original_inst = 0;

            // 检查是否是断点
            for (const auto& bp : g_bp_vec) {
                if ((uint64_t)bp.address == current_addr && !bp.is_temp) {
                    is_breakpoint = true;
                    original_inst = bp.origin_inst;
                    break;
                }
            }

            std::string result;
            if (is_breakpoint) {
                result = disasm((uint8_t*)&original_inst, 4, current_addr, true);
            } else {
                result = disasm(code, sizeof(code), current_addr, false);
            }

            // 标记当前PC位置
            uint64_t current_pc = 0;
            get_reg(pid, "pc", &current_pc);
            if (current_addr == current_pc) {
                std::cout << "--> ";
            } else {
                std::cout << "    ";
            }

            std::cout << result << std::endl;
        }
    }

    if (is_continue) {
        g_pcb.last_disasm_addr = pc_value + (line * 4);
    }// 如果是显示特定地址且line > 1，也要更新
    else if (target_addr != nullptr && line > 1) {
        g_pcb.last_disasm_addr = pc_value + (line * 4);
    }
}

uint8_t get_inst_type(pid_t pid, void* address) {
    auto pc = (uint64_t)address;
    if (pc == 0) {
        if (get_reg(pid, "pc", &pc) != 0) {
            return 0;
        }
    }

    uint32_t instruction;
    bool found_original = false;

    // 检查是否在断点位置
    for (const auto& bp : g_bp_vec) {
        if (bp.address == (void*)pc) {
            instruction = bp.origin_inst;
            found_original = true;
            break;
        }
    }

    if (!found_original) {
        if (read_memory_vm(pid, (void*)pc, sizeof(instruction), &instruction) != sizeof(instruction)) {
            LOGE("Failed to read instruction at 0x%lx", pc);
            return 0;
        }
    }

    csh handle;
    if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        return 0;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn;
    size_t count = cs_disasm(handle, (uint8_t*)&instruction, sizeof(instruction), pc, 1, &insn);

    uint8_t group_type = 0;
    if (count > 0 && insn[0].detail) {
        cs_detail* detail = insn[0].detail;
        if (detail->groups_count > 0) {
            group_type = detail->groups[0];
            LOGD("Instruction type: %s %s -> group %d",
                 insn[0].mnemonic, insn[0].op_str, group_type);
        }
        cs_free(insn, count);
    }

    cs_close(&handle);
    return group_type;
}

// ==================== Trace功能 ====================

void trace_start(uintptr_t start, uintptr_t end) {
    LOG_ENTER("(start=0x%lx, end=0x%lx)", start, end);

    g_pcb.trace_begin = start;
    g_pcb.trace_end = end;
    g_pcb.trace_started = false;

    // 关闭之前的trace文件
    if (g_pcb.trace_fp) {
        fclose(g_pcb.trace_fp);
        g_pcb.trace_fp = nullptr;
    }

    // 打开新的trace文件
    char filename[128];
    snprintf(filename, sizeof(filename), "trace_%016lx_%016lx.log", start, end);
    g_pcb.trace_fp = fopen(filename, "w");
    if (!g_pcb.trace_fp) {
        LOGE("Failed to open trace file: %s", filename);
    } else {
        LOGI("Trace output file: %s", filename);
    }
}

void trace_reset() {
    LOG_ENTER("");

    if (g_pcb.trace_fp) {
        fclose(g_pcb.trace_fp);
        g_pcb.trace_fp = nullptr;
    }

    g_pcb.trace_begin = 0;
    g_pcb.trace_end = 0;
    g_pcb.trace_started = false;
}

void trace_log_step(pid_t pid) {
    if (!g_pcb.trace_fp) {
        return;
    }

    uint64_t pc = 0;
    if (get_reg(pid, "pc", &pc) != 0) {
        return;
    }

    uint8_t inst[4] = {0};
    bool is_breakpoint = false;
    uint32_t original_inst = 0;

    // 检查是否在断点位置
    for (const auto& bp : g_bp_vec) {
        if ((uint64_t)bp.address == pc && !bp.is_temp) {
            is_breakpoint = true;
            original_inst = bp.origin_inst;
            break;
        }
    }

    if (is_breakpoint) {
        // 使用原始指令
        memcpy(inst, &original_inst, 4);
    } else {
        // 读取当前指令
        if (read_memory_vm(pid, (void*)pc, sizeof(inst), inst) != sizeof(inst)) {
            fprintf(g_pcb.trace_fp, "[read fail] PC=0x%lx\n", pc);
            fflush(g_pcb.trace_fp);
            return;
        }
    }

    std::string line = disasm(inst, sizeof(inst), pc, false);
    fprintf(g_pcb.trace_fp, "%s\n", line.c_str());
    fflush(g_pcb.trace_fp);
}

// ==================== 工具函数 ====================

void hexdump(const void* data, size_t size, uintptr_t base_addr) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    const size_t bytes_per_line = 16;

    for (size_t i = 0; i < size; i += bytes_per_line) {
        printf("0x%08lx  ", base_addr + i);

        // 打印十六进制
        for (size_t j = 0; j < bytes_per_line; j++) {
            if (i + j < size) {
                printf("%02x ", bytes[i + j]);
            } else {
                printf("   ");
            }

            if (j == 7) {
                printf(" ");
            }
        }

        // 打印ASCII
        printf(" |");
        for (size_t j = 0; j < bytes_per_line && i + j < size; j++) {
            uint8_t byte = bytes[i + j];
            if (byte >= 32 && byte <= 126) {
                printf("%c", byte);
            } else {
                printf(".");
            }
        }
        printf("|\n");
    }
}

std::vector<std::string> split_space(const std::string& s) {
    std::istringstream iss(s);
    std::vector<std::string> tokens;
    std::string t;
    while (iss >> t) {
        tokens.push_back(t);
    }
    return tokens;
}

pid_t get_process_pid(const char* process_name) {
    if (process_name == nullptr) {
        return -1;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pidof -s %s", process_name);

    FILE* fp = popen(cmd, "r");
    if (!fp) {
        return -1;
    }

    pid_t pid = -1;
    if (fscanf(fp, "%d", &pid) != 1) {
        pid = -1;
    }

    pclose(fp);
    LOGI("Process '%s' PID: %d", process_name, pid);
    return pid;
}