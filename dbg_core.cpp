//
// Created by XiaM on 2025/9/9.
//
#include "dbg_core.h"

PCB g_pcb;

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

long attach_process(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);

    long result = ptrace(PTRACE_ATTACH,pid,NULL,NULL);
    if(-1 == result){
        LOGE("PTRACE_ATTACH %s", strerror(errno));
        exit(1);
    }

    return result;
}

long detach_process(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);

    long result = ptrace(PTRACE_DETACH,pid,NULL,NULL);
    if(-1 == result){
        LOGE("PTRACE_DETACH %s", strerror(errno));
    }

    return result;
}

void parse_thread_signal(pid_t pid) {
    //LOG_ENTER("pid=%d", pid);

    int status = 0;
    pid_t r = waitpid(pid, &status, 0);  // 阻塞等待该线程的状态变化
    if (r == -1) {
        LOGE("waitpid failed: %s", strerror(errno));
        return;
    }

    if (!WIFSTOPPED(status)) {
        return;
    }

    // 读一次 PC
    uint64_t pc = 0;
    (void)get_reg(pid, "pc", &pc);

    int sig = WSTOPSIG(status);
    siginfo_t info{};
    ptrace(PTRACE_GETSIGINFO, pid, 0, &info);
    LOGD("stopped:si_signo=%d si_code=%d si_pid=%d", info.si_signo, info.si_code, info.si_pid);

    // trace模式：检查是否应该停止，但让信号正常处理
    if (g_pcb.current_command == CommandType::TRACE) {
        // 检查停止条件
        if (sig == SIGTRAP && info.si_code == TRAP_BRKPT) {
            // 命中断点：停止trace
            LOG("trace命中断点 PC=0x%lx，停止trace", pc);
            trace_reset(); 
        } else if (pc == g_pcb.trace_end) {
            // 到达结束地址：停止trace
            trace_log_step(pid);  // 记录结束地址的指令
            LOG("trace到达结束地址 PC=0x%lx，停止trace", pc);
            trace_reset();
        } else {
            // 继续trace：记录当前步骤（无论跳转到哪里）
            trace_log_step(pid);
        }
    }
    
    // 统一的命令处理
    if (g_pcb.current_command != CommandType::NONE) {
        handle_command_signal(pid, pc, sig, info);
        return;
    } else {
        // 程序被信号打断，重置反汇编地址
        if (sig == SIGSTOP || (sig == SIGTRAP && info.si_code != TRAP_BRKPT && info.si_code != TRAP_HWBKPT)) {
            g_pcb.last_disasm_addr = 0; 
            LOGE("被信号 %d 打断，PC=0x%lx", sig, pc);
        }
    }
}

void handle_command_signal(pid_t pid, uint64_t pc, int sig, siginfo_t info) {
    CommandType cmd = g_pcb.current_command;
    
    switch (cmd) {
        case CommandType::STEP_INTO:
        case CommandType::STEP_OVER:
        case CommandType::TRACE:  // 
        {
            if (sig == SIGTRAP && info.si_code == TRAP_BRKPT) {
                LOG("命中断点 PC=0x%lx", pc);
                g_pcb.last_disasm_addr = 0; // 重置反汇编地址，让下次u命令从当前PC开始
                
                // 检查是否是步过的临时断点
                if (cmd == CommandType::STEP_OVER && bp_is_temp_for_step_over((void*)pc)) {
                    // 步过操作完成：清除临时断点，显示结果
                    LOG("步过操作完成 PC=0x%lx", pc);
                    
                    for (size_t i = 0; i < g_bp_vec.size(); i++) {
                        if (g_bp_vec[i].address == (void*)pc && g_bp_vec[i].is_temp) {
                            bp_clear(pid, i);
                            break;
                        }
                    }
                    
                    // 显示当前指令
                    disasm_lines(pid, nullptr, 1, false);
                    
                    // 清除命令状态（但trace应该继续）
                    if (cmd != CommandType::TRACE) {
                        g_pcb.current_command = CommandType::NONE;
                    }
                } else {
                    // 普通断点：临时禁用断点，执行单步
                    bp_temp_disable(pid, (void*)pc);
                    print_all_regs(pid);
                    
                    // 如果是步过命令遇到普通断点，清除之前的临时断点
                    if (cmd == CommandType::STEP_OVER) {
                        bp_clear_all_temp_for_step_over(pid);
                    }
                    
                    // 执行单步
                    if (cmd == CommandType::STEP_INTO || cmd == CommandType::TRACE) {
                        step_into(pid);
                    } else {
                        step_over(pid);
                    }
                    // 保持命令状态，等待单步完成信号
                }
                
            } else if (sig == SIGTRAP && info.si_code == TRAP_HWBKPT) {//HWBKPT 是 singelstep后的信号
                // 单步完成：恢复断点，显示结果，清除命令状态
                LOGD("单步完成 PC=0x%lx", pc);
                
                if (g_pcb.temp_disabled_bp != nullptr) {
                    bp_restore_temp_disabled(pid);
                }
                
                // 清除任何遗留的步过临时断点
                if (cmd == CommandType::STEP_OVER) {
                    bp_clear_all_temp_for_step_over(pid);
                }
                
                // 显示当前指令
                disasm_lines(pid, nullptr, 1, false);
                
                // 清除命令状态（但trace应该继续）
                if (cmd != CommandType::TRACE) {
                    g_pcb.current_command = CommandType::NONE;
                } else {
                    // trace模式：自动继续下一步
                    step_into(pid);
                }
            }
        }
            break;
            
        case CommandType::CONTINUE:
        {
            if (sig == SIGTRAP && info.si_code == TRAP_BRKPT) {
                LOG("命中断点 PC=0x%lx", pc);
                g_pcb.last_disasm_addr = 0; // 重置反汇编地址，让下次u命令从当前PC开始
                bp_temp_disable(pid, (void*)pc);
                
                // 检查是否是trace模式的起始断点
                if (g_pcb.trace_begin != 0 && pc == g_pcb.trace_begin) {
                    LOG("命中trace起始地址断点，开始trace模式");
                    g_pcb.trace_ever_into = true;
                    
                    // 找到并清除trace起始地址的断点，避免循环命中
                    for (size_t i = 0; i < g_bp_vec.size(); i++) {
                        if (g_bp_vec[i].address == (void*)pc) {
                            LOG("清除trace起始地址断点 [%zu]", i);
                            bp_clear(pid, i);
                            break;
                        }
                    }
                    
                    // 切换到trace模式并立即开始trace
                    g_pcb.current_command = CommandType::TRACE;
                    step_into(pid);  // 立即单步，开始trace
                   
                } else {
                    // 普通断点：停下来等待用户命令
                    print_all_regs(pid);
                    disasm_lines(pid, nullptr, 1, false);  // 显示当前指令
                    
                    // 清除命令状态，停下来等待用户命令
                    g_pcb.current_command = CommandType::NONE;
                }
                
            } else if (sig == SIGTRAP && info.si_code == TRAP_HWBKPT) {
                // 单步完成：恢复断点，继续执行
                LOG("跳过断点完成，继续执行 PC=0x%lx", pc);
                
                if (g_pcb.temp_disabled_bp != nullptr) {
                    bp_restore_temp_disabled(pid);
                }
                
                // 继续执行
                resume_process(pid);
                // 保持命令状态，继续等待下一个断点或停止信号
            }
        }
            break;
            
        default:
            // 不应该到达这里
            g_pcb.current_command = CommandType::NONE;
            break;
    }
}

// ================================
// 新的状态机信号处理系统
// ================================

void parse_signal_new(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);

    // 等待信号
    int status;
    if (waitpid(pid, &status, WUNTRACED) == -1) {
        LOGE("waitpid failed: %s", strerror(errno));
        return;
    }
    
    // 获取PC和信号信息
    uint64_t pc = 0;
    get_reg(pid, "pc", &pc);
    
    int sig = WSTOPSIG(status);
    siginfo_t info{};
    ptrace(PTRACE_GETSIGINFO, pid, 0, &info);
    
    LOGD("状态=%d, PC=0x%lx, sig=%d, code=%d",
        (int)g_pcb.debugger_state, pc, sig, info.si_code);
    
    // 根据当前状态分发处理
    switch (g_pcb.debugger_state) {
        case DebuggerState::IDLE:
            handle_idle_signal(pid, pc, sig, info);
            break;
        case DebuggerState::CONTINUE:
            handle_continue_signal(pid, pc, sig, info);
            break;
        case DebuggerState::STEP:
            handle_step_signal(pid, pc, sig, info);
            break;
        case DebuggerState::TRACE_ACTIVE:
            handle_trace_signal_new(pid, pc, sig, info);
            break;
        default:
            LOG("未知调试器状态: %d", (int)g_pcb.debugger_state);
            g_pcb.debugger_state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
            break;
    }
}

// IDLE状态：处理意外的信号（程序被外部中断）
void handle_idle_signal(pid_t pid, uint64_t pc, int sig, siginfo_t info) {
    LOG_ENTER("(pid=%d, pc=0x%lx, sig=%d, code=%d)", pid, pc, sig, info.si_code);

    if (sig == SIGSTOP || (sig == SIGTRAP && info.si_code != TRAP_BRKPT && info.si_code != TRAP_HWBKPT)) {
        LOG("程序被信号 %d 中断，PC=0x%lx", sig, pc);
        g_pcb.last_disasm_addr = 0; // 重置反汇编地址
        // 保持IDLE状态，等待用户命令
    } else {
        LOG("IDLE状态收到意外信号: sig=%d, code=%d", sig, info.si_code);
    }
}

// CONTINUE状态：处理运行中的断点信号
void handle_continue_signal(pid_t pid, uint64_t pc, int sig, siginfo_t info) {
    LOG_ENTER("(pid=%d, pc=0x%lx, sig=%d, code=%d)", pid, pc, sig, info.si_code);
    
    if (sig == SIGTRAP && info.si_code == TRAP_BRKPT) {
        LOG("命中断点 PC=0x%lx", pc);
        g_pcb.last_disasm_addr = 0;
        bp_temp_disable(pid, (void*)pc);
        
        // 检查是否是trace起始断点
        if (g_pcb.trace_begin != 0 && pc == g_pcb.trace_begin) {
            LOG("trace起始断点，启动trace模式");
            g_pcb.trace_ever_into = true;
            
            // 清除起始断点
            for (size_t i = 0; i < g_bp_vec.size(); i++) {
                if (g_bp_vec[i].address == (void*)pc) {
                    bp_clear(pid, i);
                    break;
                }
            }
            
            // 切换到trace状态并开始
            g_pcb.debugger_state = DebuggerState::TRACE_ACTIVE;
            g_pcb.current_command = CommandType::TRACE;  // 设置命令类型，让trace_log_step正常工作
            step_into(pid);
        } else {
            // 普通断点：显示信息，回到空闲状态
            print_all_regs(pid);
            disasm_lines(pid, nullptr, 1, false);
            g_pcb.debugger_state = DebuggerState::IDLE;
            g_pcb.need_wait_signal = false;
        }
    } else {
        LOG("CONTINUE状态收到意外信号: sig=%d, code=%d", sig, info.si_code);
        g_pcb.debugger_state = DebuggerState::IDLE;
        g_pcb.need_wait_signal = false;
    }
}

// STEP状态：处理单步完成信号
void handle_step_signal(pid_t pid, uint64_t pc, int sig, siginfo_t info) {
    LOG_ENTER("(pid=%d, pc=0x%lx, sig=%d, code=%d)", pid, pc, sig, info.si_code);
    if (sig == SIGTRAP && info.si_code == TRAP_HWBKPT) {
        LOG("单步完成 PC=0x%lx", pc);
        
        // 恢复临时禁用的断点
        if (g_pcb.temp_disabled_bp != nullptr) {
            bp_restore_temp_disabled(pid);
        }
        
        // 显示结果，回到空闲状态
        disasm_lines(pid, nullptr, 1, false);
        g_pcb.debugger_state = DebuggerState::IDLE;
        g_pcb.need_wait_signal = false;
    } else if (sig == SIGTRAP && info.si_code == TRAP_BRKPT) {
        LOG("单步时命中断点 PC=0x%lx", pc);
        // 处理单步过程中遇到的断点
        bp_temp_disable(pid, (void*)pc);
        print_all_regs(pid);
        disasm_lines(pid, nullptr, 1, false);
        g_pcb.debugger_state = DebuggerState::IDLE;
        g_pcb.need_wait_signal = false;
    } else {
        LOG("STEP状态收到意外信号: sig=%d, code=%d", sig, info.si_code);
        g_pcb.debugger_state = DebuggerState::IDLE;
        g_pcb.need_wait_signal = false;
    }
}

// TRACE_ACTIVE状态：处理trace过程中的信号
void handle_trace_signal_new(pid_t pid, uint64_t pc, int sig, siginfo_t info) {
    LOG_ENTER("(pid=%d, pc=0x%lx, sig=%d, code=%d)", pid, pc, sig, info.si_code);
    // 检查停止条件
    if (sig == SIGTRAP && info.si_code == TRAP_BRKPT) {
        LOG("trace过程中命中断点 PC=0x%lx，停止trace", pc);
        trace_reset();
        g_pcb.debugger_state = DebuggerState::IDLE;
        bp_temp_disable(pid, (void*)pc);
        print_all_regs(pid);
        disasm_lines(pid, nullptr, 1, false);
    } else if (pc == g_pcb.trace_end) {
        LOG("trace到达结束地址 PC=0x%lx，停止trace", pc);
        trace_log_step(pid);  // 记录结束地址的指令
        trace_reset();
        disasm_lines(pid, nullptr, 1, false);
        g_pcb.debugger_state = DebuggerState::IDLE;
    } else if (sig == SIGTRAP && info.si_code == TRAP_HWBKPT) {
        // 正常的trace单步
        trace_log_step(pid);
        
        // 恢复可能的临时禁用断点
        if (g_pcb.temp_disabled_bp != nullptr) {
            bp_restore_temp_disabled(pid);
        }
        
        // 继续下一步trace
        step_into(pid);
        // 保持TRACE_ACTIVE状态
    } else {
        LOG("TRACE状态收到意外信号: sig=%d, code=%d", sig, info.si_code);
        trace_reset();
        g_pcb.debugger_state = DebuggerState::IDLE;
    }
}


int suspend_process(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);

    int result = kill(pid,SIGSTOP);
    return result;
}

long resume_process(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);

    long result = ptrace(PTRACE_CONT,pid,NULL,NULL);
    if (result == -1) {
        LOGE("waitpid failed: %s", strerror(errno));
        return result;
    }
    
    // 设置等待信号标志，让command_loop等待断点或其他信号
    g_pcb.need_wait_signal = true;
    return result;
}

long get_reg(pid_t pid, const char* reg_name, uint64_t* value) {
    //LOG_ENTER("(pid=%d, reg_name=%s, value=%p)", pid, reg_name, value);

    user_regs_struct regs{};
    iovec iov{&regs, sizeof(user_regs_struct)};

    long result = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    if (result == -1) {
        LOGE("PTRACE_GETREGSET failed: %s", strerror(errno));
        return -1;
    }

    auto it = reg_map.find(reg_name);
    if(it == reg_map.end()) {
        LOGE("Unknown reg: %s", reg_name);
        return -1;
    }

    // 通过偏移访问
    *value = *reinterpret_cast<const uint64_t*>(reinterpret_cast<const char*>(&regs) + it->second);
    return 0;
}

long set_reg(pid_t pid, const char* reg_name, uint64_t value) {
    LOG_ENTER("(pid=%d, reg_name=%s, value=0x%lx)", pid, reg_name, (unsigned long)value);

    user_regs_struct regs{};
    iovec iov{&regs, sizeof(user_regs_struct)};

    // 先读取现有寄存器状态
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

    *reinterpret_cast<uint64_t*>(reinterpret_cast<char*>(&regs) + it->second) = value;

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
        std::cout << "Failed to read registers\n";
        return false;
    }

    std::cout << std::hex << std::setfill('0');

//    for (int i = 0; i < 31; i++) {
//        std::cout << "x" << std::setw(2) << i << "=0x" << std::setw(16) << regs.regs[i];
//        if ((i + 1) % 4 == 0) {
//            std::cout << "\n";
//        } else {
//            std::cout << "  ";
//        }
//    }


//    std::cout << "pstate=0x" << std::setw(8) << regs.pstate ;
//    std::cout << "sp =0x" << std::setw(16) << regs.sp << "  ";
    std::cout << "pc =0x" << std::setw(16) << regs.pc << "\n";

    std::cout << std::dec;
    return true;
}

void print_single_reg(const std::string& reg_name, uint64_t value) {
    std::cout << reg_name << " = 0x" << std::hex << std::setfill('0') << std::setw(16) << value;
    std::cout << " (" << std::dec << value << ")" << std::endl;
}

std::vector<std::string> split_space(const std::string &s) {
    std::istringstream iss(s);
    std::vector<std::string> tokens;
    std::string t;
    while (iss >> t) tokens.push_back(t);
    return tokens;
}

pid_t get_process_pid(const char *process_name) {
    if (process_name == nullptr) exit(1);

    char cmd[256];
    std::snprintf(cmd, sizeof(cmd), "pidof -s %s", process_name); // -s 只要一个PID

    FILE* fp = popen(cmd, "r");
    if (!fp) exit(1);;

    pid_t pid = -1;
    if (fscanf(fp, "%d", &pid) != 1) {
        pid = -1;
    }

    LOG("get_process_pid: %d",pid);

    pclose(fp);
    return pid;
}

long step_into(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);

    long result = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    if (result == -1) {
        LOGE("PTRACE_SINGLESTEP failed: %s", strerror(errno));
        return result;
    }
    
    g_pcb.need_wait_signal = true;
    return result;
}

long step_over(pid_t pid){
    LOG_ENTER("(pid=%d)", pid);

    uint64_t pc_value;
    if (get_reg(pid, "pc", &pc_value) != 0) {
        LOGE("Failed to get PC register");
        return -1;
    }

    uint8_t inst_type = get_inst_type(pid, (void*)pc_value);
    
    if (inst_type == CS_GRP_CALL) {
        // BL/BLR ：在返回地址设置临时断点
        uintptr_t return_addr = pc_value + 4;
        LOGD("step_over 检测到 CS_GRP_CALL 设置临时断点: 0x%lx", return_addr);
        
        if (!bp_set_temp_for_step_over(pid, (void*)return_addr)) {
            LOGE("step_over 临时断点设置失败");
            return -1;
        }
        
        // 继续执行
        return resume_process(pid);
        
    } else {
        LOGE("step_over 非调用指令，单步");
        return step_into(pid);
    }
}

ssize_t read_memory_vm(pid_t pid, void *target_address, size_t len, void *save_buffer) {
    //LOG_ENTER("(pid=%d, target_address=%p, len=%zu, save_buffer=%p)", pid, target_address, len, save_buffer);

    iovec local{save_buffer,len};
    iovec remote{target_address,len};
    ssize_t result = process_vm_readv(pid,&local,1,&remote,1,0);
    if (result == -1) {
        LOGE("process_vm_readv failed: %s", strerror(errno));
    }
    return result;
}

void hexdump(const void* data, size_t size, uintptr_t base_addr) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    const size_t bytes_per_line = 16;
    
    for (size_t i = 0; i < size; i += bytes_per_line) {
        // 打印地址
        printf("0x%08lx  ", base_addr + i);
        
        // 打印十六进制字节 (分两组，每组8字节)
        for (size_t j = 0; j < bytes_per_line; j++) {
            if (i + j < size) {
                printf("%02x ", bytes[i + j]);
            } else {
                printf("   "); // 空白填充
            }
            
            // 在第8个字节后添加额外空格
            if (j == 7) {
                printf(" ");
            }
        }
        
        // 打印ASCII表示
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

ssize_t write_memory_vm(pid_t pid, void *target_address, void *write_data, size_t len) {
    LOG_ENTER("(pid=%d, target_address=%p, write_data=%p, len=%zu)", pid, target_address, write_data, len);

    iovec local{write_data, len};
    iovec remote{target_address, len};
    ssize_t result = process_vm_writev(pid, &local, 1, &remote, 1, 0);

    if (result != -1) {
        LOG("直接写入成功: %zd bytes", result);
    }else{
        LOGE("process_vm_writev failed: %s", strerror(errno));
    }

    return result;
}

ssize_t write_memory_ptrace(pid_t pid, void *target_address, void *write_data, size_t len) {
    //LOG_ENTER("(pid=%d, target_address=%p, write_data=%p, len=%zu)", pid, target_address, write_data, len);

    uint8_t *data = (uint8_t*)write_data;
    uintptr_t addr = (uintptr_t)target_address;
    size_t bytes_written = 0;

    while(bytes_written < len){
        uintptr_t aligned_start =  addr & ~(sizeof(long) - 1);//向前对齐
        size_t offset_in_word = addr - aligned_start;//对齐后多写的差值

        //用 VM 读取
        uintptr_t orig_data = 0;
        if (read_memory_vm(pid, (void*)aligned_start, sizeof(long), &orig_data) != sizeof(uintptr_t)) {
            LOGE("write_memory_ptrace 读失败 0x%lx", aligned_start);
            return -1;
        }

        // 计算本次写入长度
        size_t copy_len = std::min(len - bytes_written, sizeof(uintptr_t) - offset_in_word);

        // 修改需要的字节
        memcpy((uint8_t*)&orig_data + offset_in_word, data + bytes_written, copy_len);

        //ptrace 写回
        if (ptrace(PTRACE_POKETEXT, pid, (void*)aligned_start, (void*)orig_data) == -1) {
            LOGE("PTRACE_POKETEXT 失败 at 0x%lx: %s", aligned_start, strerror(errno));
            return -1;
        }

        bytes_written += copy_len;
        addr += copy_len;
    }

    LOGD("ptrace write success: %zu bytes", bytes_written);
    return (ssize_t)bytes_written;
}

void disasm_lines(pid_t pid, void* target_addr, size_t line, bool is_continue) {
    //LOG_ENTER("(pid=%d, target_addr=%p, line=%zu, is_continue=%d)", pid, target_addr, line, is_continue);

    uint64_t pc_value = 0;

    if (target_addr != nullptr) {
        // 指定了具体地址，重置全局状态
        pc_value = (uint64_t)target_addr;
        g_pcb.last_disasm_addr = pc_value;
    } else if (is_continue && g_pcb.last_disasm_addr != 0) {
        // 连续反汇编，从上次位置继续
        pc_value = g_pcb.last_disasm_addr;
    } else {
        // 重置到当前PC
        get_reg(pid, "pc", &pc_value);
        g_pcb.last_disasm_addr = pc_value;
    }

    // 逐条反汇编，每条4字节
    for(size_t i = 0; i < line; i++) {
        uint8_t code[4] = {0};
        uint64_t current_addr = pc_value + (i * 4);
        
        if(read_memory_vm(pid, (void*)current_addr, sizeof(code), code) == sizeof(code)) {
            // 检查是否是断点地址
            bool is_breakpoint = false;
            uint32_t original_inst = 0;
            for(const auto& bp : g_bp_vec) {
                if((uint64_t)bp.address == current_addr) {
                    is_breakpoint = true;
                    original_inst = bp.origin_inst;
                    break;
                }
            }

            std::string result;
            if(is_breakpoint) {
                // 使用原始指令进行反汇编
                result = disasm((uint8_t*)&original_inst, 4, current_addr,is_breakpoint);
            } else {
                result = disasm(code, sizeof(code), current_addr);
            }
            LOG("%s", result.c_str());

        } 
    }
    
    // 更新下次反汇编的起始地址
    if (is_continue || target_addr != nullptr) {
        g_pcb.last_disasm_addr = pc_value + (line * 4);
    }
}

bool bp_set(pid_t pid, void *address) {
    LOG_ENTER("(pid=%d, address=%p)", pid, address);
    uint32_t BRK = 0xD4200000;

    do{
        //已存在 跳过
        for(auto& bp:g_bp_vec){
            if(bp.address == address) return true;
        }

        uint32_t orig  = 0;
        if (read_memory_vm(pid, address, 4, &orig) != 4) break;
        if (write_memory_ptrace(pid, address, &BRK, 4) != 4)  break;

        breakpoint newbp{address, orig};
        g_bp_vec.emplace_back(newbp);
        print_singel_bp(g_bp_vec.size()-1);
        return true;

    }while(0);

    LOGE("bp_set 失败");
    return false;
}

// 设置步过操作的临时断点
bool bp_set_temp_for_step_over(pid_t pid, void *address) {
    LOG_ENTER("(pid=%d, address=%p)", pid, address);
    uint32_t BRK = 0xD4200000;

    do{
        //已存在 跳过
        for(auto& bp:g_bp_vec){
            if(bp.address == address) {
                // 如果已存在，标记为临时断点
                bp.is_temp = true;
                return true;
            }
        }

        uint32_t orig  = 0;
        if (read_memory_vm(pid, address, 4, &orig) != 4) break;
        if (write_memory_ptrace(pid, address, &BRK, 4) != 4)  break;

        breakpoint newbp{address, orig, true};  // 标记为临时断点
        g_bp_vec.emplace_back(newbp);
        // 临时断点不打印给用户看 print_singel_bp(g_bp_vec.size()-1);
        return true;

    }while(0);

    LOGE("bp_set_temp_for_step_over 失败");
    return false;
}

bool bp_clear(pid_t pid, size_t index) {
    LOG_ENTER("(pid=%d, index=%zu)", pid, index);

    breakpoint& bp = g_bp_vec[index];

    /*如果在程序遇到断点trap的时候先禁用了断点 此时删除断点 当再go的时候 断点又被写回了
    *检查要删除的断点是否是当前临时禁用的断点*/
    if (bp.address == g_pcb.temp_disabled_bp) {
        LOGD("清除临时禁用状态: 0x%lx", (unsigned long)bp.address);
        g_pcb.temp_disabled_bp = nullptr;  // 清除临时禁用状态
        // 断点已经被临时禁用 不需要写回原数据了
    } else {
        // 如果断点当前是激活状态，需要写回原始指令
        if (write_memory_ptrace(pid, bp.address, (void *) &bp.origin_inst, 4) != 4) {
            LOGE("bp_clear 写回指令失败");
            return false;
        }
    }

    g_bp_vec.erase(g_bp_vec.begin() + index);
    return true;
}

void bp_show() {
    LOG_ENTER("");

    for (size_t i = 0; i < g_bp_vec.size(); ++i) {
        // 跳过步过操作的临时断点
        if (!g_bp_vec[i].is_temp) {
            print_singel_bp(i);
        }
    }
}



void print_singel_bp(size_t index) {
    const auto& bp = g_bp_vec[index];
    printf("[%zu] addr=0x%016lx inst=0x%08x\n",
           index,
           (unsigned long)bp.address,
           bp.origin_inst);
}

// 临时禁用指定地址的断点（写回原始指令）
void bp_temp_disable(pid_t pid, void* address) {
    LOG_ENTER("(pid=%d, address=%p)", pid, address);
    
    for (const auto& bp : g_bp_vec) {
        if (bp.address == address) {
            // 写回原始指令
            if (write_memory_ptrace(pid, bp.address, (void*)&bp.origin_inst, 4) == 4) {
                g_pcb.temp_disabled_bp = address;
                LOGD("临时禁用断点: 0x%lx", (unsigned long)address);
            } else {
                LOGE("禁用断点失败: 0x%lx", (unsigned long)address);
            }
            break;
        }
    }
}

// 恢复临时禁用的断点（重新写入BRK）
void bp_restore_temp_disabled(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);
    
    if (g_pcb.temp_disabled_bp != nullptr) {
        uint32_t BRK = 0xD4200000;
        if (write_memory_ptrace(pid, g_pcb.temp_disabled_bp, (void*)&BRK, 4) == 4) {
            LOGD("恢复临时禁用的断点: 0x%lx", (unsigned long)g_pcb.temp_disabled_bp);
            g_pcb.temp_disabled_bp = nullptr;
        } else {
            LOGE("恢复断点失败: 0x%lx", (unsigned long)g_pcb.temp_disabled_bp);
        }
    }
}

// 检查指定地址是否有断点
bool bp_is_at_address(void* address) {
    for (const auto& bp : g_bp_vec) {
        if (bp.address == address) {
            return true;
        }
    }
    return false;
}

// 检查是否是步过的临时断点
bool bp_is_temp_for_step_over(void* address) {
    for (const auto& bp : g_bp_vec) {
        if (bp.address == address && bp.is_temp) {
            return true;
        }
    }
    return false;
}

// 清除所有步过的临时断点
void bp_clear_all_temp_for_step_over(pid_t pid) {
    for (int i = g_bp_vec.size() - 1; i >= 0; i--) {
        if (g_bp_vec[i].is_temp) {
            LOGD("清除步过临时断点: 0x%lx", (unsigned long)g_bp_vec[i].address);
            bp_clear(pid, i);
        }
    }
}

std::string disasm(const uint8_t *code , size_t code_size, uint64_t address, bool isbp){
    csh  handle;
    cs_err error = cs_open(CS_ARCH_AARCH64,CS_MODE_ARM,&handle);
    if(error != CS_ERR_OK){
        return std::string("cs_open failed: ") + cs_strerror(error);
    }

    cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON);//开启详细模式

    cs_insn* insn;
    size_t count = cs_disasm(handle, code, code_size, address, 1, &insn);
    if (count == 0) {
        cs_err derr = cs_errno(handle);
        cs_close(&handle);
        return std::string("cs_disasm failed: ") + cs_strerror(derr);
    }

    std::ostringstream oss;
    oss << "0x" << std::hex << address << " " << insn[0].mnemonic << " " << insn[0].op_str;
    if (isbp) {
        oss << " [Breakpoint]";
    }

    cs_free(insn,1);
    cs_close(&handle);

    return oss.str();
}

uint8_t get_inst_type(pid_t pid, void* address) {

    // 如果地址为空，获取当前PC
    auto pc = (uint64_t)address;
    if (pc == 0) {
        if (get_reg(pid, "pc", &pc) != 0) {
            return 0; // 返回0表示失败
        }
    }

    // 如果PC在断点位置，使用保存的原始指令
    uint32_t instruction;
    bool found_original = false;
    
    for (const auto& bp : g_bp_vec) {
        if (bp.address == (void*)pc) {
            instruction = bp.origin_inst;
            LOGD("get_inst_type: 在断点位置0x%lx使用原始指令=0x%x", pc, instruction);
            found_original = true;
            break;
        }
    }
    
    // 如果不在断点位置，正常读取内存
    if (!found_original) {
        if (read_memory_vm(pid, (void*)pc, sizeof(instruction), &instruction) != sizeof(instruction)) {
            LOGE("get_inst_type: read_memory_vm 失败！");
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
    if (insn[0].detail) {
        cs_detail* detail = insn[0].detail;
        group_type = detail->groups[0];
        LOGD("指令类型: %s %s -> CS_GRP_%d", insn[0].mnemonic, insn[0].op_str, group_type);
        cs_free(insn, count);
    }
    
    cs_close(&handle);
    return group_type;
}

void trace_start(uintptr_t start, uintptr_t end) {
    g_pcb.trace_begin = start;
    g_pcb.trace_end = end;

    // 如果之前的trace文件还打开着，先关闭它
    if (g_pcb.trace_fp) {
        std::fflush(g_pcb.trace_fp);
        std::fclose(g_pcb.trace_fp);
        g_pcb.trace_fp = nullptr;
    }

    char filename[128];
    std::snprintf(filename, sizeof(filename),
                  "trace_%016lx_%016lx.log",
                  (unsigned long)start, (unsigned long)end);

//    g_pcb.trace_fp = std::fopen(filename, "w");
    g_pcb.trace_fp = std::fopen("trace.log", "w");
    if (!g_pcb.trace_fp) {
        LOGE("Trace.start fp 打开失败");
    }
}

void trace_log_step(pid_t pid) {
    if (g_pcb.current_command != CommandType::TRACE || !g_pcb.trace_fp) return;

    uint64_t pc = 0;
    if (get_reg(pid, "pc", &pc) != 0) return;

    uint8_t inst[4] = {0};
    if (read_memory_vm(pid, (void*)pc, sizeof(inst), inst) != sizeof(inst)) {
        std::fprintf(g_pcb.trace_fp, "[read fail] PC=0x%lx\n", pc);
        std::fflush(g_pcb.trace_fp);
        LOGE("[trace] [read fail] PC=0x%lx", pc);
        return;
    }
    
    std::string line = ::disasm(inst, sizeof(inst), pc, false);
    std::fprintf(g_pcb.trace_fp, "%s\n", line.c_str());
    std::fflush(g_pcb.trace_fp);
    

    LOG("[trace] %s", line.c_str());
    std::fflush(stdout);
}

void trace_reset() {
    if (g_pcb.trace_fp) {
        std::fflush(g_pcb.trace_fp);
        std::fclose(g_pcb.trace_fp);
        g_pcb.trace_fp = nullptr;
    }
    // 重置到空闲状态
    g_pcb.debugger_state = DebuggerState::IDLE;
    g_pcb.current_command = CommandType::NONE; // 保留兼容
    g_pcb.trace_ever_into = false;
    g_pcb.need_wait_signal = false;
    g_pcb.trace_begin = 0;
    g_pcb.trace_end = 0;
}
