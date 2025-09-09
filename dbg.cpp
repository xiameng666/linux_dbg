//
// Created by XiaM on 2025/9/9.
//
#include "dbg.h"
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
        // 特殊寄存器
        {"sp",   offsetof(struct user_regs_struct, sp)},
        {"pc",   offsetof(struct user_regs_struct, pc)},
        {"pstate", offsetof(struct user_regs_struct, pstate)},
};

long attach_process(pid_t pid) {
    LOG_ENTER();

    long result = ptrace(PTRACE_ATTACH,pid,NULL,NULL);
    if(-1 == result){
        LOGE("PTRACE_ATTACH %s", strerror(errno));
        exit(1);
    }

    return result;
}

long detach_process(pid_t pid) {
    LOG_ENTER();

    long result = ptrace(PTRACE_DETACH,pid,NULL,NULL);
    if(-1 == result){
        LOGE("PTRACE_DETACH %s", strerror(errno));
    }

    return result;
}

void parse_thread_signal(pid_t pid) {
    LOG_ENTER();

    int status = 0;
    pid_t r = waitpid(pid, &status, 0);  // 阻塞等待该线程的状态变化
    if (r == -1) {
        LOGE("waitpid failed: %s", strerror(errno));
        return;
    }

    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        LOG("stopped: tid=%d sig=%d", r, sig);
        siginfo_t info{};
        LOG("si_signo=%d si_code=%d si_pid=%d", info.si_signo, info.si_code, info.si_pid);
    } else if (WIFEXITED(status)) {
        LOG("exited: tid=%d code=%d", r, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        LOG("signaled: tid=%d sig=%d", r, WTERMSIG(status));
    } else if (WIFCONTINUED(status)) {
        LOG("continued: tid=%d", r);
    }
}

int suspend_process(pid_t pid) {
    LOG_ENTER();

    int result = kill(pid,SIGSTOP);
    return result;
}

long resume_process(pid_t pid) {
    LOG_ENTER();

    long result = ptrace(PTRACE_CONT,pid,NULL,NULL);
    if (result == -1) {
        LOGE("waitpid failed: %s", strerror(errno));
    }

    return result;
}

long get_reg(pid_t pid, const char* reg_name, uint64_t* value) {
    LOG_ENTER();

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
    LOG_ENTER();
    
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
    LOG_ENTER();

    user_regs_struct regs{};
    iovec iov{&regs, sizeof(user_regs_struct)};
    long result = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    if (result == -1) {
        LOGE("PTRACE_GETREGSET failed: %s", strerror(errno));
        std::cout << "Failed to read registers\n";
        return false;
    }

    std::cout << std::hex << std::setfill('0');

    for (int i = 0; i < 31; i++) {
        std::cout << "x" << std::setw(2) << i << "=0x" << std::setw(16) << regs.regs[i];
        if ((i + 1) % 4 == 0) {
            std::cout << "\n";
        } else {
            std::cout << "  ";
        }
    }

    std::cout << "sp =0x" << std::setw(16) << regs.sp << "  ";
    std::cout << "pc =0x" << std::setw(16) << regs.pc << "  ";
    std::cout << "pstate=0x" << std::setw(8) << regs.pstate << "\n";
    
    std::cout << std::dec; // 恢复十进制显示
    return true;
}

void print_single_reg(const std::string& reg_name, uint64_t value) {
    LOG_ENTER();
    std::cout << reg_name << " = 0x" << std::hex << std::setfill('0') << std::setw(16) << value;
    std::cout << " (" << std::dec << value << ")" << std::endl;
}

void command_loop(pid_t pid) {
    LOG_ENTER();

    std::string cmdline;
    while(true){
        std::cout<< "> " <<std::flush;
        std::getline(std::cin,cmdline);

        //分割输入的命令
        if(cmdline.empty()) continue;
        auto args_vec = split_space(cmdline);

        //观测分割情况
        for (size_t i = 0; i < args_vec.size(); ++i) {
            LOG("arg[%zu]=%s", i, args_vec[i].c_str());
        }

        if(args_vec.empty()) continue;
        const std::string& inst = args_vec[0];

        if(inst == "g"){
            resume_process(pid);
        } else if(inst == "p") {
            parse_thread_signal(pid);
        } else if(inst == "stop"){
            suspend_process(pid);
        } else if(inst == "r"){
            if (args_vec.size() == 1) {
                // r - 显示所有寄存器
                print_all_regs(pid);
            } else if (args_vec.size() == 3) {
                // r <reg_name> <value> - 设置寄存器
                try {
                    uint64_t value = std::stoull(args_vec[2], nullptr, 0); // 支持0x前缀
                    if (set_reg(pid, args_vec[1].c_str(), value) == 0) {
                        std::cout << "Set " << args_vec[1] << " = 0x" << std::hex << value << std::dec << "\n";
                    } else {
                        std::cout << "Failed to set register: " << args_vec[1] << "\n";
                    }
                } catch (const std::exception& e) {
                    std::cout << "Invalid value: " << args_vec[2] << "\n";
                }
            }
        } else if(inst == "s") {
            //步入
            step_into(pid);
        } else if(inst == "n") {
            //步过
            step_over(pid);
        } else if(inst == "help" || inst == "h") {
            std::cout << "Available commands:\n";
            std::cout << "  g - Resume/Go process\n";
            std::cout << "  p - Parse thread signal\n";
            std::cout << "  stop - Suspend process\n";
            std::cout << "  r - Register operations\n";
            std::cout << "  s - Step into (single step)\n";
            std::cout << "  n - Step over (next)\n";
        } else {
            std::cout << "Unknown command: " << inst << " (try 'help')\n";
        }

    }
}

std::vector<std::string> split_space(const std::string &s) {
    std::istringstream iss(s);
    std::vector<std::string> tokens;
    std::string t;
    while (iss >> t) tokens.push_back(t);
    return tokens;
}

pid_t get_process_pid(const char *process_name) {
    LOG_ENTER();

    if (process_name == nullptr) exit(1);;

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
    LOG_ENTER();

    long result = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    if (result == -1) {
        LOGE("PTRACE_SINGLESTEP failed: %s", strerror(errno));
    }

    return result;
}

long step_over(pid_t pid) {
    LOG_ENTER();
    
    // 简化实现：暂时对所有指令都使用单步
    // TODO: 后续优化为检测函数调用指令，设置临时断点
    
    uint64_t current_pc;
    if (get_reg(pid, "pc", &current_pc) != 0) {
        LOGE("Failed to get current PC");
        return -1;
    }
    
    LOG("Step over at PC: 0x%lx", current_pc);
    
    // 读取当前指令（4字节，ARM64）
    long instruction = ptrace(PTRACE_PEEKTEXT, pid, current_pc, NULL);
    if (instruction == -1) {
        LOGE("Failed to read instruction at 0x%lx: %s", current_pc, strerror(errno));
        return -1;
    }
    
    uint32_t instr = instruction & 0xFFFFFFFF;
    LOG("Instruction at 0x%lx: 0x%08x", current_pc, instr);
    
    // 简单判断：检查是否是BL/BLR指令（函数调用）
    bool is_call = false;
    
    // BL指令：0x94000000 - 0x97FFFFFF 
    if ((instr & 0xFC000000) == 0x94000000) {
        is_call = true;
        LOG("Detected BL (branch with link) instruction");
    }
    // BLR指令：0xD63F0000 - 0xD63F03FF
    else if ((instr & 0xFFFFFC00) == 0xD63F0000) {
        is_call = true;
        LOG("Detected BLR (branch with link register) instruction");
    }
    
    if (is_call) {
        // 对于函数调用：在下一条指令设置临时断点
        uint64_t next_pc = current_pc + 4;  // ARM64指令长度为4字节
        LOG("Function call detected, setting temporary breakpoint at 0x%lx", next_pc);
        
        // 读取下一条指令的原始字节
        long original_instr = ptrace(PTRACE_PEEKTEXT, pid, next_pc, NULL);
        if (original_instr == -1) {
            LOGE("Failed to read instruction at return address 0x%lx", next_pc);
            return -1;
        }
        
        // 设置断点（替换为 0xD4200000，ARM64的brk #0指令）
        long breakpoint_instr = (original_instr & 0xFFFFFFFF00000000UL) | 0xD4200000;
        if (ptrace(PTRACE_POKETEXT, pid, next_pc, breakpoint_instr) == -1) {
            LOGE("Failed to set temporary breakpoint at 0x%lx", next_pc);
            return -1;
        }
        
        // 继续执行直到命中断点
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
            LOGE("Failed to continue execution");
            return -1;
        }
        
        // 等待进程停止（命中断点）
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            LOGE("waitpid failed: %s", strerror(errno));
            return -1;
        }
        
        // 恢复原始指令
        if (ptrace(PTRACE_POKETEXT, pid, next_pc, original_instr) == -1) {
            LOGE("Failed to restore original instruction at 0x%lx", next_pc);
        }
        
        // 检查是否正确停在断点处
        uint64_t stopped_pc;
        if (get_reg(pid, "pc", &stopped_pc) == 0) {
            if (stopped_pc == next_pc + 4) {
                // PC指向断点后的下一条指令，需要回退
                if (set_reg(pid, "pc", next_pc) != 0) {
                    LOGE("Failed to adjust PC after breakpoint");
                }
            }
        }
        
        LOG("Step over completed, stopped at 0x%lx", next_pc);
        return 0;
        
    } else {
        // 对于非函数调用指令：直接单步执行
        LOG("Non-call instruction, using single step");
        return step_into(pid);
    }
}
