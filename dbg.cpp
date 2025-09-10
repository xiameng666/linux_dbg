//
// Created by XiaM on 2025/9/9.
//
#include "dbg.h"
#include "disasm.h"

// 全局状态：记录上次反汇编的地址，用于连续反汇编
static uint64_t g_last_disasm_addr = 0;
// 临时禁用的断点地址
static void* g_temp_disabled_bp = nullptr;

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
    LOG_ENTER("(pid=%d)", pid);

    int status = 0;
    pid_t r = waitpid(pid, &status, 0);  // 阻塞等待该线程的状态变化
    if (r == -1) {
        LOGE("waitpid failed: %s", strerror(errno));
        return;
    }

    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        siginfo_t info{};
        ptrace(PTRACE_GETSIGINFO, pid, 0, &info);
        LOG("stopped:si_signo=%d si_code=%d si_pid=%d", info.si_signo, info.si_code, info.si_pid);
        
        // 检测断点命中
        if (sig == SIGTRAP && info.si_code == TRAP_BRKPT) {
            uint64_t pc = 0;
            if (get_reg(pid, "pc", &pc) == 0) {
                LOG("命中断点 PC=0x%lx", pc);
                g_last_disasm_addr = 0; // 重置为0，下次u命令会从当前PC开始
                
                // 临时禁用当前断点，避免 g 命令时再次触发
                bp_temp_disable(pid, (void*)pc);
                print_all_regs(pid);
                //handle_breakpoint_hit(pid, (void*)pc);
            }
        }
        //检测单步
        else if (sig == SIGTRAP && info.si_code == TRAP_HWBKPT) {
            uint64_t pc = 0;
            if (get_reg(pid, "pc", &pc) == 0) {
                LOG("单步完成 PC=0x%lx", pc);
            }
        }
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
    }

    return result;
}

long get_reg(pid_t pid, const char* reg_name, uint64_t* value) {
    LOG_ENTER("(pid=%d, reg_name=%s, value=%p)", pid, reg_name, value);

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

    std::cout << std::dec;
    return true;
}

void print_single_reg(const std::string& reg_name, uint64_t value) {
    std::cout << reg_name << " = 0x" << std::hex << std::setfill('0') << std::setw(16) << value;
    std::cout << " (" << std::dec << value << ")" << std::endl;
}

void command_loop(pid_t pid) {
    MapControl mapControl(pid);
    uint8_t read_memory_buffer[0x1000];
    std::string cmdline;

    while(true){
        std::cout<< "> " <<std::flush;
        std::getline(std::cin,cmdline);

        //分割输入的命令
        if(cmdline.empty()) continue;
        auto args_vec = split_space(cmdline);

//        //观测分割情况
//        for (size_t i = 0; i < args_vec.size(); ++i) {
//            LOG("arg[%zu]=%s", i, args_vec[i].c_str());
//        }

        if(args_vec.empty()) continue;
        std::string& inst = args_vec[0];
        std::transform(inst.begin(), inst.end(), inst.begin(), ::tolower);

        if(inst == "g"){
            // 如果有临时禁用的断点
            if (g_temp_disabled_bp != nullptr) {
                // 单步执行跳过当前断点指令
                step_into(pid);
                parse_thread_signal(pid);
                // 然后恢复断点
                bp_restore_temp_disabled(pid);
            }
            // 恢复执行
            resume_process(pid);
            parse_thread_signal(pid);

        }
        else if(inst == "p") {
            //解析信号
            parse_thread_signal(pid);

        }
        else if(inst == "stop"){
            //挂起
            suspend_process(pid);

        }
        else if(inst == "r"){
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

        }
        else if(inst == "u") {
            if(args_vec.size() == 2){
               void*  pc_value = (void*)std::stoull(args_vec[1], nullptr,16);
                disasm_lines(pid, pc_value,5,true);
            }else{
                // u - 连续反汇编
                disasm_lines(pid, nullptr, 5, true);
            }

        }
        else if(inst == "s") {
            //步入
            // 先恢复临时禁用的断点
            bp_restore_temp_disabled(pid);

            step_into(pid);
            parse_thread_signal(pid);
            // 重置反汇编状态到当前PC，并显示当前指令
            disasm_lines(pid, nullptr, 1, false);

        }
        else if(inst == "n") {
            //步过
            // 先恢复临时禁用的断点
            bp_restore_temp_disabled(pid);
            step_over(pid);
            parse_thread_signal(pid);
            // 重置反汇编状态到当前PC，并显示当前指令
            disasm_lines(pid, nullptr, 1, false);

        }
        else if (inst == "bp") {
            uint64_t addr = std::stoull(args_vec[1], nullptr, 16);
            bp_set(pid, (void*)addr);

        }
        else if (inst == "bpl") {
            bp_show();

        }
        else if (inst == "bpc") {
            size_t index = (size_t)std::stoul(args_vec[1], nullptr, 10);
            bp_clear(pid, index);

        }
        else if(inst == "map") {
            mapControl.print_maps();

        }

        else if(inst == "prot") {
            void *address= (void*)std::stoull(args_vec[1], nullptr,16);
            size_t len = std::stoul(args_vec[2], nullptr,0);
            int prot = std::stoi(args_vec[3], nullptr,0);
            mapControl.change_map_permissions(address,len,prot);

        }

        else if(inst == "mr"){

            //[mr addr len] 读取内存
            void *address= (void*)std::stoull(args_vec[1], nullptr,16);
            size_t len = std::stoul(args_vec[2], nullptr,0);
            read_memory_vm(pid, address, len, read_memory_buffer);

        }
        else if(inst == "mw"){
            //[mw addr xx xx ...] 写入内存
            void *address= (void*)std::stoull(args_vec[1], nullptr,16);
            std::vector<uint8_t> bytes(args_vec.size()-2);
            std::transform(args_vec.begin() + 2, args_vec.end(), bytes.begin(),
                           [](const std::string& s) {
                               return (uint8_t)std::stoull(s, nullptr, 16);  // 强制16进制
                           });

            ssize_t written = write_memory_ptrace(pid, (void *) address, bytes.data(), bytes.size());
            std::cout << "write " << written << " bytes\n";

        }
        else {
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
    }

    return result;
}

long step_over(pid_t pid){
    LOG_ENTER("(pid=%d)", pid);

    //非调用指令：直接单步 PTRACE_SINGLESTEP
    //如果是BL BLR ，在PC+4 设置一个临时断点，然后 go

    return 0;
}


ssize_t read_memory_vm(pid_t pid, void *target_address, size_t len, void *save_buffer) {
    LOG_ENTER("(pid=%d, target_address=%p, len=%zu, save_buffer=%p)", pid, target_address, len, save_buffer);


    iovec local{save_buffer,len};
    iovec remote{target_address,len};
    ssize_t result = process_vm_readv(pid,&local,1,&remote,1,0);
    if (result == -1) {
        LOGE("process_vm_readv failed: %s", strerror(errno));
    }
    return result;
}

ssize_t write_memory_vm(pid_t pid, void *target_address, void *write_data, size_t len) {
    LOG_ENTER("(pid=%d, target_address=%p, write_data=%p, len=%zu)", pid, target_address, write_data, len);

    // 先尝试直接写入
    iovec local{write_data, len};
    iovec remote{target_address, len};
    ssize_t result = process_vm_writev(pid, &local, 1, &remote, 1, 0);

    if (result != -1) {
        LOG("直接写入成功: %zd bytes", result);
    }else{
        LOGE("process_vm_writev failed: %s", strerror(errno));
    }

    /*
    LOG("Direct write failed, trying with permission change...");

    MapControl mapControl(pid);

    // 修改权限
    bool perm_changed = mapControl.change_map_permissions(target_address, len, PROT_READ | PROT_WRITE);
    if (!perm_changed) {
        LOG("Permission change failed, but continuing...");
    }

    // 再次写入
    result = process_vm_writev(pid, &local, 1, &remote, 1, 0);

    //恢复修改的权限
    mapControl.resume_map_permissions();

    if (result == -1) {
        LOGE("process_vm_writev failed: %s", strerror(errno));
    }
*/
    return result;
}

ssize_t write_memory_ptrace(pid_t pid, void *target_address, void *write_data, size_t len) {
    LOG_ENTER("(pid=%d, target_address=%p, write_data=%p, len=%zu)", pid, target_address, write_data, len);

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

    LOG("ptrace write success: %zu bytes", bytes_written);
    return (ssize_t)bytes_written;
}

void disasm_lines(pid_t pid, void* target_addr, size_t line, bool is_continue) {
    LOG_ENTER("(pid=%d, target_addr=%p, line=%zu, is_continue=%d)", pid, target_addr, line, is_continue);

    uint64_t pc_value = 0;

    if (target_addr != nullptr) {
        // 指定了具体地址，重置全局状态
        pc_value = (uint64_t)target_addr;
        g_last_disasm_addr = pc_value;
    } else if (is_continue && g_last_disasm_addr != 0) {
        // 连续反汇编，从上次位置继续
        pc_value = g_last_disasm_addr;
    } else {
        // 重置到当前PC
        get_reg(pid, "pc", &pc_value);
        g_last_disasm_addr = pc_value;
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
            
            if(is_breakpoint) {
                // 使用原始指令进行反汇编
                disasm((uint8_t*)&original_inst, 4, current_addr,is_breakpoint);
            } else {
                disasm(code, sizeof(code), current_addr);
            }
        } 
    }
    
    // 更新下次反汇编的起始地址
    if (is_continue || target_addr != nullptr) {
        g_last_disasm_addr = pc_value + (line * 4);
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

bool bp_clear(pid_t pid, size_t index) {
    LOG_ENTER("(pid=%d, index=%zu)", pid, index);

    breakpoint& bp = g_bp_vec[index];

    /*如果在程序遇到断点trap的时候先禁用了断点 此时删除断点 当再go的时候 断点又被写回了
    *检查要删除的断点是否是当前临时禁用的断点*/
    if (bp.address == g_temp_disabled_bp) {
        LOG("清除临时禁用状态: 0x%lx", (unsigned long)bp.address);
        g_temp_disabled_bp = nullptr;  // 清除临时禁用状态
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
        print_singel_bp(i);
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
                g_temp_disabled_bp = address;
                LOG("临时禁用断点: 0x%lx", (unsigned long)address);
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
    
    if (g_temp_disabled_bp != nullptr) {
        uint32_t BRK = 0xD4200000;
        if (write_memory_ptrace(pid, g_temp_disabled_bp, (void*)&BRK, 4) == 4) {
            LOG("恢复临时禁用的断点: 0x%lx", (unsigned long)g_temp_disabled_bp);
            g_temp_disabled_bp = nullptr;
        } else {
            LOGE("恢复断点失败: 0x%lx", (unsigned long)g_temp_disabled_bp);
        }
    }
}


