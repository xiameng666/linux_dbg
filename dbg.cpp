//
// Created by XiaM on 2025/9/9.
//
#include "dbg.h"


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

        //观测分割情况
        for (size_t i = 0; i < args_vec.size(); ++i) {
            LOG("arg[%zu]=%s", i, args_vec[i].c_str());
        }

        if(args_vec.empty()) continue;
        std::string& inst = args_vec[0];
        std::transform(inst.begin(), inst.end(), inst.begin(), ::tolower);

        if(inst == "g"){
            //恢复
            resume_process(pid);

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
        else if(inst == "s") {
            //步入
            step_into(pid);

        }
        else if(inst == "n") {
            //步过
            step_over(pid);

        }
        else if(inst == "map") {
            mapControl.print_maps();
        }
        else if(inst == "mr"){

            //[mr addr len] 读取内存
            void *address= (void*)std::stoull(args_vec[1], nullptr,16);
            size_t len = std::stoul(args_vec[2], nullptr,0);
            mapControl.read_memory(pid, address, len, read_memory_buffer);

        }
        else if(inst == "mw"){
            //[mw addr xx xx ...] 写入内存
            void *address= (void*)std::stoull(args_vec[1], nullptr,16);
            std::vector<uint8_t> bytes(args_vec.size()-2);
            std::transform(args_vec.begin() + 2, args_vec.end(), bytes.begin(),
                           [](const std::string& s) {
                               return (uint8_t)std::stoull(s, nullptr, 16);  // 强制16进制
                           });

            ssize_t written = mapControl.write_memory(pid, (void*)address, bytes.data(), bytes.size());
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
    LOG_ENTER();

    long result = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    if (result == -1) {
        LOGE("PTRACE_SINGLESTEP failed: %s", strerror(errno));
    }

    return result;
}

long step_over(pid_t pid){
    //TODO

    return 0;
}


