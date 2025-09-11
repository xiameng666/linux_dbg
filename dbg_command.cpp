//
// Created by XiaM on 2025/9/11.
//
#include "dbg_command.h"

// 命令映射表
static std::unordered_map<std::string, CommandHandler> command_table = {
        {"g", cmd_continue},
        // ✅ 移除"p"命令，parse_thread_signal现在在command_loop中自动调用
        {"stop", cmd_stop},
        {"r", cmd_registers},
        {"u", cmd_disasm},
        {"s", cmd_step_into},
        {"n", cmd_step_over},
        {"bp", cmd_breakpoint},
        {"bpl", cmd_bp_list},
        {"bpc", cmd_bp_clear},
        {"map", cmd_maps},
        {"prot", cmd_protect},
        {"mr", cmd_memory_read},
        {"mw", cmd_memory_write},
        {"help", cmd_help},
        {"trace", cmd_trace}
};

// ✅ 重构后的主循环 - 智能信号等待架构
void command_loop(pid_t pid) {
    MapControl mapControl(pid);
    uint8_t read_memory_buffer[0x1000];
    std::string cmdline;

    while(true){
        // 🔧 反向逻辑：默认等待信号（只有特定命令会禁用）
        if (g_pcb.need_wait_signal) {
            parse_thread_signal(pid);
            
            // 检查trace是否需要继续（trace模式下的自动单步）
            if (g_pcb.trace_enabled && g_pcb.trace_need_continue) {
                g_pcb.trace_need_continue = false;
                step_into(pid);
                continue;  // 继续下一轮循环，等待信号
            }
            
            // 如果有临时禁用的断点，在信号处理后恢复
            if (g_pcb.temp_disabled_bp != nullptr) {
                bp_restore_temp_disabled(pid);
            }
        }

        // 🎯 用户命令输入和处理
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
        std::string inst = args_vec[0];
        std::transform(inst.begin(), inst.end(), inst.begin(), ::tolower);

        // 💡 反向逻辑：默认需要等待信号
        g_pcb.need_wait_signal = true;

        // 查找并执行命令
        auto it = command_table.find(inst);
        if(it != command_table.end()) {
            it->second(pid, args_vec);  // 调用对应的命令处理函数
        } else {
            std::cout << "Unknown command: " << inst << " (try 'help')\n";
            g_pcb.need_wait_signal = false;  // 未知命令不需要等待信号
        }
    }
}

void cmd_continue(pid_t pid, const std::vector<std::string>& args) {
    //parse_sign中收到TRAP_BRKPT->临时禁用断点
    //cmd_continue中先单步一次执行原始指令 → 收到单步 SIGTRAP → 再把断点恢复 → go。

    if (g_pcb.temp_disabled_bp != nullptr) {
        // 单步执行跳过当前断点指令
        step_into(pid);
    } else {
        // 直接继续执行
        resume_process(pid);
    }

    // ✅ 默认需要等待信号，无需额外设置
}

// ✅ cmd_parse已移除，parse_thread_signal现在在command_loop中统一调用

void cmd_stop(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if(inst == "stop") 里面的代码，完全不变
    //挂起
    suspend_process(pid);
}

void cmd_registers(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if(inst == "r") 里面的代码，完全不变
    if (args.size() == 1) {
        // r - 显示所有寄存器
        print_all_regs(pid);
    } else if (args.size() == 3) {
        // r <reg_name> <value> - 设置寄存器
        try {
            uint64_t value = std::stoull(args[2], nullptr, 0); // 支持0x前缀
            if (set_reg(pid, args[1].c_str(), value) == 0) {
                std::cout << "Set " << args[1] << " = 0x" << std::hex << value << std::dec << "\n";
            } else {
                std::cout << "Failed to set register: " << args[1] << "\n";
            }
        } catch (const std::exception& e) {
            std::cout << "Invalid value: " << args[2] << "\n";
        }
    }
    // 🚫 不需要等待信号：寄存器读取/设置操作
    g_pcb.need_wait_signal = false;
}

void cmd_disasm(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if(inst == "u") 里面的代码，完全不变
    if(args.size() == 2){
        void*  pc_value = (void*)std::stoull(args[1], nullptr,16);
        disasm_lines(pid, pc_value,5,true);
    }else{
        // u - 连续反汇编
        disasm_lines(pid, nullptr, 5, true);
    }
    // 🚫 不需要等待信号：纯内存读取操作
    g_pcb.need_wait_signal = false;
}

void cmd_step_into(pid_t pid, const std::vector<std::string>& args) {
    // 如果有临时禁用的断点，先单步执行原始指令，再恢复断点
    if (g_pcb.temp_disabled_bp != nullptr) {
        step_into(pid);
        // ✅ 移除阻塞等待，让command_loop统一处理
        // parse_thread_signal(pid);      
        // bp_restore_temp_disabled(pid); // 恢复断点逻辑移到信号处理中
    } else {
        step_into(pid);
        // ✅ 移除阻塞等待
        // parse_thread_signal(pid);
    }

    // ✅ 默认需要等待信号，无需额外设置
}

void cmd_step_over(pid_t pid, const std::vector<std::string>& args) {
    if (g_pcb.temp_disabled_bp != nullptr) {
        step_into(pid);
        // ✅ 移除阻塞等待
        // parse_thread_signal(pid);
        // bp_restore_temp_disabled(pid);
    } else {
        step_over(pid);
        // ✅ 移除阻塞等待
        // parse_thread_signal(pid);
    }

    // ✅ 默认需要等待信号，无需额外设置
}

void cmd_breakpoint(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if (inst == "bp") 里面的代码，完全不变
    uint64_t addr = std::stoull(args[1], nullptr, 16);
    bp_set(pid, (void*)addr);
    // 🚫 不需要等待信号：断点设置操作
    g_pcb.need_wait_signal = false;
}

void cmd_bp_list(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if (inst == "bpl") 里面的代码，完全不变
    bp_show();
    // 🚫 不需要等待信号：断点列表显示操作
    g_pcb.need_wait_signal = false;
}

void cmd_bp_clear(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if (inst == "bpc") 里面的代码，完全不变
    size_t index = (size_t)std::stoul(args[1], nullptr, 10);
    bp_clear(pid, index);
    // 🚫 不需要等待信号：断点清除操作
    g_pcb.need_wait_signal = false;
}

void cmd_maps(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if(inst == "map") 里面的代码，完全不变
    MapControl mapControl(pid);
    mapControl.print_maps();
    // 🚫 不需要等待信号：读取/proc/pid/maps文件
    g_pcb.need_wait_signal = false;
}

void cmd_protect(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if(inst == "prot") 里面的代码，完全不变
    MapControl mapControl(pid);
    void *address= (void*)std::stoull(args[1], nullptr,16);
    size_t len = std::stoul(args[2], nullptr,0);
    int prot = std::stoi(args[3], nullptr,0);
    mapControl.change_map_permissions(address,len,prot);
    // 🚫 不需要等待信号：内存保护属性修改
    g_pcb.need_wait_signal = false;
}

void cmd_memory_read(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if(inst == "mr") 里面的代码，完全不变
    static uint8_t read_memory_buffer[0x1000];

    //[mr addr len] 读取内存
    void *address= (void*)std::stoull(args[1], nullptr,16);
    size_t len = std::stoul(args[2], nullptr,0);
    read_memory_vm(pid, address, len, read_memory_buffer);

    ssize_t bytes_read = read_memory_vm(pid, address, len, read_memory_buffer);
    if (bytes_read > 0) {
        hexdump(read_memory_buffer, bytes_read, (uintptr_t)address);
    }
    // 🚫 不需要等待信号：内存读取操作
    g_pcb.need_wait_signal = false;
}

void cmd_memory_write(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if(inst == "mw") 里面的代码，完全不变
    //[mw addr xx xx ...] 写入内存
    void *address= (void*)std::stoull(args[1], nullptr,16);
    std::vector<uint8_t> bytes(args.size()-2);
    std::transform(args.begin() + 2, args.end(), bytes.begin(),
                   [](const std::string& s) {
                       return (uint8_t)std::stoull(s, nullptr, 16);  // 强制16进制
                   });

    ssize_t written = write_memory_ptrace(pid, (void *) address, bytes.data(), bytes.size());
    std::cout << "write " << written << " bytes\n";
    // 🚫 不需要等待信号：内存写入操作
    g_pcb.need_wait_signal = false;
}

void cmd_help(pid_t pid, const std::vector<std::string>& args) {
    std::cout << "Available commands:\n";
    std::cout << "  g          - Continue execution\n";
    std::cout << "  p          - Parse thread signal\n";
    std::cout << "  stop       - Suspend process\n";
    std::cout << "  r [reg] [val] - Show/set registers\n";
    std::cout << "  u [addr]   - Disassemble\n";
    std::cout << "  s          - Step into\n";
    std::cout << "  n          - Step over\n";
    std::cout << "  bp <addr>  - Set breakpoint\n";
    std::cout << "  bpl        - List breakpoints\n";
    std::cout << "  bpc <idx>  - Clear breakpoint\n";
    std::cout << "  map        - Show memory maps\n";
    std::cout << "  prot <addr> <len> <prot> - Change protection\n";
    std::cout << "  mr <addr> <len> - Read memory\n";
    std::cout << "  mw <addr> <bytes...> - Write memory\n";
    std::cout << "  help       - Show this help\n";
    // 🚫 不需要等待信号：纯文本输出
    g_pcb.need_wait_signal = false;
}

void cmd_trace(pid_t pid, const std::vector<std::string> &args) {
    auto start= (uintptr_t)std::stoull(args[1], nullptr,16);
    auto end= (uintptr_t)std::stoull(args[2], nullptr,16);

    trace_start(start,end);
    step_into(pid);
    
    // ✅ 默认需要等待信号，无需额外设置
}
