//
// Created by XiaM on 2025/9/11.
//
#include "dbg_command.h"

// 命令映射表
static std::unordered_map<std::string, CommandHandler> command_table = {
        {"g", cmd_continue},
        {"p", cmd_print_pcb},
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

void command_loop(pid_t pid) {
    MapControl mapControl(pid);
    uint8_t read_memory_buffer[0x1000];
    std::string cmdline;

    while(true){
        while (g_pcb.need_wait_signal) {
            parse_signal(pid);
        }

        // 不需要等待信号时才进入命令输入
        while(true) {
            std::cout<< "> " <<std::flush;
            std::getline(std::cin,cmdline);
            
            if(!cmdline.empty()) break; 
        }
        auto args_vec = split_space(cmdline);

//        //观测分割情况
//        for (size_t i = 0; i < args_vec.size(); ++i) {
//            LOG("arg[%zu]=%s", i, args_vec[i].c_str());
//        }

        if(args_vec.empty()) continue;
        std::string inst = args_vec[0];
        std::transform(inst.begin(), inst.end(), inst.begin(), ::tolower);

        //默认需要等待信号
        g_pcb.need_wait_signal = true;

        // 查找并执行命令
        auto it = command_table.find(inst);
        if(it != command_table.end()) {
            it->second(pid, args_vec);
        } else {
            std::cout << "Unknown command: " << inst << " (try 'help')\n";
            g_pcb.need_wait_signal = false;
        }
    }
}

void cmd_continue(pid_t pid, const std::vector<std::string>& args) {
    // 设置调试器状态
    g_pcb.debugger_state = DebuggerState::CONTINUE;
    g_pcb.current_command = CommandType::CONTINUE;
    
    // 检查是否需要跨越断点
    if (g_pcb.temp_disabled_bp != nullptr) {
        // 当前在一个临时禁用的断点上，需要先单步跨越
        step_into(pid);
    } else {
        // 正常继续执行
        resume_process(pid);
    }
}

// ✅ cmd_parse已移除，parse_thread_signal现在在command_loop中统一调用

void cmd_stop(pid_t pid, const std::vector<std::string>& args) {
    //挂起
    suspend_process(pid);
}

void cmd_registers(pid_t pid, const std::vector<std::string>& args) {
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
    // 不需要等待信号：寄存器读取/设置操作
    g_pcb.need_wait_signal = false;
}

void cmd_disasm(pid_t pid, const std::vector<std::string>& args) {
    if(args.size() == 2){
        void*  pc_value = (void*)std::stoull(args[1], nullptr,16);
        disasm_lines(pid, pc_value,5,true);
    }else{
        // u - 连续反汇编
        disasm_lines(pid, nullptr, 5, true);
    }
    // 不需要等待信号：纯内存读取操作
    g_pcb.need_wait_signal = false;
}

void cmd_step_into(pid_t pid, const std::vector<std::string>& args) {
    // 设置新的调试器状态
    g_pcb.debugger_state = DebuggerState::STEP;
    g_pcb.current_command = CommandType::STEP_INTO;
    step_into(pid);
}

void cmd_step_over(pid_t pid, const std::vector<std::string>& args) {
    // 设置新的调试器状态
    g_pcb.debugger_state = DebuggerState::STEP;
    g_pcb.current_command = CommandType::STEP_OVER;
    step_over(pid);
    
}

void cmd_breakpoint(pid_t pid, const std::vector<std::string>& args) {
    uint64_t addr = std::stoull(args[1], nullptr, 16);
    bp_set(pid, (void*)addr);
    // 不需要等待信号：断点设置操作
    g_pcb.need_wait_signal = false;
}

void cmd_bp_list(pid_t pid, const std::vector<std::string>& args) {
    bp_show();

    // 不需要等待信号：断点列表显示操作
    g_pcb.need_wait_signal = false;
}

void cmd_bp_clear(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if (inst == "bpc") 里面的代码，完全不变
    size_t index = (size_t)std::stoul(args[1], nullptr, 10);
    bp_clear(pid, index);

    // 不需要等待信号：断点清除操作
    g_pcb.need_wait_signal = false;
}

void cmd_maps(pid_t pid, const std::vector<std::string>& args) {
    MapControl mapControl(pid);
    
    // grep xxx
    if (args.size() >= 2) {
        // 使用第二个参数作为过滤条件
        mapControl.print_maps(args[1]);
    } else {
        // 没有参数，显示所有映射
        mapControl.print_maps();
    }

    // 不需要等待信号：读取/proc/pid/maps文件
    g_pcb.need_wait_signal = false;
}

void cmd_protect(pid_t pid, const std::vector<std::string>& args) {
    MapControl mapControl(pid);
    void *address= (void*)std::stoull(args[1], nullptr,16);
    size_t len = std::stoul(args[2], nullptr,0);
    int prot = std::stoi(args[3], nullptr,0);
    mapControl.change_map_permissions(address,len,prot);
    // 🚫 不需要等待信号：内存保护属性修改
    g_pcb.need_wait_signal = false;
}

void cmd_memory_read(pid_t pid, const std::vector<std::string>& args) {
    static uint8_t read_memory_buffer[0x1000];

    //[mr addr len] 读取内存
    void *address= (void*)std::stoull(args[1], nullptr,16);
    size_t len = std::stoul(args[2], nullptr,0);
    ssize_t bytes_read = read_memory_vm(pid, address, len, read_memory_buffer);
    if (bytes_read > 0) {
        hexdump(read_memory_buffer, bytes_read, (uintptr_t)address);
    }
    // 🚫 不需要等待信号：内存读取操作
    g_pcb.need_wait_signal = false;
}

void cmd_memory_write(pid_t pid, const std::vector<std::string>& args) {
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
    std::cout << "  p          - Print PCB (Process Control Block) status\n";
    std::cout << "  stop       - Suspend process\n";
    std::cout << "  r [reg] [val] - Show/set registers\n";
    std::cout << "  u [addr]   - Disassemble\n";
    std::cout << "  s          - Step into\n";
    std::cout << "  n          - Step over\n";
    std::cout << "  bp <addr>  - Set breakpoint\n";
    std::cout << "  bpl        - List breakpoints\n";
    std::cout << "  bpc <idx>  - Clear breakpoint\n";
    std::cout << "  map [filter] - Show memory maps (optional filter string)\n";
    std::cout << "  prot <addr> <len> <prot> - Change protection\n";
    std::cout << "  mr <addr> <len> - Read memory\n";
    std::cout << "  mw <addr> <bytes...> - Write memory\n";
    std::cout << "  trace <start> <end> - Start trace from start to end address\n";
    std::cout << "  help       - Show this help\n";

    g_pcb.need_wait_signal = false;
}

void cmd_trace(pid_t pid, const std::vector<std::string> &args) {
    auto start= (uintptr_t)std::stoull(args[1], nullptr,16);
    auto end= (uintptr_t)std::stoull(args[2], nullptr,16);

    trace_start(start,end);
    
    // 获取当前PC
    uint64_t current_pc = 0;
    get_reg(pid, "pc", &current_pc);
    
    LOG("在trace起始地址 0x%lx 设置断点", start);
    if (bp_set(pid, (void*)start)) {
        LOG("断点设置成功，继续执行直到到达trace起始地址");
        // 设置状态为CONTINUE，等待起始断点
        g_pcb.debugger_state = DebuggerState::CONTINUE;
        g_pcb.current_command = CommandType::CONTINUE; // 保留兼容
        resume_process(pid);
    } else {
        LOG("断点设置失败，trace启动失败");
        trace_reset();
        g_pcb.need_wait_signal = false;
    }
}

void cmd_print_pcb(pid_t pid, const std::vector<std::string>& args) {
    printf("=== PCB状态 ===\n");

    // 基本进程信息
    printf("进程信息:\n");
    printf("  PID: %d\n", g_pcb.pid);
    printf("  需要等待信号: %s\n", g_pcb.need_wait_signal ? "是" : "否");

    // 调试器状态信息
    printf("\n调试器状态:\n");
    printf("  当前状态: ");
    switch (g_pcb.debugger_state) {
        case DebuggerState::IDLE:        printf("IDLE (空闲)\n"); break;
        case DebuggerState::CONTINUE:    printf("CONTINUE (运行)\n"); break;
        case DebuggerState::STEP:        printf("STEP (单步)\n"); break;
        case DebuggerState::TRACE_ACTIVE: printf("TRACE_ACTIVE (trace中)\n"); break;
        default: printf("未知(%d)\n", (int)g_pcb.debugger_state); break;
    }

    printf("  命令类型(兼容): ");
    switch (g_pcb.current_command) {
        case CommandType::NONE:      printf("NONE\n"); break;
        case CommandType::STEP_INTO: printf("STEP_INTO\n"); break;
        case CommandType::STEP_OVER: printf("STEP_OVER\n"); break;
        case CommandType::CONTINUE:  printf("CONTINUE\n"); break;
        case CommandType::TRACE:     printf("TRACE\n"); break;
        default: printf("未知(%d)\n", (int)g_pcb.current_command); break;
    }

    // 反汇编状态
    printf("\n反汇编状态:\n");
    printf("  上次反汇编地址: 0x%lx\n", g_pcb.last_disasm_addr);

    // 断点状态
    printf("\n断点状态:\n");
    printf("  临时禁用断点: %s", g_pcb.temp_disabled_bp ? "有" : "无");
    if (g_pcb.temp_disabled_bp) {
        printf(" (地址: 0x%lx)", (uintptr_t)g_pcb.temp_disabled_bp);
    }
    printf("\n");

    // Trace状态
    printf("\nTrace状态:\n");
    printf("  起始地址: 0x%lx\n", g_pcb.trace_begin);
    printf("  结束地址: 0x%lx\n", g_pcb.trace_end);
    printf("  已进入过trace: %s\n", g_pcb.trace_ever_into ? "是" : "否");
    printf("  trace文件: %s\n", g_pcb.trace_fp ? "已打开" : "未打开");

    // 当前PC值
    uint64_t current_pc = 0;
    if (get_reg(pid, "pc", &current_pc) == 0) {
        printf("\n当前执行状态:\n");
        printf("  PC: 0x%lx\n", current_pc);
    }

    printf("=====================================\n");
    
    // 不需要等待信号
    g_pcb.need_wait_signal = false;
}
