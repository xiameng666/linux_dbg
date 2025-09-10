//
// Created by XiaM on 2025/9/11.
//
#include "dbg_command.h"

// 全局状态：记录上次反汇编的地址，用于连续反汇编
extern uint64_t g_last_disasm_addr;
// 临时禁用的断点地址
extern void* g_temp_disabled_bp;

// 命令映射表
static std::unordered_map<std::string, CommandHandler> command_table = {
        {"g", cmd_continue},
        {"p", cmd_parse},
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
        {"help", cmd_help}
};

// 重构后的主循环 - 完全保留你的原始逻辑
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
        std::string inst = args_vec[0];
        std::transform(inst.begin(), inst.end(), inst.begin(), ::tolower);

        // 查找并执行命令
        auto it = command_table.find(inst);
        if(it != command_table.end()) {
            it->second(pid, args_vec);  // 调用对应的命令处理函数
        } else {
            std::cout << "Unknown command: " << inst << " (try 'help')\n";
        }
    }
}

// 各个命令的实现 - 完全保留你的原始逻辑，只是提取为独立函数

void cmd_continue(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 if(inst == "g") 里面的代码，完全不变
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

void cmd_parse(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if(inst == "p") 里面的代码，完全不变
    //解析信号
    parse_thread_signal(pid);
}

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
}

void cmd_step_into(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if(inst == "s") 里面的代码，完全不变
    //步入
    // 先恢复临时禁用的断点
    bp_restore_temp_disabled(pid);

    step_into(pid);
    parse_thread_signal(pid);
    // 重置反汇编状态到当前PC，并显示当前指令
    disasm_lines(pid, nullptr, 1, false);
}

void cmd_step_over(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if(inst == "n") 里面的代码，完全不变
    //步过
    // 先恢复临时禁用的断点
    bp_restore_temp_disabled(pid);
    step_over(pid);
    parse_thread_signal(pid);
    // 重置反汇编状态到当前PC，并显示当前指令
    disasm_lines(pid, nullptr, 1, false);
}

void cmd_breakpoint(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if (inst == "bp") 里面的代码，完全不变
    uint64_t addr = std::stoull(args[1], nullptr, 16);
    bp_set(pid, (void*)addr);
}

void cmd_bp_list(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if (inst == "bpl") 里面的代码，完全不变
    bp_show();
}

void cmd_bp_clear(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if (inst == "bpc") 里面的代码，完全不变
    size_t index = (size_t)std::stoul(args[1], nullptr, 10);
    bp_clear(pid, index);
}

void cmd_maps(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if(inst == "map") 里面的代码，完全不变
    MapControl mapControl(pid);
    mapControl.print_maps();
}

void cmd_protect(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if(inst == "prot") 里面的代码，完全不变
    MapControl mapControl(pid);
    void *address= (void*)std::stoull(args[1], nullptr,16);
    size_t len = std::stoul(args[2], nullptr,0);
    int prot = std::stoi(args[3], nullptr,0);
    mapControl.change_map_permissions(address,len,prot);
}

void cmd_memory_read(pid_t pid, const std::vector<std::string>& args) {
    // 这是你原来的 else if(inst == "mr") 里面的代码，完全不变
    static uint8_t read_memory_buffer[0x1000];

    //[mr addr len] 读取内存
    void *address= (void*)std::stoull(args[1], nullptr,16);
    size_t len = std::stoul(args[2], nullptr,0);
    read_memory_vm(pid, address, len, read_memory_buffer);
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
}