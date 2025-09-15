//
// Created by XiaM on 2025/9/11.
//
#include "dbg_command.h"
#include <iostream>
#include <sstream>
#include <algorithm>

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
        {"trace", cmd_trace},
        {"help", cmd_help},
        {"q", cmd_quit},
        {"quit", cmd_quit}
};

// 获取用户输入
std::string get_user_command() {
    std::cout << ">> ";
    std::string cmd;
    std::getline(std::cin, cmd);
    return cmd;
}

// 执行命令
void execute_command(pid_t pid, const std::string& cmd) {
    if (cmd.empty()) {
        return;
    }

    std::vector<std::string> args = split_space(cmd);
    if (args.empty()) {
        return;
    }

    auto it = command_table.find(args[0]);
    if (it != command_table.end()) {
        it->second(pid, args);
    } else {
        std::cout << "未知命令: " << args[0] << "\n";
        std::cout << "try 'help'\n";
    }
}

void command_loop(pid_t pid) {
    LOG_ENTER("(pid=%d)", pid);

    while (true) {
        // 处理上一次指令导致的信号
        if (g_pcb.need_wait_signal) {
            parse_signal(pid);
            continue;  // 处理完 重新检查状态
        }

        // 只有在IDLE状态才接受命令
        if (g_pcb.state == DebuggerState::IDLE) {
            std::string cmd = get_user_command();
            execute_command(pid, cmd);
        }
    }
}

// ==================== 命令处理函数 ====================

void cmd_continue(pid_t pid, const std::vector<std::string>& args) {
    LOG_ENTER("(pid=%d)", pid);

    // 处理当前位置有断点的情况（穿越断点）
    uint64_t pc = 0;
    get_reg(pid, "pc", &pc);

    if (has_breakpoint_at((void*)pc)) {
        // 临时禁用断点
        bp_temp_disable(pid, (void*)pc);

        // 单步越过断点
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        int status;
        waitpid(pid, &status, 0);

        // 恢复断点
        bp_restore_temp_disabled(pid);
    }

    // 清理所有临时断点
    clear_all_temp_breakpoints(pid);

    // 继续执行
    if (resume_process(pid) == 0) {
        LOGI("cmd_continue...");
    }
}

void cmd_stop(pid_t pid, const std::vector<std::string>& args) {
    LOG_ENTER("(pid=%d)", pid);

    if (suspend_process(pid) == 0) {
        LOGI("cmd_stop");
        g_pcb.need_wait_signal = true;
    }
}

void cmd_registers(pid_t pid, const std::vector<std::string>& args) {
    if (args.size() == 1) {
        // r - 显示所有寄存器
        print_all_regs(pid);
    } else if (args.size() == 3) {
        // r <reg_name> <value> - 设置寄存器
        try {
            uint64_t value = std::stoull(args[2], nullptr, 0);
            if (set_reg(pid, args[1].c_str(), value) == 0) {
                std::cout << "Set " << args[1] << " = 0x"
                          << std::hex << value << std::dec << "\n";
            } else {
                std::cout << "set_reg 失败: " << args[1] << "\n";
            }
        } catch (const std::exception& e) {
            std::cout << "invalid value: " << args[2] << "\n";
        }
    } else if (args.size() == 2) {
        // r <reg_name> - 显示单个寄存器
        uint64_t value;
        if (get_reg(pid, args[1].c_str(), &value) == 0) {
            print_single_reg(args[1], value);
        } else {
            std::cout << "get_reg 失败: " << args[1] << "\n";
        }
    }
}

void cmd_disasm(pid_t pid, const std::vector<std::string>& args) {
    if (args.size() == 2) {
        // u <addr> - 从指定地址反汇编
        try {
            void* pc_value = (void*)std::stoull(args[1], nullptr, 16);
            disasm_lines(pid, pc_value, 5, false);
        } catch (const std::exception& e) {
            std::cout << "Invalid address: " << args[1] << "\n";
        }
    } else {
        // u - 连续反汇编
        disasm_lines(pid, nullptr, 5, true);
    }
}

void cmd_step_into(pid_t pid, const std::vector<std::string>& args) {
    LOG_ENTER("(pid=%d)", pid);

    // 如果当前位置有断点，需要临时禁用
    uint64_t pc = 0;
    get_reg(pid, "pc", &pc);

    if (has_breakpoint_at((void*)pc)) {
        bp_temp_disable(pid, (void*)pc);
    }

    // 执行单步
    if (step_into(pid) == 0) {
        LOGI("Single stepping...");
    }
}

void cmd_step_over(pid_t pid, const std::vector<std::string>& args) {
    LOG_ENTER("(pid=%d)", pid);

    uint64_t pc = 0;
    get_reg(pid, "pc", &pc);

    // 如果当前位置有断点，需要处理
    if (has_breakpoint_at((void*)pc)) {
        bp_temp_disable(pid, (void*)pc);
    }

    // 执行步过
    if (step_over(pid) == 0) {
        LOGI("Stepping over...");
    }
}

void cmd_breakpoint(pid_t pid, const std::vector<std::string>& args) {
    if (args.size() != 2) {
        std::cout << "Usage: bp <address>\n";
        return;
    }

    try {
        uint64_t addr = std::stoull(args[1], nullptr, 16);
        if (bp_set(pid, (void*)addr)) {
            std::cout << "Breakpoint set at 0x" << std::hex << addr << std::dec << "\n";
        } else {
            std::cout << "Failed to set breakpoint\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Invalid address: " << args[1] << "\n";
    }
}

void cmd_bp_list(pid_t pid, const std::vector<std::string>& args) {
    bp_show();
}

void cmd_bp_clear(pid_t pid, const std::vector<std::string>& args) {
    if (args.size() != 2) {
        std::cout << "Usage: bpc <index>\n";
        return;
    }

    try {
        size_t index = std::stoul(args[1], nullptr, 10);
        if (bp_clear(pid, index)) {
            std::cout << "Breakpoint " << index << " cleared\n";
        } else {
            std::cout << "Failed to clear breakpoint\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Invalid index: " << args[1] << "\n";
    }
}

void cmd_maps(pid_t pid, const std::vector<std::string>& args) {
    MapControl mapControl(pid);

    if (args.size() >= 2) {
        // map <filter> - 过滤显示
        mapControl.print_maps(args[1]);
    } else {
        // map - 显示所有映射
        mapControl.print_maps();
    }
}

void cmd_protect(pid_t pid, const std::vector<std::string>& args) {
    if (args.size() != 4) {
        std::cout << "Usage: prot <address> <length> <protection>\n";
        std::cout << "  protection: combination of 1(r) 2(w) 4(x)\n";
        return;
    }

    try {
        MapControl mapControl(pid);
        void* address = (void*)std::stoull(args[1], nullptr, 16);
        size_t len = std::stoul(args[2], nullptr, 0);
        int prot = std::stoi(args[3], nullptr, 0);

        mapControl.change_map_permissions(address, len, prot);
        std::cout << "Protection changed\n";
    } catch (const std::exception& e) {
        std::cout << "Invalid parameters\n";
    }
}

void cmd_memory_read(pid_t pid, const std::vector<std::string>& args) {
    if (args.size() != 3) {
        std::cout << "Usage: mr <address> <length>\n";
        return;
    }

    try {
        void* address = (void*)std::stoull(args[1], nullptr, 16);
        size_t len = std::stoul(args[2], nullptr, 0);

        auto* buffer = new uint8_t[len];
        ssize_t bytes_read = read_memory_vm(pid, address, len, buffer);

        if (bytes_read > 0) {
            hexdump(buffer, bytes_read, (uintptr_t)address);
        } else {
            std::cout << "Failed to read memory\n";
        }

        delete[] buffer;
    } catch (const std::exception& e) {
        std::cout << "Invalid parameters\n";
    }
}

void cmd_memory_write(pid_t pid, const std::vector<std::string>& args) {
    if (args.size() < 3) {
        std::cout << "Usage: mw <address> <byte1> <byte2> ...\n";
        return;
    }

    try {
        void* address = (void*)std::stoull(args[1], nullptr, 16);
        std::vector<uint8_t> bytes(args.size() - 2);

        for (size_t i = 2; i < args.size(); i++) {
            bytes[i - 2] = (uint8_t)std::stoull(args[i], nullptr, 16);
        }

        ssize_t written = write_memory_ptrace(pid, address, bytes.data(), bytes.size());
        if (written > 0) {
            std::cout << "Wrote " << written << " bytes\n";
        } else {
            std::cout << "Failed to write memory\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Invalid parameters\n";
    }
}

void cmd_trace(pid_t pid, const std::vector<std::string>& args) {
    if (args.size() != 3) {
        std::cout << "Usage: trace <start_addr> <end_addr>\n";
        return;
    }

    try {
        uintptr_t start = std::stoull(args[1], nullptr, 16);
        uintptr_t end = std::stoull(args[2], nullptr, 16);

        // 初始化trace
        trace_start(start, end);

        // 获取当前PC
        uint64_t pc = 0;
        get_reg(pid, "pc", &pc);

        if (pc == start) {
            // 已经在起始点，直接开始trace
            g_pcb.trace_started = true;
            g_pcb.state = DebuggerState::TRACE_ACTIVE;
            trace_log_step(pid);
            ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
            g_pcb.need_wait_signal = true;
            LOGI("Starting trace from current position");
        } else {
            // 需要先运行到起始点
            bp_set_temp(pid, (void*)start);
            g_pcb.state = DebuggerState::TRACE_WAIT_START;

            // 处理当前位置的断点
            if (has_breakpoint_at((void*)pc)) {
                bp_temp_disable(pid, (void*)pc);
                ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
                int status;
                waitpid(pid, &status, 0);
                bp_restore_temp_disabled(pid);
            }

            ptrace(PTRACE_CONT, pid, 0, 0);
            g_pcb.need_wait_signal = true;
            LOGI("Running to trace start point: 0x%lx", start);
        }
    } catch (const std::exception& e) {
        std::cout << "Invalid parameters\n";
    }
}

void cmd_print_pcb(pid_t pid, const std::vector<std::string>& args) {
    printf("\n===== PCB Status =====\n");

    // 基本信息
    printf("Process:\n");
    printf("  PID: %d\n", g_pcb.pid);
    printf("  Need wait signal: %s\n", g_pcb.need_wait_signal ? "Yes" : "No");

    // 调试器状态
    printf("\nDebugger State:\n");
    printf("  Current state: %s\n", state_to_string(g_pcb.state));
    printf("  Last stop reason: %s\n", stop_reason_to_string(g_pcb.last_stop_reason));

    // 断点状态
    printf("\nBreakpoint Status:\n");
    printf("  Temp disabled BP: %s", g_pcb.temp_disabled_bp ? "Yes" : "No");
    if (g_pcb.temp_disabled_bp) {
        printf(" (0x%lx)", (uintptr_t)g_pcb.temp_disabled_bp);
    }
    printf("\n");

    printf("  Step over BP: %s", g_pcb.step_over_bp ? "Yes" : "No");
    if (g_pcb.step_over_bp) {
        printf(" (0x%lx)", (uintptr_t)g_pcb.step_over_bp);
    }
    printf("\n");

    // Trace状态
    printf("\nTrace Status:\n");
    printf("  Begin: 0x%lx\n", g_pcb.trace_begin);
    printf("  End: 0x%lx\n", g_pcb.trace_end);
    printf("  Started: %s\n", g_pcb.trace_started ? "Yes" : "No");
    printf("  File: %s\n", g_pcb.trace_fp ? "Open" : "Closed");

    // 反汇编状态
    printf("\nDisassembly:\n");
    printf("  Last address: 0x%lx\n", g_pcb.last_disasm_addr);

    // 当前PC
    uint64_t current_pc = 0;
    if (get_reg(pid, "pc", &current_pc) == 0) {
        printf("\nCurrent PC: 0x%lx\n", current_pc);
    }

    printf("======================\n\n");
}

void cmd_help(pid_t pid, const std::vector<std::string>& args) {
    std::cout << "\n===== Available Commands =====\n";
    std::cout << "Execution Control:\n";
    std::cout << "  g              - Continue execution\n";
    std::cout << "  s              - Step into (single step)\n";
    std::cout << "  n              - Step over\n";
    std::cout << "  stop           - Send SIGSTOP to process\n";
    std::cout << "\n";

    std::cout << "Breakpoints:\n";
    std::cout << "  bp <addr>      - Set breakpoint at address\n";
    std::cout << "  bpl            - List all breakpoints\n";
    std::cout << "  bpc <index>    - Clear breakpoint by index\n";
    std::cout << "\n";

    std::cout << "Memory:\n";
    std::cout << "  mr <addr> <len>        - Read memory\n";
    std::cout << "  mw <addr> <bytes...>   - Write memory\n";
    std::cout << "  map [filter]           - Show memory maps\n";
    std::cout << "  prot <addr> <len> <p>  - Change memory protection (p=1|2|4)\n";
    std::cout << "\n";

    std::cout << "Registers & Disassembly:\n";
    std::cout << "  r [reg] [val]  - Show/set registers\n";
    std::cout << "  u [addr]       - Disassemble at address or continue\n";
    std::cout << "\n";

    std::cout << "Tracing:\n";
    std::cout << "  trace <start> <end> - Trace execution from start to end\n";
    std::cout << "\n";

    std::cout << "Other:\n";
    std::cout << "  p              - Print PCB status\n";
    std::cout << "  help           - Show this help\n";
    std::cout << "  q/quit         - Quit debugger\n";
    std::cout << "===============================\n\n";
}

void cmd_quit(pid_t pid, const std::vector<std::string>& args) {
    std::cout << "Detaching from process and exiting...\n";

    // 清理trace
    if (g_pcb.trace_fp) {
        trace_reset();
    }

    // 分离进程
    detach_process(pid);

    // 退出程序
    exit(0);
}