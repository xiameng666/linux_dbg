//
// Created by XiaM on 2025/9/11.
//

#ifndef LINUX_DBG_DBG_COMMAND_H
#define LINUX_DBG_DBG_COMMAND_H

#include "dbg_core.h"
#include <functional>
#include <unordered_map>

// 命令处理函数类型
typedef void (*CommandHandler)(pid_t pid, const std::vector<std::string>& args);

// 命令循环
void command_loop(pid_t pid);

// 命令处理函数
void cmd_continue(pid_t pid, const std::vector<std::string>& args);
void cmd_step_into(pid_t pid, const std::vector<std::string>& args);
void cmd_step_over(pid_t pid, const std::vector<std::string>& args);
void cmd_stop(pid_t pid, const std::vector<std::string>& args);
void cmd_breakpoint(pid_t pid, const std::vector<std::string>& args);
void cmd_bp_list(pid_t pid, const std::vector<std::string>& args);
void cmd_bp_clear(pid_t pid, const std::vector<std::string>& args);
void cmd_memory_read(pid_t pid, const std::vector<std::string>& args);
void cmd_memory_write(pid_t pid, const std::vector<std::string>& args);
void cmd_trace(pid_t pid, const std::vector<std::string>& args);
void cmd_registers(pid_t pid, const std::vector<std::string>& args);
void cmd_disasm(pid_t pid, const std::vector<std::string>& args);
void cmd_maps(pid_t pid, const std::vector<std::string>& args);
void cmd_protect(pid_t pid, const std::vector<std::string>& args);
void cmd_print_pcb(pid_t pid, const std::vector<std::string>& args);
void cmd_help(pid_t pid, const std::vector<std::string>& args);
void cmd_quit(pid_t pid, const std::vector<std::string>& args);

// 辅助函数
std::string get_user_command();
void execute_command(pid_t pid, const std::string& cmd);

#endif //LINUX_DBG_DBG_COMMAND_H