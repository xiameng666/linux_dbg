//
// Created by XiaM on 2025/9/11.
//

#ifndef LINUX_DBG_DBG_COMMAND_H
#define LINUX_DBG_DBG_COMMAND_H

#include "dbg_core.h"

typedef void (*CommandHandler)(pid_t pid, const std::vector<std::string>& args);

/*

  1. 单步
     [s]:步入  OK  1
     [n]:步过       1
  2. 断点
     [bp addr]
     [bpl]  查看断点 OK    1 
     [bpc 编号] 清除断点  OK    1
  3. 内存操作
     [mr addr len] 读取内存  OK    1
     [mw addr xx xx ...] 写入内存   OK    1
  4. 跟踪
     [trace begin end]   步入到指定地址 然后将返汇编存到文件 
  5. 寄存器
     [r]  OK   1
     [r reg val]修改寄存器  OK  1
  6. 反汇编
     [u] 当前位置   OK   1
     [u addr] 目标位置   OK   1 
7. 遍历模块
*/
void command_loop(pid_t pid);

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

#endif //LINUX_DBG_DBG_COMMAND_H
