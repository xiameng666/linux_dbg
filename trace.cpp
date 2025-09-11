//
// Created by XiaM on 2025/9/11.
//
#include "trace.h"
#include "dbg_core.h"
#include "trace.h"

void Trace::start(uintptr_t begin, uintptr_t end) {
    begin_ = begin;
    end_ = end;
    enabled_ = true;

    if(fp_ && begin == -1){// 当推出
        close();
    }

    if (fp_) return;

    fp_ = std::fopen("trace.log", "w");
    if (!fp_) {
        LOGE("Trace.start fp 打开失败");
    }
}

void Trace::close() {
    if (fp_) {
        std::fflush(fp_);
        std::fclose(fp_);
        fp_ = nullptr;
    }
}

void Trace::log_step(pid_t pid){
    if(!enabled_ || !fp_) return;

    uint64_t pc = 0;
    if (get_reg(pid, "pc", &pc) != 0) return;

    LOG_ENTER("pc: %lu",pc);

    uint8_t inst[4] = {0};
    if (read_memory_vm(pid, (void*)pc, sizeof(inst), inst) != sizeof(inst)) {
        std::fprintf(fp_, "[read fail] PC=0x%lx\n", pc);
        std::fflush(fp_);
        return;
    }
    std::string line = ::disasm(inst, sizeof(inst), pc, false);
    std::fprintf(fp_, "%s\n",line.c_str());
    std::fflush(fp_);
}
