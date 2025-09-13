//
// Created by XiaM on 2025/9/13.
//

#ifndef LINUX_DBG_BREAKPOINT_H
#define LINUX_DBG_BREAKPOINT_H
#include "dbg_core.h"

////
//bool bp_set(pid_t pid,void* address);
//bool bp_set_temp_for_step_over(pid_t pid, void* address);  // 设置步过操作的临时断点
//bool bp_clear(pid_t pid, size_t index);
//void bp_show();
//void print_singel_bp(size_t index);
//void bp_temp_disable(pid_t pid, void* address);  // 临时禁用断点
//void bp_restore_temp_disabled(pid_t pid);  // 恢复临时禁用的断点
//bool bp_is_at_address(void* address);  // 检查指定地址是否有断点
//bool bp_is_temp_for_step_over(void* address);  // 检查是否是步过的临时断点
//void bp_clear_all_temp_for_step_over(pid_t pid);  // 清除所有步过的临时断点
//
//void bp_trace_disable_all(pid_t pid);  // trace开始时禁用所有断点
//void bp_trace_enable_all(pid_t pid);   // trace结束时启用所有断点
//
//
//static std::vector<breakpoint> g_bp_vec;


//// 设置步过操作的临时断点
//bool bp_set_temp_for_step_over(pid_t pid, void *address) {
//    LOG_ENTER("(pid=%d, address=%p)", pid, address);
//    uint32_t BRK = 0xD4200000;
//
//    do{
//        //已存在 跳过
//        for(auto& bp:g_bp_vec){
//            if(bp.address == address) {
//                // 如果已存在，标记为临时断点
//                bp.is_temp = true;
//                return true;
//            }
//        }
//
//        uint32_t orig  = 0;
//        if (read_memory_vm(pid, address, 4, &orig) != 4) break;
//        if (write_memory_ptrace(pid, address, &BRK, 4) != 4)  break;
//
//        breakpoint newbp{address, orig, true};  // 标记为临时断点
//        g_bp_vec.emplace_back(newbp);
//        // 临时断点不打印给用户看 print_singel_bp(g_bp_vec.size()-1);
//        return true;
//
//    }while(0);
//
//    LOGE("bp_set_temp_for_step_over 失败");
//    return false;
//}
//
//bool bp_clear(pid_t pid, size_t index) {
//    LOG_ENTER("(pid=%d, index=%zu)", pid, index);
//
//    breakpoint& bp = g_bp_vec[index];
//
//    /*如果在程序遇到断点trap的时候先禁用了断点 此时删除断点 当再go的时候 断点又被写回了
//    *检查要删除的断点是否是当前临时禁用的断点*/
//    if (bp.address == g_pcb.temp_disabled_bp) {
//        LOGD("清除临时禁用状态: 0x%lx", (unsigned long)bp.address);
//        g_pcb.temp_disabled_bp = nullptr;  // 清除临时禁用状态
//        // 断点已经被临时禁用 不需要写回原数据了
//    } else {
//        // 如果断点当前是激活状态，需要写回原始指令
//        if (write_memory_ptrace(pid, bp.address, (void *) &bp.origin_inst, 4) != 4) {
//            LOGE("bp_clear 写回指令失败");
//            return false;
//        }
//    }
//
//    g_bp_vec.erase(g_bp_vec.begin() + index);
//    return true;
//}
//
//void bp_show() {
//    LOG_ENTER("");
//
//    for (size_t i = 0; i < g_bp_vec.size(); ++i) {
//        // 跳过步过操作的临时断点
//        if (!g_bp_vec[i].is_temp) {
//            print_singel_bp(i);
//        }
//    }
//}
//
//
//
//void print_singel_bp(size_t index) {
//    const auto& bp = g_bp_vec[index];
//    printf("[%zu] addr=0x%016lx inst=0x%08x\n",
//           index,
//           (unsigned long)bp.address,
//           bp.origin_inst);
//}
//
//// 临时禁用指定地址的断点（写回原始指令）
//void bp_temp_disable(pid_t pid, void* address) {
//    LOG_ENTER("(pid=%d, address=%p)", pid, address);
//
//    for (const auto& bp : g_bp_vec) {
//        if (bp.address == address) {
//            // 写回原始指令
//            if (write_memory_ptrace(pid, bp.address, (void*)&bp.origin_inst, 4) == 4) {
//                g_pcb.temp_disabled_bp = address;
//                LOGD("临时禁用断点: 0x%lx", (unsigned long)address);
//            } else {
//                LOGE("禁用断点失败: 0x%lx", (unsigned long)address);
//            }
//            break;
//        }
//    }
//}
//
//// 恢复临时禁用的断点（重新写入BRK）
//void bp_restore_temp_disabled(pid_t pid) {
//    LOG_ENTER("(pid=%d)", pid);
//
//    if (g_pcb.temp_disabled_bp != nullptr) {
//        uint32_t BRK = 0xD4200000;
//        if (write_memory_ptrace(pid, g_pcb.temp_disabled_bp, (void*)&BRK, 4) == 4) {
//            LOGD("恢复临时禁用的断点: 0x%lx", (unsigned long)g_pcb.temp_disabled_bp);
//            g_pcb.temp_disabled_bp = nullptr;
//        } else {
//            LOGE("恢复断点失败: 0x%lx", (unsigned long)g_pcb.temp_disabled_bp);
//        }
//    }
//}
//
//// 检查指定地址是否有断点
//bool bp_is_at_address(void* address) {
//    for (const auto& bp : g_bp_vec) {
//        if (bp.address == address) {
//            return true;
//        }
//    }
//    return false;
//}
//
//// 检查是否是步过的临时断点
//bool bp_is_temp_for_step_over(void* address) {
//    for (const auto& bp : g_bp_vec) {
//        if (bp.address == address && bp.is_temp) {
//            return true;
//        }
//    }
//    return false;
//}
//
//// 清除所有步过的临时断点
//void bp_clear_all_temp_for_step_over(pid_t pid) {
//    for (int i = g_bp_vec.size() - 1; i >= 0; i--) {
//        if (g_bp_vec[i].is_temp) {
//            LOGD("清除步过临时断点: 0x%lx", (unsigned long)g_bp_vec[i].address);
//            bp_clear(pid, i);
//        }
//    }
//}

enum BpType{
    common = 0,
    temp_go,
    temp_step_over
};

struct breakpoint{
    void* address = nullptr;
    uint32_t origin_inst =0;
    BpType type = common;
};

class Breakpoint {
public:
    std::vector<breakpoint> vec_;
    void* temp_disabled_bp = nullptr;  // 临时禁用的断点地址

    inline bool bp_set(pid_t pid, void* address,BpType type) {
        LOG_ENTER("(pid=%d, address=%p)", pid, address);
        uint32_t BRK = 0xD4200000;

        do {
            // 已存在 跳过
            for (auto& bp : vec_) {
                if (bp.address == address) {
                    return true;
                }
            }

            uint32_t orig = 0;
            if (read_memory_vm(pid, address, 4, &orig) != 4) break;
            if (write_memory_ptrace(pid, address, &BRK, 4) != 4) break;

            breakpoint newbp{address, orig, common};
            vec_.emplace_back(newbp);
            print_singel_bp(vec_.size() - 1);
            return true;

        } while (0);

        LOGE("bp_set 失败");
        return false;
    }

    inline bool bp_set_temp_for_step_over(pid_t pid, void* address) {
        LOG_ENTER("(pid=%d, address=%p)", pid, address);
        uint32_t BRK = 0xD4200000;

        do {
            // 已存在 跳过
            for (auto& bp : vec_) {
                if (bp.address == address) {
                    // 如果已存在，标记为临时断点
                    bp.type = temp_step_over;
                    return true;
                }
            }

            uint32_t orig = 0;
            if (read_memory_vm(pid, address, 4, &orig) != 4) break;
            if (write_memory_ptrace(pid, address, &BRK, 4) != 4) break;

            breakpoint newbp{address, orig, temp_step_over};  // 标记为临时断点
            vec_.emplace_back(newbp);
            // 临时断点不打印给用户看 print_singel_bp(vec_.size()-1);
            return true;

        } while (0);

        LOGE("bp_set_temp_for_step_over 失败");
        return false;
    }

    inline bool bp_clear(pid_t pid, size_t index) {
        LOG_ENTER("(pid=%d, index=%zu)", pid, index);

        breakpoint& bp = vec_[index];

        /*如果在程序遇到断点trap的时候先禁用了断点 此时删除断点 当再go的时候 断点又被写回了
        *检查要删除的断点是否是当前临时禁用的断点*/
        if (bp.address == temp_disabled_bp) {
            LOGD("清除临时禁用状态: 0x%lx", (unsigned long)bp.address);
            temp_disabled_bp = nullptr;  // 清除临时禁用状态
            // 断点已经被临时禁用 不需要写回原数据了
        } else {
            // 如果断点当前是激活状态，需要写回原始指令
            if (write_memory_ptrace(pid, bp.address, (void*)&bp.origin_inst, 4) != 4) {
                LOGE("bp_clear 写回指令失败");
                return false;
            }
        }

        vec_.erase(vec_.begin() + index);
        return true;
    }

    inline void bp_show() {
        LOG_ENTER("");

        for (size_t i = 0; i < vec_.size(); ++i) {
            // 跳过步过操作的临时断点
            if (vec_[i].type != temp_step_over) {
                print_singel_bp(i);
            }
        }
    }

    inline void print_singel_bp(size_t index) {
        const auto& bp = vec_[index];
        printf("[%zu] addr=0x%016lx inst=0x%08x\n",
               index,
               (unsigned long)bp.address,
               bp.origin_inst);
    }

    inline void bp_temp_disable(pid_t pid, void* address) {
        LOG_ENTER("(pid=%d, address=%p)", pid, address);

        for (const auto& bp : vec_) {
            if (bp.address == address) {
                // 写回原始指令
                if (write_memory_ptrace(pid, bp.address, (void*)&bp.origin_inst, 4) == 4) {
                    temp_disabled_bp = address;
                    LOGD("临时禁用断点: 0x%lx", (unsigned long)address);
                } else {
                    LOGE("禁用断点失败: 0x%lx", (unsigned long)address);
                }
                break;
            }
        }
    }

    inline void bp_restore_temp_disabled(pid_t pid) {
        LOG_ENTER("(pid=%d)", pid);

        if (temp_disabled_bp != nullptr) {
            uint32_t BRK = 0xD4200000;
            if (write_memory_ptrace(pid, temp_disabled_bp, (void*)&BRK, 4) == 4) {
                LOGD("恢复临时禁用的断点: 0x%lx", (unsigned long)temp_disabled_bp);
                temp_disabled_bp = nullptr;
            } else {
                LOGE("恢复断点失败: 0x%lx", (unsigned long)temp_disabled_bp);
            }
        }
    }

    inline bool bp_is_at_address(void* address) {
        for (const auto& bp : vec_) {
            if (bp.address == address) {
                return true;
            }
        }
        return false;
    }

    inline bool bp_is_temp_for_step_over(void* address) {
        for (const auto& bp : vec_) {
            if (bp.address == address && bp.type == temp_step_over) {
                return true;
            }
        }
        return false;
    }

    inline void bp_clear_all_temp_for_step_over(pid_t pid) {
        for (int i = vec_.size() - 1; i >= 0; i--) {
            if (vec_[i].type == temp_step_over) {
                LOGD("清除步过临时断点: 0x%lx", (unsigned long)vec_[i].address);
                bp_clear(pid, i);
            }
        }
    }

    // inline void bp_trace_disable_all(pid_t pid) {
    //     LOG_ENTER("(pid=%d)", pid);
    //     for (auto& bp : vec_) {
    //         if (write_memory_ptrace(pid, bp.address, (void*)&bp.origin_inst, 4) != 4) {
    //             LOGE("禁用断点失败: 0x%lx", (unsigned long)bp.address);
    //         }
    //     }
    // }

    // inline void bp_trace_enable_all(pid_t pid) {
    //     LOG_ENTER("(pid=%d)", pid);
    //     uint32_t BRK = 0xD4200000;
    //     for (auto& bp : vec_) {
    //         if (write_memory_ptrace(pid, bp.address, (void*)&BRK, 4) != 4) {
    //             LOGE("启用断点失败: 0x%lx", (unsigned long)bp.address);
    //         }
    //     }
    // }
};


#endif //LINUX_DBG_BREAKPOINT_H
