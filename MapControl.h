//
// Created by XiaM on 2025/9/10.
//

#ifndef LINUX_DBG_MAPCONTROL_H
#define LINUX_DBG_MAPCONTROL_H

#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include "log.h"

#define PAGE_START(addr) (((uintptr_t)(addr) & PAGE_MASK))
#define PAGE_END(addr) ((((uintptr_t)(addr) + PAGE_SIZE - 1) & PAGE_MASK))

struct MapData{
    void* start_addr;
    void* end_addr;
    char permissions [8];
    int prot_flags;
    uint64_t offset;
    char device[16];
    uint64_t inode;
    std::string path;
};

class MapControl {
public:
     MapControl(pid_t pid){
        pid_ = pid;
        parse(pid);
    }
     ~MapControl() = default;

    pid_t pid_;
    std::vector<MapData> maps_;
    int temp_prot_;//如果修改了地址属性，会临时保存旧属性到此
    void* temp_address_;      // 原始页起始地址
    size_t temp_length_;      // 原始页长度

public:
    inline const MapData* find_region(void* address) const {
        LOG("--->find_region(%p)", address);

        for (const auto& map : maps_) {
            LOG("  [0x%p-0x%p]",
                map.start_addr, map.end_addr);

            if (address >= map.start_addr && address < map.end_addr) {

                return &map;
            }
        }
        return nullptr;
    }

    //解析并存储map数据
    inline bool parse(pid_t pid){
        LOG_ENTER("(pid=%d)", pid);
        maps_.clear();

        char maps_cmd[256];
        snprintf(maps_cmd,sizeof (maps_cmd),"/proc/%d/maps",pid);

        FILE* fp = fopen(maps_cmd,"r");
        if(!fp){
            LOGE("fopen maps失败");
            return false;
        }

        char line[1024];
        while(fgets(line,sizeof(line),fp)){
            MapData map{};
            char path_buf[256];
            unsigned long start_addr_temp, end_addr_temp;
            int result = sscanf(line,"%lx-%lx %7s %lx %15s %lu %s",
                                &start_addr_temp,
                                &end_addr_temp,
                                map.permissions,
                                &map.offset,
                                map.device,
                                &map.inode,
                                path_buf);

            map.start_addr = (void*)start_addr_temp;
            map.end_addr = (void*)end_addr_temp;
            map.path = path_buf;
            map.prot_flags = permissions_to_prot(map.permissions);

            maps_.emplace_back(map);
        }

        return true;
    }

    // 显示所有内存映射，支持可选的过滤字符串
    inline void print_maps(const std::string& filter = "") const {
        LOG("/proc/%d/maps | grep %s",pid_,filter.c_str());

        for (size_t i = 0; i < maps_.size(); i++) {
            const auto& map = maps_[i];
            
            char full_info[1024];
            snprintf(full_info, sizeof(full_info), "%016lx-%016lx %s prot=0x%x %s",
                    (uintptr_t)map.start_addr, (uintptr_t)map.end_addr,
                    map.permissions, map.prot_flags, map.path.c_str());
            
            // 如果没有过滤条件，或者匹配过滤条件，则显示
            if (filter.empty() || std::string(full_info).find(filter) != std::string::npos) {
                printf("[%zu] %s\n", i, full_info);
            }
        }
        LOG("=================");
    }

    inline int permissions_to_prot(const char* perms) {
        int prot = 0;
        if (perms[0] == 'r') prot |= PROT_READ;
        if (perms[1] == 'w') prot |= PROT_WRITE;
        if (perms[2] == 'x') prot |= PROT_EXEC;
        return prot;
    }

    //
    inline bool change_map_permissions(void* address,size_t len,int new_protect){
        const MapData* region = find_region(address);
        if (!region) {
            LOGE("地址 %p 不在任何映射区域内", address);
            return false;
        }

        LOG("找到区域: %016lx-%016lx %s %s",
            (uintptr_t)region->start_addr, (uintptr_t)region->end_addr,
            region->permissions, region->path.c_str());

        uintptr_t page_start = PAGE_START(address);
        uintptr_t page_end = PAGE_END((char*)address + len);
        size_t page_len = page_end - page_start;

        //保存原始信息 修改权限
        temp_prot_ = region->prot_flags;
        temp_address_ = (void*)page_start;
        temp_length_ = page_len;
        if (mprotect((void*)page_start, page_len, new_protect) == -1){
            LOGE("mprotect失败: %s", strerror(errno));
            LOGE("  地址: 0x%lx, 长度: %zu, 权限: 0x%x", page_start, page_len, new_protect);
            return false;
        }

        LOG("成功修改权限: %lu-%lu", page_start, page_end);
        return true;
    }

    inline bool resume_map_permissions(){
        LOG_ENTER("()");

        LOG("恢复权限: 地址=%p, 长度=%zu, 权限=0x%x",
            temp_address_, temp_length_, temp_prot_);

        if (mprotect(temp_address_, temp_length_, temp_prot_) == -1) {
            LOGE("恢复权限失败: %s", strerror(errno));
            LOGE("  地址: %p, 长度: %zu, 权限: 0x%x",
                 temp_address_, temp_length_, temp_prot_);
            return false;
        }

        return true;
    }

};


#endif //LINUX_DBG_MAPCONTROL_H
