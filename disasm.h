//
// Created by XiaM on 2025/9/10.
//

#ifndef LINUX_DBG_DISASM_H
#define LINUX_DBG_DISASM_H
#include "capstone/capstone.h"

void disasm(const uint8_t *code ,size_t code_size, uint64_t address){
    csh  handle;
    cs_err error = cs_open(CS_ARCH_AARCH64,CS_MODE_ARM,&handle);
    if(error != CS_ERR_OK){
        printf("cs_open %s\r\n", cs_strerror(error));
        return;
    }

    cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON);//开启详细模式

    cs_insn* insn;
    size_t count = cs_disasm(handle, code, code_size, address, 1, &insn);
    if (count == 0) {
        cs_err derr = cs_errno(handle);
        printf("cs_disasm failed: %s\r\n", cs_strerror(derr));
        cs_close(&handle);
        return;
    }

    printf("%p %s %s\r\n",address,insn[0].mnemonic,insn[0].op_str);

    cs_free(insn,1);
    cs_close(&handle);
}

#endif //LINUX_DBG_DISASM_H
