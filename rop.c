#include "rop.h"

int rop_findgadgets(char *binary, unsigned long binary_len)
{

    size_t count;
    csh handle;
    cs_insn *insn;

    struct Gadget GADGET;
    strcpy(GADGET.string,"");

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
        return -1;
    count = cs_disasm_ex(handle, binary, binary_len, 0x08048000, 0, &insn);
    if (count > 0) {
        rop_find("pop","ebp",count,insn,GADGET);
        rop_find("mov","xxx",count,insn,GADGET);
        cs_free(insn, count);
    } 
    else{
        printf("ERROR: Failed to disassemble given code!\n");
    }
    cs_close(&handle);
    return 0;
}

int rop_find(char* operate, char* operand, size_t count, cs_insn *insn, struct Gadget GADGET)
{
    size_t j;
    for (j = 0; j < count; j++) {
        /*
        printf("0x0%"PRIx64":\t%s\t\t%s\n", insn[j].address, \
        insn[j].mnemonic,insn[j].op_str);
        */
        if(!strcmp(insn[j].mnemonic,"ret") && !strcmp(insn[j-1].mnemonic,operate) && \
                (!strcmp(insn[j-1].op_str,operand) || !strcmp(operand,"xxx")))
        {
            strcat(GADGET.string,insn[j-1].mnemonic);
            strcat(GADGET.string," ");
            strcat(GADGET.string,insn[j-1].op_str);
            strcat(GADGET.string," ; ");
            GADGET.address = insn[j-1].address;
            strcat(GADGET.string,"ret");
            printf("0x0%x: %s\n",GADGET.address,GADGET.string);
            strcpy(GADGET.string,"");
            return 0;		
        }
    }
    printf("Can't find '%s %s; ret'\n",operate,operand);
    return -1;
}
