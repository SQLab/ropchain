#include "rop.h"

int rop_findgadgets(unsigned char *binary, unsigned long binary_len)
{
    size_t count;
    csh handle;
    cs_insn *insn;

    struct Chain_List *LIST;
    LIST = (struct Chain_List *)malloc(sizeof(struct Chain_List));

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
        return -1;
    }

    count = cs_disasm_ex(handle, binary, binary_len, 0x08048000, 0, &insn);
    if (count > 0) 
    {
        rop_chain_list_init(LIST);

        rop_find("pop", "eax", count, insn,LIST);
        rop_find("pop", "ebx", count, insn,LIST);
        rop_find("pop", "ecx", count, insn,LIST);
        rop_find("pop", "edx", count, insn,LIST);
        rop_find("xor", "eax, eax", count,insn, LIST);
        rop_find("int", "0x80", count, insn, LIST);

        rop_chain_list_traverse(LIST);
        cs_free(insn, count);
    } 
    else
    {
        printf("ERROR: Failed to disassemble given code!\n");
    }
    cs_close(&handle);
    return 0;
}

int rop_find(char* operate, char* operand, size_t count, cs_insn *insn, struct Chain_List *LIST)
{
    size_t j;
    struct Gadget TEMP;

    strcpy(TEMP.string, "");

    for (j = 0; j < count; j++) 
    {
        if(!strcmp(insn[j].mnemonic, "ret") && \
                (!strcmp(insn[j-1].mnemonic, operate) || !strcmp(operate, "xxx"))&& \
                (!strcmp(insn[j-1].op_str, operand) || !strcmp(operand, "xxx")))
        {
            strcat(TEMP.string, insn[j-1].mnemonic);
            strcat(TEMP.string, " ");
            strcat(TEMP.string, insn[j-1].op_str);
            strcat(TEMP.string, " ; ");
            TEMP.address = insn[j-1].address;
            strcat(TEMP.string, "ret");

            rop_chain_list_add(LIST, TEMP.address, TEMP.string);
            strcpy(TEMP.string, "");
            return 0;
        }
    }
    printf("-x--------: Can't find '%s %s; ret'\n", operate, operand);
    return -1;
}


void rop_chain_list_init(struct Chain_List *LIST)
{
    LIST->first = LIST->last = 0;
    LIST->count = 0;
}

void rop_chain_list_add(struct Chain_List *LIST, unsigned int address, char *string)
{
    struct Gadget *GADGET;
    GADGET = calloc(1, sizeof(struct Gadget));
    if(!GADGET)
    {
        fprintf(stderr ,"calloc failed.\n");
    }
    GADGET->address = address;
    strcpy(GADGET->string, string);
    if(LIST->last)
    {
        LIST->last->next = GADGET;
        GADGET->prev = LIST->last;
        LIST->last = GADGET;
    }
    else
    {
        LIST->first = GADGET;
        LIST->last = GADGET;
    }
    LIST->count++;
}

void rop_chain_list_traverse(struct Chain_List *LIST)
{
    struct Gadget *TEMP;
    for(TEMP = LIST->first; TEMP; TEMP = TEMP->next)
    {
        printf("0x0%x: %s\n", TEMP->address, TEMP->string);
    }

}
