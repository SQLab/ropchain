#include "tree.h"

void tree_init(struct Node* root)
{
    root->leftchild = NULL;
    root->rightsibling = NULL;
}

int tree_build(struct Node* root, unsigned int address, cs_insn *insn, size_t len)
{
    size_t i;
    char instruct_string[MaxInstructLen];
    struct Node *parent, *head;
    struct Node **node = (struct Node **)malloc(len * sizeof(struct Node));
    if(!node)
    {
        fprintf(stderr,"malloc failed.\n");
        return -1;
    }
    for(i = 0; i < len; i++)
    {
        node[i] = (struct Node *)malloc(sizeof(struct Node));
        if(!node[i])
        {
            fprintf(stderr,"malloc failed.\n");
            return -1;
        }
        node[i]->address = 0;
        node[i]->leftchild = NULL;
    }
    parent = root;
    for(i = 0; i < len; i++)
    {
        if(strlen(insn[i].mnemonic) + strlen(insn[i].op_str) + 1 > MaxInstructLen)
        {
            free(node[i]);
            return -1;
        }
        strcpy(instruct_string,"");
        strcat(instruct_string, insn[i].mnemonic);
        strcat(instruct_string, " ");
        strcat(instruct_string, insn[i].op_str);
        if(i == len-1)
        {
            /* leaf */
            node[i]->rightsibling = parent->leftchild;
            parent->leftchild = node[i];
            node[i]->address = insn[0].address;
            strcpy(node[i]->string, instruct_string);
        }
        else
        {
            /* branch */
            if(!parent->leftchild)
            {
                parent->leftchild = node[i];
                node[i]->rightsibling = NULL;
                parent = node[i];
                strcpy(node[i]->string, instruct_string);
            }
            else
            {
                head = parent->leftchild;
                while(head)
                {
                    if(!strcmp(head->string,instruct_string))
                    {
                        parent = head;
                        free(node[i]);
                        break;
                    }
                    head = head->rightsibling;
                }
                if(parent != head)
                {
                    node[i]->rightsibling = parent->leftchild;
                    parent->leftchild = node[i];
                    parent = node[i];
                    strcpy(node[i]->string, instruct_string);
                }
            }
        }
    }
    return 0;
}

unsigned int tree_search(struct Node* root, char* gadget_string)
{
    return 0;
}

void tree_free(struct Node* root)
{
}
