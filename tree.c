#include "tree.h"

void tree_init(struct Node* root)
{
    root->leftchild = NULL;
    root->rightsibling = NULL;
    root->vaild = 1;
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
        node[i]->vaild = 1;
        node[i]->address = 0;
        node[i]->leftchild = NULL;
        node[i]->rightsibling = NULL;
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
        if(strlen(insn[i].op_str) > 0)
        {
            strcat(instruct_string, " ");
            strcat(instruct_string, insn[i].op_str);
        }
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

struct Node *tree_search(struct Node* root, char* regexp_string, char* gadget_string, int depth, struct Arg *arg)
{
    struct Node* child,* temp;
    unsigned char *address;
    size_t i, j;
    regex_t regex;
    int reti;
    char msgbuf[100];

    /* Compile regular expression */
    reti = regcomp(&regex, regexp_string, 0);
    if(reti)
    {
        fprintf(stderr, "Could not compile regex\n");
        exit(1);
    }
    child = root->leftchild;
    while(child)
    {
        /* Execute regular expression */
        reti = regexec(&regex, child->string, 0, NULL, 0);
        /* Match and vaild */
        if(!reti && child->vaild)
        {
            strcat(gadget_string, child->string);
            strcat(gadget_string, "; ");
            /* leaf */
            if(child->address)
            {
                address = (unsigned char*)&child->address;
                /* badbyte cheching */
                for(i = 0; i < 4; i++)
                {
                    for(j = 0 ; j < arg->badbyte_no; j++)
                    {
                        if(address[i] == arg->badbyte[j])
                        {
                            i = 4;
                            break;
                        }
                    }
                    if(i == 3)
                    {
                        /* Free compiled regular expression */
                        regfree(&regex);
                        return child;
                    }
                }
            }
            /* not leaf */
            else
            {
                /* Free compiled regular expression */
                if(depth == 1)
                {
                    temp = tree_search(child, "^ret$", gadget_string, 0, arg);
                    if(temp)
                    {
                        regfree(&regex);
                        return temp;

                    }
                }
            }
        }
        else if(!reti && !child->vaild)
        {
            /* Match but invaild */
        }
        else if(reti == REG_NOMATCH)
        {
            /* No match */
        }
        else
        {
            regerror(reti, &regex, msgbuf, sizeof(msgbuf));
            fprintf(stderr, "Regex match failed: %s\n", msgbuf);
            exit(1);
        }
        child = child->rightsibling;
    }
    /* Free compiled regular expression */
    regfree(&regex);
    memset(gadget_string, 0, MaxGadgetLen);
    return 0;
}

void tree_free(struct Node* root)
{
    struct Node *temp, *node;
    node = root;
    if(node->leftchild)
    {
        tree_free(node->leftchild);
        temp = node;
        temp->leftchild = NULL;
    }
    node = root;
    if(node->rightsibling)
    {
        tree_free(node->rightsibling);
        temp = node;
        temp->rightsibling = NULL;
    }
    free(root);
}
