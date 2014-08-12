#ifndef _rop_h
#define _rop_h

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>
#include "tree.h"
#define MaxGadgetLen 200
#define MaxGadgetByte 9

struct Gadget{
    char string[MaxGadgetLen];
    unsigned int address;
    struct Gadget *next;
    struct Gadget *prev;
};

int rop_chains(unsigned char *binary, unsigned long binary_len);
int rop_parse_gadgets(struct Node *root, unsigned char *binary, unsigned long binary_len);

void rop_chain_list_init(struct Gadget *head);
void rop_chain_list_traverse(struct Gadget *head);
void rop_chain_list_free(struct Gadget *head);

#endif
