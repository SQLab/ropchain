#ifndef _rop_h
#define _rop_h
#define _rop_h

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>

struct Gadget{
    char string[500];
    unsigned int address;
    struct Gadget *prev;
    struct Gadget *next;
};

struct Chain_List{
    int count;
    struct Gadget *first;
    struct Gadget *last;
};

int rop_findgadgets(unsigned char *binary, unsigned long binary_len);
int rop_find(char* operate, char* operand, size_t count, cs_insn *insn, struct Chain_List *LIST);

void rop_chain_list_init(struct Chain_List *LIST);
void rop_chain_list_add(struct Chain_List *LIST, unsigned int address, char *string);
void rop_chain_list_traverse(struct Chain_List *LIST);

#endif
