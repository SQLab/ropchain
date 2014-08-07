#ifndef _rop_h
#define _rop_h
#define _rop_h

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>

struct Gadget{
    char string[100];
    unsigned int address;
    struct Gadget *next;
    struct Gadget *last;
};

int rop_chains(unsigned char *binary, unsigned long binary_len);
int rop_find_gadgets(char* operate, char* operand, size_t count, cs_insn *insn, struct Gadget *head);

void rop_chain_list_init(struct Gadget *head);
void rop_chain_list_add(struct Gadget *head, unsigned int address, char *string);
void rop_chain_list_traverse(struct Gadget *HEAD);

#endif
