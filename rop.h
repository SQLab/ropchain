#ifndef _rop_h
#define _rop_h
#define _rop_h

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>
#define MaxGadgetLen 100

#define MaxGadgetLen 100
#define MaxGadgetByte 4

struct Gadget{
    char string[MaxGadgetLen];
    unsigned int address;
    struct Gadget *next;
    struct Gadget *prev;
};

int rop_chains(unsigned char *binary, unsigned long binary_len);
int rop_find_gadgets(char* operate, char* operand, struct Gadget *head, unsigned char *binary, unsigned long binary_len);

void rop_chain_list_init(struct Gadget *head);
int rop_chain_list_add(struct Gadget *head, unsigned int address, char *string);
void rop_chain_list_traverse(struct Gadget *HEAD);

#endif
