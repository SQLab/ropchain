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
};

int rop_findgadgets(char *binary, unsigned long binary_len);
int rop_find(char* operate, char* operand, size_t count, cs_insn *insn, struct Gadget GADGET);

#endif
