#ifndef _spec_h
#define _spec_h

#include "rop.h"

struct Gadget
{
    char string[MaxGadgetLen];
    char target_write[4];
    char total_target_write[20][4];
    char gadget_write[20][4];
    int total_target_write_no;
    int gadget_write_no;
    int padding;
    int order;
    unsigned int address;
    struct Gadget *next;
    struct Gadget *prev;
};

int rop_chain_execve(struct Node *root, struct Gadget *head,struct Arg *arg);

#endif
