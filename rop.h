#ifndef _rop_h
#define _rop_h

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>
#include "tree.h"
#include "elf.h"
#define MaxRegExpLen 100
#define MaxGadgetByte 20

struct Gadget{
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

int rop_chain(unsigned char **chain, unsigned char *binary, struct Arg *arg);
int rop_parse_gadgets(struct Node *root, unsigned char *binary, struct Segment *text,struct Arg *arg);
int rop_chain_execve(struct Node *root, struct Gadget *head,struct Arg *arg);

int rop_build_write_memory_gadget(struct Node *root, struct Gadget **writeMEM, struct Arg *arg);
int rop_write_memory_gadget(struct Gadget *head, struct Gadget *writeMEM, unsigned int dest, unsigned int value);

int rop_build_read_memory_gadget(struct Node *root, struct Gadget **readMEM, struct Arg *arg);
int rop_read_memory_gadget(struct Gadget *head, struct Gadget *readMEM, char *dest, unsigned int src);

int rop_build_write_register_gadget(struct Node *root, struct Gadget **writeREG, struct Arg *arg);
int rop_write_register_gadget(struct Gadget *writeREG, char *dest, unsigned int value);
int rop_chain_write_register_gadget(struct Gadget *head, struct Gadget *writeREG);

int rop_build_zero_register_gadget(struct Node *root, struct Gadget **zeroREG, struct Arg *arg);
int rop_zero_register_gadget(struct Gadget *head, struct Gadget *zeroREG, char *dest);

int rop_build_arith_register_gadget(struct Node *root, struct Gadget **arithREG, struct Arg *arg);
int rop_arith_register_gadget(struct Gadget *head, struct Gadget *arithREG, char *dest, unsigned int value);

int rop_build_interrupt_gadget(struct Node *root, struct Gadget **INT, struct Arg *arg);
int rop_interrupt_gadget(struct Gadget *head, struct Gadget *INT);

int rop_gadget_info_update(struct Gadget *gadget);
void rop_parse_instruction(char *instr, struct Gadget *gadget);

void rop_chain_list_init(struct Gadget *head);
int rop_chain_list_add(struct Gadget *head, unsigned int address, char *string, int tail);
int rop_chain_list_traverse(struct Gadget *head, unsigned char **chain);
void rop_chain_list_free(struct Gadget *head);

#endif
