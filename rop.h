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

struct API
{
    struct Gadget *writeMEM;
    struct Gadget *readMEM;
    struct Gadget *writeREG;
    struct Gadget *zeroREG;
    struct Gadget *xchgREG;
    struct Gadget *shiftREG;
    struct Gadget *addREG;
    struct Gadget *cmpFLAG;
    struct Gadget *saveFLAG;
    struct Gadget *deltaFLAG;
    struct Gadget *INT;
    int result_writeMEM;
    int result_readMEM;
    int result_writeREG;
    int result_zeroREG;
    int result_xchgREG;
    int result_shiftREG;
    int result_addREG;
    int result_cmpFLAG;
    int result_saveFLAG;
    int result_deltaFLAG;
    int result_INT;
};

int rop_chain(unsigned char **chain, unsigned char *binary, struct Arg *arg);
int rop_parse_gadgets(struct Node *root, unsigned char *binary, struct Segment *text,struct Arg *arg);
int rop_chain_execve(struct Node *root, struct Gadget *head,struct Arg *arg);
void rop_build_api(struct Node *root, struct API **api, struct Arg *arg);
void rop_end_api(struct API *api);

int rop_build_write_memory_gadget(struct Node *root, struct Gadget **writeMEM, struct Arg *arg);
int rop_write_memory_gadget(struct Gadget *head, struct API *api, unsigned int dest, unsigned int value);

int rop_build_read_memory_gadget(struct Node *root, struct Gadget **readMEM, struct Arg *arg);
int rop_read_memory_gadget(struct Gadget *head, struct API *api, char *dest, unsigned int src);

int rop_build_write_register_gadget(struct Node *root, struct Gadget **writeREG, struct Arg *arg);
int rop_write_register_gadget(struct API *api, char *dest, unsigned int value);
int rop_chain_write_register_gadget(struct Gadget *head, struct API *api);

int rop_build_zero_register_gadget(struct Node *root, struct Gadget **zeroREG, struct Arg *arg);
int rop_zero_register_gadget(struct Gadget *head, struct API *api, char *dest);

int rop_build_xchg_register_gadget(struct Node *root, struct Gadget **xchgREG, struct Arg *arg);
int rop_xchg_register_gadget(struct Gadget *head, struct API *api, char *op1, char *op2);
int rop_build_add_register_gadget(struct Node *root, struct Gadget **addREG, struct Arg *arg);
int rop_add_register_gadget(struct Gadget *head, struct API *api, char *dest, unsigned int value);

int rop_build_shift_register_gadget(struct Node *root, struct Gadget **shiftREG, struct Arg *arg);
int rop_shift_register_gadget(struct Gadget *head, struct API *api, char *dest);

int rop_build_cmp_flag_gadget(struct Node *root, struct Gadget **cmpFLAG, struct Arg *arg);
int rop_cmp_flag_gadget(struct Gadget *head, struct API *api, char *op1, char *op2);
int rop_build_save_flag_gadget(struct Node *root, struct Gadget **saveFLAG, struct Arg *arg);
int rop_save_flag_gadget(struct Gadget *head, struct API *api, unsigned int dest);
int rop_build_delta_flag_gadget(struct Node *root, struct Gadget **deltaFLAG, struct Arg *arg, struct API *api);
int rop_delta_flag_gadget(struct Gadget *head, struct API *api, unsigned int dest, int delta, char *flag);

int rop_build_interrupt_gadget(struct Node *root, struct Gadget **INT, struct Arg *arg);
int rop_interrupt_gadget(struct Gadget *head, struct API *api);

int rop_gadget_info_update(struct Gadget *gadget);
int rop_parse_instruction(char *instr, struct Gadget *gadget);

void rop_chain_list_init(struct Gadget *head);
int rop_chain_list_add(struct Gadget *head, unsigned int address, char *string, int tail);
int rop_chain_list_traverse(struct Gadget *head, unsigned char **chain);
void rop_chain_list_free(struct Gadget *head);

#endif
