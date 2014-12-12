#ifndef _tree_h
#define _tree_h

#define MaxInstructLen 100
#define MaxGadgetLen 200
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include <capstone/capstone.h>

struct Node{
    char string[MaxInstructLen];
    unsigned int address;
    struct Node* leftchild;
    struct Node* rightsibling;
};

struct Arg{
    bool print;
    int offset;
    unsigned char badbyte[20];
    unsigned int badbyte_no;
};

void tree_init(struct Node* root);
int tree_build(struct Node* root, unsigned int address, cs_insn *insn, size_t len);
struct Node *tree_search(struct Node* root, char* regexp_string, char* gadget_string, int depth, struct Arg *arg);
void tree_free(struct Node* root);

#endif
