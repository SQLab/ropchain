#ifndef _tree_h
#define _tree_h

#define MaxInstructLen 100
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>

struct Node{
    char string[100];
    unsigned int address;
    struct Node* leftchild;
    struct Node* rightsibling;
};

struct Arg{
    bool print;
    int offset;
};

void tree_init(struct Node* root);
int tree_build(struct Node* root, unsigned int address, cs_insn *insn, size_t len);
struct Node *tree_search(struct Node* root, char* gadget_string);
void tree_free(struct Node* root);

#endif
