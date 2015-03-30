#ifndef _elf_h
#define _elf_h

#include <stdio.h>
#include <string.h>

struct Segment{
    unsigned int type;
    unsigned int offset;
    unsigned int vaddr;
    unsigned int paddr;
    unsigned int filesz;
    unsigned int memsz;
    unsigned int flags;
    unsigned int align;
};


struct Segment* elf_parse(unsigned char *binary);
int elf_valid(unsigned char *binary);
unsigned int elf_get_load_offset(unsigned char *binary);

#endif
