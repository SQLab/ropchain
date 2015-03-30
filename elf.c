#include "elf.h"

struct Segment* elf_parse(unsigned char *binary)
{
    struct Segment *text;
    unsigned int text_offset;
    if(elf_valid(binary) == -1)
    {
        return 0;
    }
    text_offset = elf_get_load_offset(binary);
    text = (struct Segment*)&binary[text_offset];
    return text;
}

int elf_valid(unsigned char *binary)
{
    if(strncmp((char*)binary, "\177ELF", 4))
    {
        printf("It's not a ELF file.\n");
        return -1;
    }
    /* format */
    if(binary[4] == '\x01')
    {
        //printf("ELF32\n");
    }
    else if(binary[4] == '\x02')
    {
        //printf("ELF64\n");
        return -1;
    }
    return 0;
}

unsigned int elf_get_load_offset(unsigned char *binary)
{
    unsigned int i;
    struct Segment *seg;
    int text_offset = 0;
    int header_size = (int)binary[44];
    printf("Program Headers:\n");
    printf("Type\t\tOffset\t\tVirtAddr\tPhysAddr\tFileSiz\t\tMemSiz\t\tFlag\t\tAlign\n");
    for(i = 0; i < header_size; i++)
    {
        seg = (struct Segment*)&binary[52 + i * 32];
        switch(seg->type)
        {
            case 1:
                printf("PT_LOAD\t\t");
                if(text_offset == 0)
                {
                    text_offset = 52 + i * 32;
                }
                break;
            case 2:
                printf("PT_DYNAMIC\t");
                break;
            case 3:
                printf("PT_INTERP\t");
                break;
            case 4:
                printf("PT_NOTE\t\t");
                break;
            case 5:
                printf("PT_SHLIB\t");
                break;
            case 6:
                printf("PT_PHDR\t\t");
                break;
            case 7:
                printf("PT_TLS\t\t");
                break;
            case 8:
                printf("PT_NUM\t\t");
                break;
            case 0x60000000:
                printf("PT_LOOS\t\t");
                break;
            case 0x6474e550:
                printf("PT_EH_FRAME\t");
                break;
            case 0x6474e551:
                printf("PT_STACK\t");
                break;
            case 0x6474e552:
                printf("PT_RELRO\t");
                break;
            default:
                printf("PT_OTHER\t");
        }
        printf("0x%08x\t0x%08x\t0x%08x\t0x%08x\t0x%08x\t0x%08x\t0x%08x\n", seg->offset, seg->vaddr, seg->paddr, seg->filesz, seg->memsz, seg->flags, seg->align);
    }
    printf("\n");
    return text_offset;
}
