#include "rop.h"

void usage(void)
{
    printf("Usage:\n");
    printf(" ropchain <file> [-p <bool>] [-o <offset>]\n");
    printf(" -p\tPrint all gadgets\n");
    printf(" -o\tAdd padding(offset) bytes\n");
    exit (-1);
}

int main(int argc, char** argv)
{
    FILE *fp;
    unsigned char *binary;
    unsigned long binary_len;
    unsigned char *chain;
    int chain_len = 0;
    int i;
    int offset = 0;
    char *endptr;
    bool arg_print = 1;

    if(argc < 2)
    {
        usage();
    }
    fp = fopen(argv[1], "rb");

    if(!fp)
    {
        fprintf(stderr ,"Fail to open file.\n");
        return -1;
    }

    //Get file length
    fseek(fp, 0, SEEK_END);
    binary_len=ftell(fp);
    fseek(fp, 0, SEEK_SET);

    //Allocate memory
    binary = (unsigned char *)malloc(binary_len+1);
    if(!binary)
    {
        fprintf(stderr ,"malloc failed.\n");
        return -1;
    }
    if(fread(binary, binary_len, 1, fp) == 0)
    {
        return -1;
    }
    argv++;
    argc--;

    //Parse command
    while ((argc > 1) && (argv[1][0] == '-'))
    {
        if(argv[2])
        {
            switch (argv[1][1])
            {
                case 'p':
                    if(!strcmp(argv[2], "false") || !strcmp(argv[2], "0"))
                    {
                        arg_print = 0;
                    }
                    break;
                case 'o':
                    offset = strtol(argv[2], &endptr, 10);
                    break;
                default:
                    usage();
            }
            argv += 2;
            argc -= 2;
        }
        else
        {
            fprintf(stderr, "Parser args failed.[%s]\n", argv[1]);
            return -1;
        }
    }
    chain_len = rop_chain(&chain, binary, binary_len, arg_print);
    if(chain_len > 0)
    {
        printf("\n--- Result ---\n");
        for(i = 0; i < offset; i++)
            printf("\\x41");
        for(i = 0; i < chain_len; i++)
            printf("\\x%02x",chain[i]);
        printf("\n");
    }
    free(binary);
    fclose(fp);
    return 0;
}
