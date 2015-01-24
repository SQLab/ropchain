#include "rop.h"

void usage(void)
{
    printf("Usage:\n");
    printf(" ropchain <file> [-p <bool>] [-o <offset>] [-b <badbyte>] [-l <length>]\n");
    printf(" -p\tPrint all gadgets.\n");
    printf(" -o\tAdd padding(offset) bytes to payload.\n");
    printf(" -b\tBypass badbyte gadgets. ex: \"00|20|0a\"\n");
    printf(" -l\tMaximum gadgets length\"\n");
    exit (-1);
}

int parse_arg(int argc, char** argv, struct Arg *arg);

int main(int argc, char** argv)
{
    FILE *fp;
    unsigned char *binary;
    unsigned long binary_len;
    unsigned char *chain;
    int chain_len = 0;
    int i;
    struct Arg *arg;

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

    //Arg init
    arg = (struct Arg *)malloc(sizeof(struct Arg));
    if(!arg)
    {
        fprintf(stderr ,"malloc failed.\n");
        return -1;
    }
    parse_arg(argc, argv, arg);

    chain_len = rop_chain(&chain, binary, binary_len, arg);
    if(chain_len > 0)
    {
        printf("\n--- Result ---\n");
        for(i = 0; i < arg->offset; i++)
            printf("\\x41");
        for(i = 0; i < chain_len; i++)
            printf("\\x%02x",chain[i]);
        printf("\n");
    }
    free(binary);
    fclose(fp);
    return 0;
}

int parse_arg(int argc, char** argv, struct Arg *arg)
{
    char *endptr;
    char *pch;
    arg->print = 1;
    arg->depth = 2;
    arg->offset = 0;
    arg->badbyte_no = 0;
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
                        arg->print = 0;
                    }
                    break;
                case 'o':
                    arg->offset = strtol(argv[2], &endptr, 10);
                    break;
                case 'l':
                    arg->depth = strtol(argv[2], &endptr, 10);
                    break;
                case 'b':
                    pch = strtok(argv[2], "|");
                    while(pch != NULL)
                    {
                        arg->badbyte[arg->badbyte_no] = (unsigned char)strtol(pch, NULL, 16);
                        arg->badbyte_no++;
                        pch = strtok(NULL, "|");
                    }
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
}
