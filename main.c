#include "rop.h"

int main(int argc, char** argv)
{
    FILE *fp;
    unsigned char *binary;
    unsigned char *chain;
    unsigned long binary_len;
    int i;
    int result = 0;
    int chain_len = 0;

    if(argc < 2)
    {
        fprintf(stderr ,"./ropchain <Binary File>\n");
        return -1;
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
    result = fread(binary, binary_len, 1, fp);
    if(result > 0)
    {
        chain_len = rop_chain(binary, binary_len, &chain);
        if(chain_len > 0)
        {
            printf("\n--- Result ---\n");
            for(i = 0; i < chain_len; i++)
                printf("\\x%02x",chain[i]);
            printf("\n");
        }
        free(binary);
        fclose(fp);
    }
    return 0;
}
