#include "rop.h"

int main(int argc, char** argv)
{
    FILE *fp;
    unsigned char *binary;
    unsigned long binary_len;
    int result = 0;

    if(argc < 2)
    {
        printf("./ropchain <Binary File>\n");
        return -1;
    }
    fp = fopen(argv[1], "rb");

    //Get file length
    fseek(fp, 0, SEEK_END);
    binary_len=ftell(fp);
    fseek(fp, 0, SEEK_SET);

    //Allocate memory
    binary = (unsigned char *)malloc(binary_len+1);
    if(fp)
    {
        result = fread(binary, binary_len, 1, fp);
    }
    if(result > 0)
    {
        rop_chain(binary, binary_len);
    }
    free(binary);
    fclose(fp);
    return 0;
}
