#include "rop.h"

int main(void)
{
    FILE *fp;
    char file_name[20];
    unsigned char *binary;
    unsigned long binary_len;

    printf("Enter binary file name: ");
    scanf("%s",file_name);
    fp = fopen(file_name, "rb");

    //Get file length
    fseek(fp, 0, SEEK_END);
    binary_len=ftell(fp);
    fseek(fp, 0, SEEK_SET);

    //Allocate memory
    binary = (unsigned char *)malloc(binary_len+1);
    if(fp){
        fread(binary,binary_len,1,fp);
    }   
    fclose(fp);

    rop_findgadgets(binary, binary_len);
    free(binary);
    return 0;
}
