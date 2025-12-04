#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char * argv[]){
    char buf[128]; /*Declares the buffer length to be 128 bytes*/

    if(argc == 1){
        printf("Usage: %s argument\n", argv[0]); /*Display usage*/
        exit(1);
    }
    strcpy(buf,argv[1]); /*Copy contents of arg 1 to buffer*/
    printf("%s", buf); /*Print the buffer*/

    return 0;
}
