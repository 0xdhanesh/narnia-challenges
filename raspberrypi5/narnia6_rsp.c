#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

// tired of fixing values...
// - morla
unsigned long getsp(void) {
    unsigned long sp;
    __asm__ volatile (
        "mov %0, sp       \n\t"  // Get stack pointer
        "and %0, %0, #0xff000000"  // Mask to 0xffXXXXXX
        : "=r" (sp)
        :
        : "cc"
    );
    return sp;
}


int main(int argc, char *argv[]){
    char b1[8], b2[8];
    int  (*fp)(char *)=(int(*)(char *))&puts, i;

    if(argc!=3){ printf("%s b1 b2\n", argv[0]); exit(-1); }

    /* clear environ */
    for(i=0; environ[i] != NULL; i++)
        memset(environ[i], '\0', strlen(environ[i]));
    /* clear argz    */
    for(i=3; argv[i] != NULL; i++)
        memset(argv[i], '\0', strlen(argv[i]));

    strcpy(b1,argv[1]);
    strcpy(b2,argv[2]);
    //if(((unsigned long)fp & 0xff000000) == 0xff000000)
    if(((unsigned long)fp & 0xff000000) == getsp())
        exit(-1);
    fp(b1);

    exit(1);
}
