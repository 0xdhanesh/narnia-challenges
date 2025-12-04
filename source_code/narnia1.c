#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(){
    int (*ret)();

    if(getenv("EGG")==NULL){
        printf("Give me something to execute at the env-variable EGG\n");
        exit(1);
    }

    printf("Trying to execute EGG!\n");
    ret = (int(*)())getenv("EGG");  // Cast char* to function pointer
    ret();

    return 0;
}

/*

// ORIGINAL CODE

#include <stdio.h>
#include <stdlib.h> // added_manually

int main(){
    int (*ret)();

    if(getenv("EGG")==NULL){
        printf("Give me something to execute at the env-variable EGG\n");
        exit(1);
    }

    printf("Trying to execute EGG!\n");
    ret = getenv("EGG");
    ret();

    return 0;
}
*/
