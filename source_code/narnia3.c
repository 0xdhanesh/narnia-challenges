#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){

    int  ifd,  ofd;
    char ofile[16] = "/dev/null"; /*Sets the output file to /dev/null (var size is 16 bytes)*/
    char ifile[32]; /*Sets the variable size to 32 bytes*/
    char buf[32]; /*Sets the buffer size to 32 bytes*/

    if(argc != 2){ /*Print usage*/
        printf("usage, %s file, will send contents of file 2 /dev/null\n",argv[0]);
        exit(-1);
    }

    /* open files */
    strcpy(ifile, argv[1]); /*Copies arg to ifile var (this is vulnerable)*/
    if((ofd = open(ofile,O_RDWR)) < 0 ){
        printf("error opening %s\n", ofile); /*Error handler*/
        exit(-1);
    }
    if((ifd = open(ifile, O_RDONLY)) < 0 ){
        printf("error opening %s\n", ifile); /*Error handler*/
        exit(-1);
    }

    /* copy from file1 to file2 */
    read(ifd, buf, sizeof(buf)-1); /*Read content of In File*/
    write(ofd,buf, sizeof(buf)-1); /*Write content to Out File*/
    printf("copied contents of %s to a safer place... (%s)\n",ifile,ofile);

    /* close 'em */
    close(ifd); /*Close both*/
    close(ofd);

    exit(1);
}
