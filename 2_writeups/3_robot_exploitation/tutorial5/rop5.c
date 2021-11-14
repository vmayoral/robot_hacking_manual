#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

char *shell = "/bin/sh";
void grant() {
   system("cowsay try again");
}
void exploitable() {
   char buffer[16];
   scanf("%s", buffer);
   if(strcmp(buffer,"pwned") == 0) grant();
   else  puts("Nice try\n");
}
int main(){
   exploitable();
   return 0;
}
