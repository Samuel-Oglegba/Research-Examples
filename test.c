#include <stdio.h>
/* Types of sockets.  */
enum __socket_type
{
  SOCK_STREAM = 1,		/* Sequenced, reliable, connection-based
				   byte streams.  */
#define SOCK_STREAM SOCK_STREAM
  SOCK_DGRAM = 2,		/* Connectionless, unreliable datagrams
				   of fixed maximum length.  */
#define SOCK_DGRAM SOCK_DGRAM
  SOCK_RAW = 3,			/* Raw protocol interface.  */
#define SOCK_RAW SOCK_RAW
  SOCK_RDM = 4,			/* Reliably-delivered messages.  */
#define SOCK_RDM SOCK_RDM
  SOCK_SEQPACKET = 5,		/* Sequenced, reliable, connection-based,
				   datagrams of fixed maximum length.  */
#define SOCK_SEQPACKET SOCK_SEQPACKET
  SOCK_DCCP = 6,		/* Datagram Congestion Control Protocol.  */
#define SOCK_DCCP SOCK_DCCP
  SOCK_PACKET = 10,		/* Linux specific way of getting packets
				   at the dev level.  For writing rarp and
				   other similar things on the user level. */
#define SOCK_PACKET SOCK_PACKET

  /* Flags to be ORed into the type parameter of socket and socketpair and
     used for the flags parameter of paccept.  */

  SOCK_CLOEXEC = 02000000,	/* Atomically set close-on-exec flag for the
				   new descriptor(s).  */
#define SOCK_CLOEXEC SOCK_CLOEXEC
  SOCK_NONBLOCK = 00004000	/* Atomically mark descriptor(s) as
				   non-blocking.  */
#define SOCK_NONBLOCK SOCK_NONBLOCK
};

#define SOCK_TYPE_MASK 0xf
#define O_NONBLOCK	00004000

int main(int argc, char *argv[]) {

int type = SOCK_RAW;
int flags;

printf("***type:: %d\n",type);
printf("===type:: %x\n",type);
printf("===SOCK_TYPE_MASK:: %d\n",~SOCK_TYPE_MASK);
      
      flags = type & ~SOCK_TYPE_MASK;
	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		printf("flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK):: %d\n",flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK));
	type &= SOCK_TYPE_MASK;

printf("***flags:: %d\n",flags);
printf("===flags:: %x\n",flags);
	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;


printf("type:: %d\n",type);
printf("flags & SOCK_NONBLOCK:: %d\n",flags & SOCK_NONBLOCK);
printf("flags:: %d\n",flags);
printf("flags:: %x\n",flags);
printf("flags:: %X\n",flags);
printf("~SOCK_TYPE_MASK:: %x\n",~SOCK_TYPE_MASK);
printf("SOCK_TYPE_MASK:: %d\n",SOCK_TYPE_MASK);

}