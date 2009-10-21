/*
 * grouter.h (GINI router header file)
 * AUTHOR: originally written by - Weiling Xu
 * REVISED BY: Muthucumaru Maheswaran
 * REVISED ON: December 19, 2004
 *
 */


/*
 * A simplified packet flow inside the GINI router.
 *
 */

#ifndef __GROUTER_H__
#define __GROUTER_H__


/*
 * standard includes, if any should go here!
 * keep this to a minimum!
 */
#include <limits.h>
#include <sys/time.h>
#include <pthread.h>

/*
 * global definitions.... this is stuff that could not be
 * put into specialized header files....
 */
#define MAX_NAME_LEN                256
#define MAX_DNAME_LEN		    	32
#define MAX_TYPES_PER_MODULE        8
#define MAX_TMPBUF_LEN              256
#define MAX_FRAGMENTS               16

#define BIG_PACKET_LEN              2500

#define MAX_QUEUE_SIZE              256
#define MAX_QUEUE_NUM				32

#define MAX_PORT_TRIES              20

#define LARGE_REAL_NUMBER           99.0E7
#define SMALL_REAL_NUMBER           0.99E-6
#define INFINITE_Q_SIZE             99999999

#ifndef TRUE
# define TRUE                        1
#endif

#ifndef FALSE
# define FALSE                       0
#endif

#define MAX_DOUBLE 		    		(double)LONG_MAX
#define MSG_TYPE_MAX     	    	20                  // max number of message types accepted by a module??
#define DEFAULT_MTU	            	1500		// max MTU size for the router's interfaces

#define max(A,B)                    ( (A) > (B) ? (A):(B))
#define min(A,B)                    ( (A) < (B) ? (A):(B))
#define IS_ODD(A)                   ( (A % 2) != 0 )
#define IS_EVEN(A)                  ( (A % 2) == 0 )

#define COPY_MAC(DST, SRC)          ( memcpy(DST, SRC, 6) )
#define COPY_IP(DST, SRC)           ( memcpy(DST, SRC, 4) )
#define COMPARE_MAC(X, Y)           ( memcmp(X, Y, 6) )
#define COMPARE_IP(X, Y)            ( memcmp(X, Y, 4) )
#define MAC_BCAST_ADDR              {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
#define IP_BCAST_ADDR               {0xFF, 0xFF, 0xFF, 0xFF}

// check IP RFC specifications

#define NORMAL_LISTING              11
#define VERBOSE_LISTING             12
#define BRIEF_LISTING               13

typedef unsigned char bool;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int  uint;

extern char *version;

typedef struct _router_config
{
	char *router_name;
	char *gini_home;
	int cli_flag;
	char *config_file;
	char *config_dir;
	pthread_t ghandler;
	pthread_t clihandler;
	pthread_t scheduler;
	pthread_t worker;
	int schedcycle;
	char schedpolicy[MAX_NAME_LEN];
} router_config;


// function prototypes for code in utils.c..
int compareIPUsingMask(uchar *ip_addr, uchar *network, uchar *netmask);
char *IP2Dot(char *buf, uchar ip_addr[]);
char *ID2ModuleName(char *buf, int modid);
int Dot2IP(char *buf, uchar ip_addr[]);
int Colon2MAC(char *buf, uchar mac_addr[]);
char *MAC2Colon(char *buf, uchar mac_addr[]);
double subTimeVal(struct timeval *v2, struct timeval *v1);
void printTimeVal(struct timeval *v);
char *getCurrentTimeVal();
int gAtoi(char *str);

unsigned char *gHtonl(uchar tval[], uchar val[]);
unsigned char *gNtohl(uchar tval[], uchar val[]);
ushort checksum(uchar *buf, int iwords);


// function prototypes for code in router.c
void redefineSignalHandler(int sigid, void (*my_func)());
void wait4thread(pthread_t threadid);
#endif
