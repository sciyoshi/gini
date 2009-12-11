
/*
 * mtu.h (header file for MTU)
 * AUTHOR: Originally written by Weiling Xu
 *         Revised by Muthucumaru Maheswaran
 * DATE: December 24, 2004
 */

#ifndef _MTU_H_
#define _MTU_H_

#include "grouter.h"


#define MAX_MTU                         20  // maximum mtu table size, better to be equal to CONN_MAX
#define DEFAULT_MTU                     1500    // default value of MTU

#define FRAGS_NONE                      1
#define FRAGS_ERROR                     2
#define MORE_FRAGS                      3
#define GENERAL_ERROR                   4


/*
 * MTU table entry
 */
typedef struct _mtu_entry_t 
{
	bool is_empty;                     // indicate entry used or not
	int mtu;                           // mtu value
	uchar ip_addr[4];
} mtu_entry_t;

void MTUTableInit();
int findInterfaceIP(int index, 
		    uchar *ip_addr);
void deleteMTUEntry(int index);
void addMTUEntry(int index, 
		 int mtu, uchar *ip_addr);
int findMTU(int index);
int findAllInterfaceIPs(uchar buf[][4]);
#endif //_MTU_H_
