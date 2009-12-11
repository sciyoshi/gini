/*
 * routetable.h (header file for Route table data structures
 * AUTHOR: Originally written by Weiling Xu
 *         Revised by Muthucumaru Maheswaran
 * DATE: July 11, 2005
 *
 */

#ifndef __ROUTE_TABLE_H__
#define __ROUTE_TABLE_H__


/*
 * Private definitions: only used within the IP module
 */

#include "grouter.h"

#define MAX_ROUTES                      20	// maximum route table size

#define GINI_ROUTE_MAX MAX_ROUTES

#define gini_route_table route_tbl

/*
 * route table entry
 */
typedef struct _route_entry_t 
{
	bool is_empty;			        // indicates whether entry is used or not
	uchar network[4];			// Network IP address
	uchar netmask[4];			// Netmask
	uchar nexthop[4];			// Nexthop IP address
	int  interface;			        // output interface
} route_entry_t, GiniRoute;

extern route_entry_t route_tbl[MAX_ROUTES];

#define gini_route_table_find(ip, nexthop, iface) (findRouteEntry (route_tbl, ip, nexthop, iface) == EXIT_SUCCESS)

// prototypes of the functions provided for the route table handling..

void RouteTableInit(route_entry_t route_tbl[]);
void addRouteEntry(route_entry_t route_tbl[], uchar* nwork, uchar* nmask, uchar* nhop, int interface);
void deleteRouteEntryByIndex(route_entry_t route_tbl[], int i);
void printRouteTable(route_entry_t route_tbl[]);
void deleteRouteEntryByInterface(route_entry_t route_tbl[], int interface);
int findRouteEntry(route_entry_t route_tbl[], uchar *ip_addr, uchar *nhop, int *ixface);
#endif
