/**
 * COMP535 - Programming Assignment 2, IP Multicasting
 * Samuel Cormier-Iijima (260174995), Michael Spivack (260224370)
 * multicast.h: multicast group membership and expiration
 */

#ifndef __MULTICAST_H__
#define __MULTICAST_H__

#include <glib.h>

#include "grouter.h"
#include "message.h"
#include "ip.h"
#include "gnet.h"

/**
 * The number of seconds until a membership is considered inactive and removed
 */
#define GINI_MCAST_MEMBERSHIP_EXPIRATION_TIME 90

#define GINI_MCAST_ALL_HOSTS   "\xE0\x00\x00\x01"
#define GINI_MCAST_ALL_ROUTERS "\xE0\x00\x00\x02"
#define GINI_MCAST_ALL_DVMRP   "\xE0\x00\x00\x04"
#define GINI_MCAST_ALL_PIM     "\xE0\x00\x00\x0D"

void     gini_mcast_ip_to_mac (guchar       mac[6],
                               const guchar ip[4]);

void     gini_mcast_init (void);

gboolean gini_mcast_process (GiniPacket *packet);

void     gini_mcast_membership_add (GiniInterface   *interface,
                                    GiniInetAddress  group_address);

void     gini_mcast_membership_remove (GiniInterface   *interface,
                                       GiniInetAddress  group_address);

gboolean gini_mcast_membership_get (GiniInterface   *interface,
                                    GiniInetAddress  group_address);

#endif

