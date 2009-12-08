#ifndef __MULTICAST_H__
#define __MULTICAST_H__

#include <glib.h>

#include "grouter.h"
#include "ip.h"
#include "ip.h"
#include "gnet.h"

/**
 * The number of seconds until a membership is considered inactive and removed
 */
#define GRTR_MCAST_MEMBERSHIP_EXPIRATION_TIME 30

void grtr_mcast_incoming (GiniPacket *packet);

void grtr_mcast_membership_add (GiniInterface   *interface,
                                GiniInetAddress  group_address);

#endif

