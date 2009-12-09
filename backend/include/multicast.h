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
#define GRTR_MCAST_MEMBERSHIP_EXPIRATION_TIME 30

void gini_mcast_incoming (GiniPacket *packet);

void gini_mcast_membership_add (GiniInterface   *interface,
                                GiniInetAddress  group_address);

void gini_mcast_membership_remove (GiniInterface   *interface,
                                   GiniInetAddress  group_address);

#endif

