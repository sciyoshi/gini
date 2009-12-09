#ifndef __IGMP_H__
#define __IGMP_H__

#include <glib.h>

#include "grouter.h"
#include "ip.h"
#include "protocols.h"

#define GINI_IGMP_ALL_HOSTS_GROUP "\xE0\x00\x00\x01"

#define GINI_IGMP_VERSION 1

typedef enum {
	GINI_IGMP_MESSAGE_TYPE_QUERY = 1,
	GINI_IGMP_MESSAGE_TYPE_REPORT = 2,
} GiniIgmpMessageType;

typedef struct {
	guint8 type : 4;
	guint8 version : 4;
	guint8 _unused;
	guint16 checksum;
	guint32 group_address;
} GiniIgmpHeader;

void grtr_igmp_init (void);

void grtr_igmp_process (GiniPacket *packet);

#endif
