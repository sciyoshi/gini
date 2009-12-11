#ifndef __IGMP_H__
#define __IGMP_H__

#include <glib.h>

typedef struct _GiniIgmpHeader GiniIgmpHeader;

#include "grouter.h"
#include "message.h"
#include "ip.h"
#include "protocols.h"

#define GINI_IGMP_VERSION 1

#define GINI_IGMP_QUERY_STARTUP_RATE 4
#define GINI_IGMP_QUERY_STARTUP_COUNT 3
#define GINI_IGMP_QUERY_RATE 60

typedef enum {
	GINI_IGMP_MESSAGE_TYPE_QUERY = 1,
	GINI_IGMP_MESSAGE_TYPE_REPORT = 2,
	GINI_IGMP_MESSAGE_TYPE_DVMRP = 3
} GiniIgmpMessageType;

struct _GiniIgmpHeader {
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
	guint8 type : 4;
	guint8 version : 4;
#else
	guint8 version : 4;
	guint8 type : 4;
#endif
	union {
		guint8 subtype;
		guint8 _unused;
	};
	guint16 checksum;
	guint32 group_address;
};

void     gini_igmp_init (void);

gboolean gini_igmp_process (GiniPacket *packet);

#endif

