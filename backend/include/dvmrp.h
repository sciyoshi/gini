#ifndef __DVMRP_H__
#define __DVMRP_H__

#include <glib.h>

#include "message.h"

#define GINI_DVMRP_PINGS 20

typedef enum {
	GINI_DVMRP_MESSAGE_TYPE_REQUEST = 1,
	GINI_DVMRP_MESSAGE_TYPE_RESPONSE = 2,
	GINI_DVMRP_MESSAGE_TYPE_NMR = 3
} GiniDvmrpMessageType;

void     gini_dvmrp_init (void);

gboolean gini_dvmrp_process (GiniPacket *packet);

#endif

