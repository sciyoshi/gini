#ifndef __DVMRP_H__
#define __DVMRP_H__

#include <glib.h>

#include "message.h"

#define GINI_DVMRP_FULL_UPDATE_RATE 60
#define GINI_DVMRP_TRIGGERED_UPDATE_RATE 5
#define GINI_DVMRP_STARTUP_COUNT 3

typedef enum {
	GINI_DVMRP_MESSAGE_TYPE_REQUEST = 1,
	GINI_DVMRP_MESSAGE_TYPE_RESPONSE = 2,
	GINI_DVMRP_MESSAGE_TYPE_NMR = 3,

	// non-standard DVMRP message for the purposes of detecting leaves
	GINI_DVMRP_MESSAGE_TYPE_LEAF = 50
} GiniDvmrpMessageType;

void     gini_dvmrp_init (void);

gboolean gini_dvmrp_process (GiniPacket *packet);

gboolean gini_dvmrp_forward (GiniPacket *packet);

#endif

