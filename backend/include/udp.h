#ifndef __UDP_H__
#define __UDP_H__

#include <glib.h>

typedef struct _GiniUdpHeader GiniUdpHeader;

#include "grouter.h"
#include "message.h"
#include "ip.h"
#include "icmp.h"
#include "protocols.h"

struct _GiniUdpHeader {
	guint16 src_port;
	guint16 dst_port;
	guint16 length;
	guint16 checksum;
};

void  gini_udp_send    (GiniSocketAddress *dst,
                        guint16            src_port,
                        gchar             *data,
                        gsize              length);

gsize gini_udp_recv    (GiniSocketAddress *dst,
                        guint16            src_port,
                        gchar             *data,
                        gsize              length);

void  gini_udp_process (GiniPacket *packet);

void  gini_udp_init    (void);

void  grtr_cli_udp     (gchar *cmd);

#endif

