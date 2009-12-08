#ifndef __UDP_H__
#define __UDP_H__

#include <glib.h>

#include "grouter.h"
#include "message.h"
#include "ip.h"
#include "icmp.h"
#include "protocols.h"

void  grtr_udp_send    (GiniSocketAddress *dst,
                        guint16            src_port,
                        gchar             *data,
                        gsize              length);

gsize grtr_udp_recv    (GiniSocketAddress *dst,
                        guint16            src_port,
                        gchar             *data,
                        gsize              length);

void  grtr_udp_process (GiniPacket *packet);

void  grtr_udp_init    (void);

void  grtr_cli_udp     (gchar *cmd);

#endif

