#ifndef __UDP_H__
#define __UDP_H__

#include <glib.h>

#include "grouter.h"
#include "message.h"
#include "ip.h"
#include "icmp.h"
#include "protocols.h"

#define GINI_UDP_PROTOCOL UDP_PROTOCOL
#define GINI_ICMP_PROTOCOL ICMP_PROTOCOL

#define GINI_IP_HEADER_SIZE(ip) ((ip)->ip_hdr_len * 4)

#define gini_ip_prepare IPPreparePacket
#define gini_ip_outgoing IPOutgoingPacket
#define gini_ip_send IPSend2Output
#define gini_aton Dot2IP
#define gini_checksum checksum

typedef gpacket_t GiniPacket;
typedef ip_packet_t GiniIpHeader;
typedef icmphdr_t GiniIcmpHeader;

typedef struct {
	guint32 address;
} GiniInetAddress;

typedef struct {
	guint16         port;
	GiniInetAddress address;
} GiniSocketAddress;

typedef struct {
	guint16 src_port;
	guint16 dst_port;
	guint16 length;
	guint16 checksum;
} GiniUdpHeader;

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

