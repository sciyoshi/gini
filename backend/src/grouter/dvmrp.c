/**
 * COMP535 - Programming Assignment 2
 * IP Multicasting
 * Samuel Cormier-Iijima (260174995), Michael Spivack (260224370)
 *
 * This file implements a simple DVMRP-like protocol to build and maintain
 * a source-based distribution tree. Since GINI does not support dynamic
 * topology changes, we decided not to implement the dynamic routing algorithm
 * that DVMRP and RIP provide. Thus, instead of maintaining its own routing
 * table that includes a metric, this protocol simply uses the static routing
 * information provided by the GINI route table.
 *
 * Because of this limitation, some of the information needed by Reverse Path
 * Multicasting (RPM) is not available. Specifically, the router cannot
 * determine which of the virtual networks it is connected to are children
 * (usually found by Reverse Path Broadcasting, or RPB) and which are leaves
 * (found using Truncated Reverse Path Broadcasting, or TRPB). Instead, we
 * extend the pruning protocol to include a message saying that the neighbor
 * router does not want to receive ANY messages from the given source,
 * regardless of the multicast group. This takes the place of determining leaves
 * in DVMRP, and is suited for GINI since the topology doesn't change (so there
 * is no expiration either) and since routers can only be connected either to
 * a single other router or a LAN of hosts (GINI doesn't support multiple
 * routers connected to a switch).
 *
 * Also, since GINI does not provide a way to know whether an interface is
 * connected to another router or to a LAN of hosts, we decided to send packets
 * to the multicast all router address to ping for other routers. If no reply
 * is received, we assume that the memberships for that link can be managed
 * by IGMP.
 *
 * See [1] and [2] a more in-depth discussion of this subject.
 *
 * [1] RFC 1075, "Distance Vector Multicast Routing Protocol".
 * [2] Deering, S., "Multicast Routing in Internetworks and Extended LANs",
 *     SIGCOMM Summer 1988 Proceedings, August 1988.
 */

#include "multicast.h"
#include "dvmrp.h"
#include "gnet.h"
#include "message.h"

gboolean
gini_dvmrp_ping (int *count)
{
	int i;

	for (i = 0; i < MAX_INTERFACES; i++) {
		GiniInterface *iface = gini_iface_get (i);

		if (!iface) {
			continue;
		} else {
			GiniPacket *packet = gini_packet_new ();
			GiniIpHeader *ip = packet->ip;
			GiniIgmpHeader *igmp = packet->igmp;

			ip->ip_ttl = 1;
			ip->ip_prot = GINI_IGMP_PROTOCOL;

			/* should be handled by IP layer */
			ip->ip_pkt_len = g_htons (sizeof (GiniIgmpHeader) + ip->ip_hdr_len * 4);

			*(guint32 *) ip->ip_dst = *(guint32 *) GINI_MCAST_ALL_ROUTERS;
			*(guint32 *) ip->ip_src = g_htonl (*(guint32 *) iface->ip_addr);

			ip->ip_cksum = 0;
			ip->ip_cksum = g_htons (gini_checksum (ip, ip->ip_hdr_len * 2));

			gini_mcast_ip_to_mac (packet->data.header.dst, (guchar *) GINI_MCAST_ALL_ROUTERS);

			packet->frame.dst_interface = i;
			packet->frame.arp_bcast = TRUE;

			igmp->version = GINI_IGMP_VERSION;
			igmp->type = GINI_IGMP_MESSAGE_TYPE_DVMRP;
			igmp->subtype = GINI_DVMRP_MESSAGE_TYPE_REQUEST;
			memset (&igmp->group_address, 0, sizeof (igmp->group_address));
			igmp->checksum = 0;
			igmp->checksum = g_htons (gini_checksum (igmp, sizeof (GiniIgmpHeader) / 2));

			gini_ip_send (packet);
		}
	}

	if (*count++ == GINI_DVMRP_PINGS) {
		g_free (count);
		return FALSE;
	}

	return TRUE;
}

void
gini_dvmrp_init (void)
{
	g_timeout_add_seconds (10, (GSourceFunc) gini_dvmrp_ping, g_malloc0 (sizeof (int)));
}

gboolean
gini_dvmrp_process (GiniPacket *packet)
{
	if (packet->igmp->subtype == GINI_DVMRP_MESSAGE_TYPE_REQUEST) {
		packet->igmp->subtype = GINI_DVMRP_MESSAGE_TYPE_RESPONSE;

		packet->igmp->checksum = 0;
		packet->igmp->checksum = g_htons (gini_checksum ((char *) packet->igmp, sizeof (GiniIgmpHeader) / 2));

		*(guint32 *) packet->ip->ip_src = g_htonl (*(guint32 *) packet->frame.src_ip_addr);
		packet->ip->ip_ttl = 1;
		packet->ip->ip_cksum = 0;
		packet->ip->ip_cksum = g_htons (gini_checksum ((char *) packet->ip, packet->ip->ip_hdr_len * 2));

		packet->frame.dst_interface = packet->frame.src_interface;
		packet->frame.arp_bcast = TRUE;

		gini_ip_send (packet);

		return TRUE;
	} else if (packet->igmp->subtype == GINI_DVMRP_MESSAGE_TYPE_RESPONSE) {
		
	} else {
		g_debug ("silently dropping unknown DVMRP message type %d", packet->igmp->subtype);
	}

	return FALSE;
}

