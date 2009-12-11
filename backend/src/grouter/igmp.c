#include "igmp.h"
#include "dvmrp.h"
#include "multicast.h"
#include "gnet.h"

static gboolean
gini_igmp_query (int *count)
{
	GiniInterface *iface = NULL;

	//g_debug ("sending IGMP query on all interfaces...");

	while ((iface = gini_iface_next (iface))) {
		GiniPacket *packet = gini_packet_new ();
		GiniIpHeader *ip = packet->ip;
		GiniIgmpHeader *igmp = packet->igmp;

		igmp->version = GINI_IGMP_VERSION;
		igmp->type = GINI_IGMP_MESSAGE_TYPE_QUERY;
		igmp->checksum = g_htons (gini_checksum ((char *) igmp, sizeof (GiniIgmpHeader) / 2));

		ip->ip_ttl = 1;
		ip->ip_prot = GINI_IGMP_PROTOCOL;

		/* should be handled by IP layer */
		ip->ip_pkt_len = g_htons (sizeof (GiniIgmpHeader) + ip->ip_hdr_len * 4);

		*(guint32 *) ip->ip_dst = *(guint32 *) GINI_MCAST_ALL_HOSTS;
		*(guint32 *) ip->ip_src = g_htonl (*(guint32 *) iface->ip_addr);

		ip->ip_cksum = g_htons (gini_checksum ((char *) ip, ip->ip_hdr_len * 2));

		gini_mcast_ip_to_mac (packet->data.header.dst, (guchar *) GINI_MCAST_ALL_HOSTS);

		packet->frame.dst_interface = iface->id;
		packet->frame.arp_bcast = TRUE;

		gini_ip_send (packet);
	}

	if (count && --(*count) <= 0) {
		g_free (count);
		return FALSE;
	}

	return TRUE;
}

void
gini_igmp_init (void)
{
	int *count = g_new0 (int, 1);

	*count = GINI_IGMP_QUERY_STARTUP_COUNT;

	// RFC 1075, 5.4: on router startup, multicast a number of requests
	g_timeout_add_seconds (GINI_IGMP_QUERY_STARTUP_RATE, (GSourceFunc) gini_igmp_query, count);

	g_timeout_add_seconds (GINI_IGMP_QUERY_RATE, (GSourceFunc) gini_igmp_query, NULL);
}

gboolean
gini_igmp_process (GiniPacket *packet)
{
	GiniIpHeader *ip = packet->ip;
	GiniIgmpHeader *igmp = packet->igmp;

	if (gini_checksum ((char *) igmp, sizeof (GiniIgmpHeader) / 2) != 0) {
		g_debug ("dropping IGMP packet with invalid checksum: 0x%.4X", gini_checksum ((char *) igmp, sizeof (GiniIgmpHeader) / 2));
		return FALSE;
	}

	if (igmp->type == GINI_IGMP_MESSAGE_TYPE_QUERY) {
		if (g_ntohl (*(gint32 *) packet->ip->ip_src) < *(gint32 *) packet->frame.src_ip_addr) {
			// according to RFC 1075, 5.4 we should stop sending queries on this interface
		}
	} else if (igmp->type == GINI_IGMP_MESSAGE_TYPE_REPORT) {
		GiniInterface *iface = gini_iface_get (packet->frame.src_interface);

		if (!iface) {
			g_warning ("packet received on invalid interface!?");
			return FALSE;
		}

		// RFC 1112, Appendix I, page 12
		if (*(guint32 *) ip->ip_dst != igmp->group_address) {
			g_debug ("mismatch in IP destination field and host group address");
			return FALSE;
		}

		gini_mcast_membership_add (iface, g_ntohl (igmp->group_address));
	} else if (igmp->type == GINI_IGMP_MESSAGE_TYPE_DVMRP) {
		return gini_dvmrp_process (packet);
	} else {
		g_debug ("silently dropping unknown IGMP message type");
	}

	return FALSE;
}

