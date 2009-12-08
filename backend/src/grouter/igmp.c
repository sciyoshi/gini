#include "igmp.h"
#include "gnet.h"

static gboolean
grtr_igmp_query (gpointer data)
{
	int i;

	g_debug ("sending IGMP query on all interfaces...");

	for (i = 0; i < MAX_INTERFACES; i++) {
		GiniInterface *iface = grtr_iface_get (i);

		if (!iface) {
			continue;
		} else {
			GiniPacket *packet = g_malloc0 (sizeof (GiniPacket));
			GiniIpHeader *ip = GINI_IP_HEADER (packet);
			GiniIgmpHeader *igmp = (GiniIgmpHeader *) (ip + 1);

			ip->ip_version = 4;
			ip->ip_hdr_len = 5;
			ip->ip_tos = 0;
			ip->ip_identifier = IP_OFFMASK & random ();
			RESET_DF_BITS (ip->ip_frag_off);
			RESET_MF_BITS (ip->ip_frag_off);
			ip->ip_frag_off = 0;

			ip->ip_ttl = 1;
			ip->ip_cksum = 0;
			ip->ip_prot = GINI_IGMP_PROTOCOL;
			ip->ip_pkt_len = g_htons (sizeof (GiniIgmpHeader) + ip->ip_hdr_len * 4);

			*(guint32 *) ip->ip_dst = *(guint32 *) GINI_IGMP_ALL_HOSTS_GROUP;
			*(guint32 *) ip->ip_src = g_htonl (*(guint32 *) iface->ip_addr);

			ip->ip_cksum = 0;
			ip->ip_cksum = g_htons (gini_checksum ((char *) ip, ip->ip_hdr_len * 2));

			memset (packet->data.header.dst, 0, sizeof (packet->data.header.dst));
			packet->data.header.dst[0] = 0x10;
			packet->data.header.dst[2] = 0x5E;
			*(guint32 *) (packet->data.header.dst + 2) |= 0x7FFFFF & *(guint32 *) GINI_IGMP_ALL_HOSTS_GROUP;

			packet->data.header.prot = g_htons (GINI_IP_PROTOCOL);
			packet->frame.dst_interface = i;
			packet->frame.arp_valid = TRUE;

			igmp->version = GINI_IGMP_VERSION;
			igmp->type = GINI_IGMP_MESSAGE_TYPE_QUERY;
			memset (&igmp->group_address, 0, sizeof (igmp->group_address));
			igmp->checksum = 0;
			igmp->checksum = g_htons (gini_checksum ((char *) igmp, sizeof (GiniIgmpHeader) / 2));

			gini_ip_send (packet);
		}
	}

	return TRUE;
}

void
grtr_igmp_init (void)
{
	g_timeout_add_seconds (15, grtr_igmp_query, NULL);
}

void
grtr_igmp_process (GiniPacket *packet)
{
	GiniIpHeader *ip = GINI_IP_HEADER (packet);
	GiniIgmpHeader *igmp = (GiniIgmpHeader *) ((char *) ip + ip->ip_hdr_len * 4);

	g_debug ("version: 0x%.1X", igmp->version);
	g_debug ("type: 0x%.1X", igmp->type);
	g_debug ("unused: 0x%.2X", igmp->_unused);
	g_debug ("address: 0x%.4X", igmp->group_address);

	if (gini_checksum ((char *) igmp, sizeof (GiniIgmpHeader) / 2) != 0) {
		g_debug ("dropping IGMP packet with invalid checksum: 0x%.4X", gini_checksum ((char *) igmp, sizeof (GiniIgmpHeader) / 2));
		return;
	}

	if (igmp->type == GINI_IGMP_MESSAGE_TYPE_QUERY) {
		g_debug ("ignoring IGMP Query");
	} else if (igmp->type == GINI_IGMP_MESSAGE_TYPE_REPORT) {
		GiniInterface *iface = grtr_iface_get (packet->frame.src_interface);
		char tmp1[64], tmp2[64];

		if (!iface) {
			g_warning ("packet received on invalid interface!?");
			return;
		}

		// RFC 1112, Appendix I, page 12
		if (*(guint32 *) ip->ip_dst != igmp->group_address) {
			g_debug ("mismatch in IP destination field and host group address");
			return;
		}

		*(guint32 *) tmp2 = g_ntohl (igmp->group_address);

		g_debug ("membership report on interface %s to multicast group %s",
			gini_ntoa (tmp1, iface->ip_addr),
			gini_ntoa (tmp2, tmp2));

		grtr_mcast_membership_add (iface, igmp->group_address);
	} else {
		g_debug ("silently dropping unknown IGMP message type");
	}
}

