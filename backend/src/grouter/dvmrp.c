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
 * in DVMRP, since implementing the full dynamic routing algorithm would be
 * too complicated for the assignment, and since GINI routers can only be
 * connected either to a single other router or a LAN of hosts (GINI doesn't
 * support multiple routers connected to a switch). This works under the
 * assumption that the network topology doesn't change on-the-fly.
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
#include "cli.h"
#include "message.h"
#include "routetable.h"

typedef struct {
	GiniInetAddress  network;
	GiniInetAddress  netmask;
	GiniInetAddress  nexthop;
	GiniInterface   *iface;

	gboolean         children[GINI_IFACE_MAX];

	GTree           *groups;
} GiniDvmrpRoute;

static gboolean gini_dvmrp_edges[GINI_IFACE_MAX] = { TRUE };

static GArray *gini_dvmrp_routes;

static inline GiniDvmrpRoute *
gini_dvmrp_route_get (int index)
{
	return &g_array_index (gini_dvmrp_routes, GiniDvmrpRoute, index);
}

GiniDvmrpRoute *
gini_dvmrp_route_find (GiniInetAddress ip)
{
	int i;

	g_debug ("route find");

	if (!gini_dvmrp_routes)
		return NULL;

	for (i = 0; i < gini_dvmrp_routes->len; i++) {
		GiniDvmrpRoute *route = gini_dvmrp_route_get (i);

		if (gini_ip_cmp_masked (&ip, &route->network, &route->netmask) == 0) {
			return route;
		}
	}

	return NULL;
}

static inline gboolean
gini_dvmrp_reverse_path_check (GiniDvmrpRoute *route,
                               GiniPacket     *packet)
{
	return route->iface->id == packet->frame.src_interface;
}

gboolean
gini_dvmrp_forward (GiniPacket *packet)
{
	GiniPacket *forward;
	GiniDvmrpRoute *route;
	GiniInterface *iface = NULL;
	GiniInetAddress src_ip, dst_ip;
	gulong *leaves;
	char tmp1[64], tmp2[64];

	src_ip = g_ntohl (*(guint32 *) packet->ip->ip_src);
	dst_ip = g_ntohl (*(guint32 *) packet->ip->ip_dst);

	g_debug ("forwarding in dvmrp: %s to %s", gini_ntoa (tmp1, (uchar *) &src_ip), gini_ntoa (tmp2, (uchar *) &src_ip));

	// find the route to the sender in the table
	if (!(route = gini_dvmrp_route_find (src_ip))) {
		return FALSE;
	}

	// reverse path check
	if (!gini_dvmrp_reverse_path_check (route, packet)) {
		return FALSE;
	}

	if (!(leaves = g_tree_lookup (route->groups, GINT_TO_POINTER (dst_ip)))) {
		g_tree_insert (route->groups, GINT_TO_POINTER (dst_ip), leaves = g_new0 (gulong, GINI_IFACE_MAX));
	}

	while ((iface = gini_iface_next (iface))) {
		if (iface->id == packet->frame.src_interface) {
			continue;
		}

		if (!gini_dvmrp_edges[iface->id]) {
			if (!route->children[iface->id] || leaves[iface->id] != 0)
				continue;
		} else if (!gini_mcast_membership_get (iface, dst_ip)) {
			continue;
		}

		// copy the packet and forward on this interface
		forward = gini_packet_copy (packet);

		forward->frame.dst_interface = iface->id;
		forward->frame.arp_bcast = TRUE;

		gini_ip_send_fragmented (forward);
	}

	// packet needs to be freed
	return FALSE;
}

gboolean
gini_dvmrp_request (int *count)
{
	GiniInterface *iface = NULL;

	while ((iface = gini_iface_next (iface))) {
		GiniPacket *packet = gini_packet_new ();
		GiniIpHeader *ip = packet->ip;
		GiniIgmpHeader *igmp = packet->igmp;

		g_debug ("sending request");

		igmp->version = GINI_IGMP_VERSION;
		igmp->type = GINI_IGMP_MESSAGE_TYPE_DVMRP;
		igmp->subtype = GINI_DVMRP_MESSAGE_TYPE_REQUEST;
		memset (&igmp->group_address, 0, sizeof (igmp->group_address));
		igmp->checksum = g_htons (gini_checksum (igmp, sizeof (GiniIgmpHeader) / 2));

		ip->ip_ttl = 1;
		ip->ip_prot = GINI_IGMP_PROTOCOL;

		/* should be handled by IP layer */
		ip->ip_pkt_len = g_htons (sizeof (GiniIgmpHeader) + ip->ip_hdr_len * 4);

		*(guint32 *) ip->ip_dst = *(guint32 *) GINI_MCAST_ALL_ROUTERS;
		*(guint32 *) ip->ip_src = g_htonl (*(guint32 *) iface->ip_addr);

		ip->ip_cksum = g_htons (gini_checksum (ip, ip->ip_hdr_len * 2));

		gini_mcast_ip_to_mac (packet->data.header.dst, (guchar *) GINI_MCAST_ALL_ROUTERS);

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
/*
static void
gini_dvmrp_route_init (void)
{
	int i;

	gini_dvmrp_routes = g_array_sized_new (FALSE, TRUE, sizeof (GiniDvmrpRoute), GINI_ROUTE_MAX);

	for (i = 0; i < GINI_ROUTE_MAX; i++) {
		GiniRoute route = gini_route_table[i];

		if (!route.is_empty) {
			GiniDvmrpRoute copy = {
				.network = *(guint32 *) route.network,
				.netmask = *(guint32 *) route.netmask,
				.nexthop = *(guint32 *) route.nexthop,
				.iface = gini_iface_get (route.interface),
				.groups = g_tree_new_full ((GCompareDataFunc) gini_ip_cmp, NULL, NULL, g_free)
			};

			g_array_append_val (gini_dvmrp_routes, copy);
		}
	}
}
*/
void
gini_dvmrp_cli (int   argc,
                char *argv[])
{
	
}

void
gini_dvmrp_init (void)
{
	int *count = g_malloc0 (sizeof (int));

	*count = GINI_DVMRP_STARTUP_COUNT;

	// send a couple of requests at startup to detect leafs
	//g_timeout_add_seconds (GINI_DVMRP_TRIGGERED_UPDATE_RATE, (GSourceFunc) gini_dvmrp_request, count);

	//g_timeout_add_seconds (GINI_DVMRP_FULL_UPDATE_RATE, (GSourceFunc) gini_dvmrp_request, NULL);

	grtr_cli_register ("dvmrp", gini_dvmrp_cli, NULL);

	//gini_dvmrp_route_init ();
}

static gboolean
gini_dvmrp_process_request (GiniPacket *packet)
{
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
}

gboolean
gini_dvmrp_process (GiniPacket *packet)
{
	switch (packet->igmp->subtype) {
	case GINI_DVMRP_MESSAGE_TYPE_REQUEST:
		return gini_dvmrp_process_request (packet);

	case GINI_DVMRP_MESSAGE_TYPE_RESPONSE:
		gini_dvmrp_edges[packet->frame.src_interface] = FALSE;
		return FALSE;

	case GINI_DVMRP_MESSAGE_TYPE_NMR:
	case GINI_DVMRP_MESSAGE_TYPE_LEAF:
		break;

	default:
		g_debug ("silently dropping unknown DVMRP message type %d", packet->igmp->subtype);
	}

	return FALSE;
}

