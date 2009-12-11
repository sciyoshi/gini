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
 * See [1], [2], and [3] a more in-depth discussion of this subject.
 *
 * [1] RFC 1075, "Distance Vector Multicast Routing Protocol".
 * [1] Internet Draft, "DVMRP Version 3".
 * [3] Deering, S., "Multicast Routing in Internetworks and Extended LANs",
 *     SIGCOMM Summer 1988 Proceedings, August 1988.
 */

#include <glib/gstdio.h>

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

typedef struct {
	gboolean prune_sent;
	gulong   pruned[GINI_IFACE_MAX];
} GiniDvmrpRouteGroup;

static gboolean gini_dvmrp_edges[GINI_IFACE_MAX];

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

static void
gini_dvmrp_send (GiniDvmrpMessageType  type,
                 GiniInetAddress       dst_address,
                 GiniInetAddress       group_address,
                 GiniInterface        *iface)
{
	GiniPacket *packet = gini_packet_new ();
	GiniIpHeader *ip = packet->ip;
	GiniIgmpHeader *igmp = packet->igmp;

	igmp->version = GINI_IGMP_VERSION;
	igmp->type = GINI_IGMP_MESSAGE_TYPE_DVMRP;
	igmp->subtype = type;
	igmp->group_address = group_address;
	igmp->checksum = g_htons (gini_checksum (igmp, sizeof (GiniIgmpHeader) / 2));

	ip->ip_ttl = 1;
	ip->ip_prot = GINI_IGMP_PROTOCOL;

	/* should be handled by IP layer */
	ip->ip_pkt_len = g_htons (sizeof (GiniIgmpHeader) + ip->ip_hdr_len * 4);

	*(guint32 *) ip->ip_dst = dst_address;
	*(guint32 *) ip->ip_src = g_htonl (*(guint32 *) iface->ip_addr);

	ip->ip_cksum = g_htons (gini_checksum (ip, ip->ip_hdr_len * 2));

	gini_mcast_ip_to_mac (packet->data.header.dst, (guchar *) &dst_address);

	packet->frame.dst_interface = iface->id;
	packet->frame.arp_bcast = TRUE;

	gini_ip_send (packet);
}

gboolean
gini_dvmrp_forward (GiniPacket *packet)
{
	GiniPacket *forward;
	GiniDvmrpRoute *route;
	GiniInterface *iface = NULL;
	GiniInetAddress src_ip, dst_ip;
	gboolean should_prune = TRUE;
	GiniDvmrpRouteGroup *group;
	GString *message;
	gchar tmp1[64], tmp2[64];

	src_ip = g_ntohl (*(guint32 *) packet->ip->ip_src);
	dst_ip = g_ntohl (*(guint32 *) packet->ip->ip_dst);

	// find the route to the sender in the table
	if (!(route = gini_dvmrp_route_find (src_ip))) {
		g_debug ("could not find route to sender");
		return FALSE;
	}

	message = g_string_sized_new (128);

	g_string_printf (message, "packet from %s to %s on %s ->",
		gini_ntoa (tmp1, (uchar *) &src_ip),
		gini_ntoa (tmp2, (uchar *) &dst_ip),
		gini_iface_get (packet->frame.src_interface)->device_name);

	// reverse path check
	if (!gini_dvmrp_reverse_path_check (route, packet)) {
		// send a LEAF message back to the sender, we're the dominant router for
		// this multicast sender (equivalent to sending route with infinity metric)
		gini_dvmrp_send (
				GINI_DVMRP_MESSAGE_TYPE_LEAF,
				*(guint32 *) GINI_MCAST_ALL_ROUTERS,
				g_ntohl (src_ip),
				gini_iface_get (packet->frame.src_interface));
		g_string_append (message, " sending LEAF back (RPF check failed)");
		goto end;
	}

	if (!(group = g_tree_lookup (route->groups, GINT_TO_POINTER (dst_ip)))) {
		g_tree_insert (route->groups, GINT_TO_POINTER (dst_ip), group = g_new0 (GiniDvmrpRouteGroup, 1));
	}

	while ((iface = gini_iface_next (iface))) {
		if (iface->id == packet->frame.src_interface) {
			continue;
		}

		g_string_append_printf (message, " %s: ", iface->device_name);

		if (!gini_dvmrp_edges[iface->id]) {
			if (!route->children[iface->id]) {
				g_string_append (message, "NO (not child for src)");
				continue;
			}

			if (group->pruned[iface->id] != 0) {
				g_string_append (message, "NO (pruned)");
				continue;
			}

			g_string_append (message, "YES (forwarding)");
		} else {
			if (!gini_mcast_membership_get (iface, dst_ip)) {
				g_string_append (message, "NO (no IGMP members)");
				continue;
			}

			g_string_append (message, "YES (local IGMP)");
		}

		// copy the packet and forward on this interface, don't send a prune
		should_prune = FALSE;

		forward = gini_packet_copy (packet);

		forward->frame.dst_interface = iface->id;
		forward->frame.arp_bcast = TRUE;

		gini_ip_send_fragmented (forward);
	}

	if (should_prune && !gini_dvmrp_edges[packet->frame.src_interface]) {
		g_string_append (message, " sending PRUNE message");
		group->prune_sent = TRUE;

		gini_dvmrp_send (
			GINI_DVMRP_MESSAGE_TYPE_PRUNE,
			*(guint32 *) packet->ip->ip_dst,
			*(guint32 *) packet->ip->ip_src,
			gini_iface_get (packet->frame.src_interface));
	}

end:
	g_debug ("%s", message->str);
	g_string_free (message, TRUE);

	// packet needs to be freed
	return FALSE;
}

void
gini_dvmrp_graft (GiniInetAddress  group_address,
                  GiniInterface   *src_iface)
{
	gboolean forward_graft[GINI_IFACE_MAX] = { FALSE };
	GiniInterface *iface = NULL;
	GiniDvmrpRouteGroup *group;
	int i;

	for (i = 0; i < gini_dvmrp_routes->len; i++) {
		GiniDvmrpRoute *route = gini_dvmrp_route_get (i);

		if (route->iface == src_iface)
			continue;

		if (!(group = g_tree_lookup (route->groups, GINT_TO_POINTER (group_address))))
			continue;

		group->pruned[src_iface->id] = FALSE;

		if (group->prune_sent) {
			group->prune_sent = FALSE;
			forward_graft[route->iface->id] = TRUE;
		}
	}

	while ((iface = gini_iface_next (iface))) {
		if (forward_graft[iface->id]) {
			gini_dvmrp_send (
				GINI_DVMRP_MESSAGE_TYPE_GRAFT,
				*(guint32 *) GINI_MCAST_ALL_ROUTERS,
				g_ntohl (group_address),
				iface);
		}
	}
}

gboolean
gini_dvmrp_probe (int *count)
{
	GiniInterface *iface = NULL;

	while ((iface = gini_iface_next (iface))) {
		gini_dvmrp_send (
			GINI_DVMRP_MESSAGE_TYPE_PROBE,
			*(guint32 *) GINI_MCAST_ALL_ROUTERS,
			0,
			iface);
	}

	if (count && --(*count) <= 0) {
		g_free (count);
		return FALSE;
	}

	return TRUE;
}

static gboolean
gini_dvmrp_process_probe (GiniPacket *packet)
{
	packet->igmp->subtype = GINI_DVMRP_MESSAGE_TYPE_REPORT;

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

static gboolean
gini_dvmrp_process_prune (GiniPacket *packet)
{
	GiniDvmrpRoute *route;
	GiniInetAddress src_ip, dst_ip;
	GTimeVal now;
	GiniDvmrpRouteGroup *group;

	src_ip = g_ntohl (packet->igmp->group_address);
	dst_ip = g_ntohl (*(guint32 *) packet->ip->ip_dst);

	// find the route to the sender in the table
	if (!(route = gini_dvmrp_route_find (src_ip))) {
		return FALSE;
	}

	// find the pruned list for this group
	if (!(group = g_tree_lookup (route->groups, GINT_TO_POINTER (dst_ip)))) {
		return FALSE;
	}

	g_get_current_time (&now);

	group->pruned[packet->frame.src_interface] = now.tv_sec;

	// we don't check here if the whole route is pruned; that's done if another
	// packet is received for the same route

	return FALSE;
}

static gboolean
gini_dvmrp_process_graft (GiniPacket *packet)
{
	gini_dvmrp_graft (g_ntohl (packet->igmp->group_address),
		              gini_iface_get (packet->frame.src_interface));

	return TRUE;
}

static gboolean
gini_dvmrp_process_leaf (GiniPacket *packet)
{
	GiniDvmrpRoute *route;
	GiniInetAddress src_ip;

	src_ip = g_ntohl (packet->igmp->group_address);

	// find the route to the sender in the table
	if (!(route = gini_dvmrp_route_find (src_ip))) {
		return FALSE;
	}

	route->children[packet->frame.src_interface] = FALSE;

	return FALSE;
}

gboolean
gini_dvmrp_process (GiniPacket *packet)
{
	switch (packet->igmp->subtype) {
	case GINI_DVMRP_MESSAGE_TYPE_PROBE:
		return gini_dvmrp_process_probe (packet);

	case GINI_DVMRP_MESSAGE_TYPE_REPORT:
		gini_dvmrp_edges[packet->frame.src_interface] = FALSE;
		return FALSE;

	case GINI_DVMRP_MESSAGE_TYPE_PRUNE:
		return gini_dvmrp_process_prune (packet);

	case GINI_DVMRP_MESSAGE_TYPE_GRAFT:
		return gini_dvmrp_process_graft (packet);

	case GINI_DVMRP_MESSAGE_TYPE_LEAF:
		return gini_dvmrp_process_leaf (packet);

	default:
		g_debug ("silently dropping unknown DVMRP message type %d", packet->igmp->subtype);
	}

	return FALSE;
}

static void
gini_dvmrp_route_init (void)
{
	int i,j ;

	if (!gini_dvmrp_routes) {
		gini_dvmrp_routes = g_array_sized_new (FALSE, TRUE, sizeof (GiniDvmrpRoute), GINI_ROUTE_MAX);
	} else if (gini_dvmrp_routes->len) {
		g_array_remove_range (gini_dvmrp_routes, 0, gini_dvmrp_routes->len);
	}

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

			for (j = 0; j < GINI_IFACE_MAX; j++) {
				copy.children[j] = j != route.interface;
			}

			g_array_append_val (gini_dvmrp_routes, copy);
		}
	}
}

static gboolean
print_groups (GiniInetAddress  group,
              gulong          *pruned,
              GiniDvmrpRoute  *route)
{
	GiniInterface *iface = NULL;
	char tmp[64];

	g_printf ("\n                | %-15s |",
		gini_ntoa (tmp, (uchar *) &group));

	while ((iface = gini_iface_next (iface)))
		g_printf (" %-6s",
			gini_dvmrp_edges[iface->id] ? "IGMP" : (
				!route->children[iface->id] ? "No" : (
					pruned[iface->id] ? "Pruned" : "Yes")));

	return TRUE;
}

void
gini_dvmrp_cli (int   argc,
                char *argv[])
{
	if (argc == 2 && strcmp (argv[1], "init") == 0) {
		gini_dvmrp_route_init ();
	} else if (argc == 2 && strcmp (argv[1], "show") == 0) {
		GiniInterface *iface = NULL;
		int i;
		char tmp1[64], tmp2[64];

		while ((iface = gini_iface_next (iface)))
			g_printf ("%-7s: %s\n", iface->device_name, gini_dvmrp_edges[iface->id] ? "Edge" : "Router");

		g_printf ("----------------+-----------------+-----------\n");
		g_printf ("Network         | Netmask         | Interface \n");
		g_printf ("----------------+-----------------+-----------\n");

		for (i = 0; i < gini_dvmrp_routes->len; i++) {
			GiniDvmrpRoute *route = gini_dvmrp_route_get (i);

			g_printf ("%-15s | %-15s | %-6s",
				gini_ntoa (tmp1, (uchar *) &route->network),
				gini_ntoa (tmp2, (uchar *) &route->netmask),
				route->iface->device_name);

			g_printf ("\n                | Multicast Group |");

			while ((iface = gini_iface_next (iface)))
				g_printf (" %-6s", iface->device_name);

			g_printf ("\n                | 0.0.0.0         |");

			while ((iface = gini_iface_next (iface)))
				g_printf (" %-6s",
					gini_dvmrp_edges[iface->id] ? "IGMP" : (
						route->children[iface->id] ? "Yes" : "No"));

			if (route->groups)
				g_tree_foreach (route->groups, (GTraverseFunc) print_groups, route);

			g_printf ("\n----------------+-----------------+-----------\n");
		}
	}
}

void
gini_dvmrp_init (void)
{
	int i, *count = g_malloc0 (sizeof (int));

	*count = GINI_DVMRP_STARTUP_COUNT;

	// send a couple of probes at startup to detect leafs
	g_timeout_add_seconds (GINI_DVMRP_TRIGGERED_UPDATE_RATE, (GSourceFunc) gini_dvmrp_probe, count);

	g_timeout_add_seconds (GINI_DVMRP_FULL_UPDATE_RATE, (GSourceFunc) gini_dvmrp_probe, NULL);

	for (i = 0; i < GINI_IFACE_MAX; i++) {
		gini_dvmrp_edges[i] = TRUE;
	}

	grtr_cli_register ("dvmrp", gini_dvmrp_cli, NULL);

	//gini_dvmrp_route_init ();
}

