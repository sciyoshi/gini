#include <glib/gstdio.h>

#include "multicast.h"
#include "igmp.h"
#include "dvmrp.h"
#include "cli.h"

static GTree *gini_mcast_memberships[GINI_IFACE_MAX];

/**
 * Multicast group membership management
 */

void
gini_mcast_membership_add (GiniInterface   *interface,
                           GiniInetAddress  group_address)
{
	GTimeVal time;
	gchar tmp1[64], tmp2[64];
	GTree **memberships = gini_mcast_memberships + interface->id;

	if (!*memberships)
		*memberships = g_tree_new ((GCompareFunc) gini_ip_cmp);

	g_get_current_time (&time);

	g_debug ("adding membership on interface %s to multicast group %s",
		gini_ntoa (tmp1, interface->ip_addr),
		gini_ntoa (tmp2, (uchar *) &group_address));

	g_tree_replace (*memberships, GINT_TO_POINTER (group_address), GINT_TO_POINTER (time.tv_sec));
}

void
gini_mcast_membership_remove (GiniInterface   *interface,
                              GiniInetAddress  group_address)
{
	GTree *memberships = gini_mcast_memberships[interface->id];

	if (memberships)
		g_tree_remove (memberships, GINT_TO_POINTER (group_address));
}

gboolean
gini_mcast_membership_get (GiniInterface   *interface,
                           GiniInetAddress  group_address)
{
	GTree *memberships = gini_mcast_memberships[interface->id];

	if (!memberships)
		return FALSE;

	return g_tree_lookup_extended (memberships, GINT_TO_POINTER (group_address), NULL, NULL);
}

typedef struct {
	GTimeVal  current;
	GSList   *expired;
} ExpireInfo;

static void
add_expired (GiniInetAddress  group_address,
             gulong           last_time,
             ExpireInfo      *info)
{
	if (info->current.tv_sec - last_time > GINI_MCAST_MEMBERSHIP_EXPIRATION_TIME)
		info->expired = g_slist_prepend (info->expired, GINT_TO_POINTER (group_address));
}

static gboolean
gini_mcast_clean_expired (gpointer data)
{
	ExpireInfo info;
	GiniInterface *iface = NULL;
	char tmp1[64], tmp2[64];

	g_get_current_time (&info.current);
	info.expired = NULL;

	while ((iface = gini_iface_next (iface))) {
		if (!gini_mcast_memberships[iface->id])
			continue;

		g_tree_foreach (gini_mcast_memberships[iface->id], (GTraverseFunc) add_expired, &info);

		while (info.expired) {
			g_debug ("removing membership on interface %s to multicast group %s",
				gini_ntoa (tmp1, iface->ip_addr),
				gini_ntoa (tmp2, (uchar *) &(info.expired->data)));

			gini_mcast_membership_remove (iface, GPOINTER_TO_INT (info.expired->data));

			info.expired = g_slist_delete_link (info.expired, info.expired);
		}
	}

	return TRUE;
}

/**
 * Multicast packet handling
 */

void
gini_mcast_ip_to_mac (uchar       mac[6],
                      const uchar ip[4])
{
	memcpy (mac, ip, sizeof (GiniInetAddress));

	mac[0] = 0x01;
	mac[1] = 0x00;
	mac[2] = 0x5E;
	mac[3] &= 0x7F;
}

gboolean
gini_mcast_process (GiniPacket *packet)
{
	if (packet->ip->ip_prot == GINI_IGMP_PROTOCOL) {
		return gini_igmp_process (packet);
	} else {
		return gini_dvmrp_forward (packet);
	}
}

/**
 * CLI functions
 */

typedef struct {
	GiniInterface *iface;
	GTimeVal       now;
} MembershipInfo;

static void
print_membership (GiniInetAddress  group_address,
                  gulong           last_time,
                  MembershipInfo  *info)
{
	gchar tmp1[64], tmp2[64];

	g_printf ("%-9s | %-17s | %-17s | %lds ago\n",
		info->iface->device_name,
		gini_ntoa (tmp1, info->iface->ip_addr),
		gini_ntoa (tmp2, (uchar *) &group_address),
		info->now.tv_sec - last_time);
}

static void
gini_mcast_cli (int argc, char *argv[])
{
	MembershipInfo info;
	GiniInterface *iface = NULL;

	g_get_current_time (&info.now);

	g_printf ("----------+-------------------+-------------------+-------------\n");
	g_printf ("Interface | Interface IP      | Multicast Group   | Last Report \n");
	g_printf ("----------+-------------------+-------------------+-------------\n");

	while ((iface = gini_iface_next (iface))) {
		GTree *memberships = gini_mcast_memberships[iface->id];

		if (!memberships) {
			continue;
		}

		info.iface = iface;

		g_tree_foreach (memberships, (GTraverseFunc) print_membership, &info);

		g_printf ("----------+-------------------+-------------------+-------------\n");
	}
}

void
gini_mcast_init (void)
{
	gini_igmp_init ();
	gini_dvmrp_init ();

	grtr_cli_register ("mcast", gini_mcast_cli, NULL);

	g_timeout_add_seconds (10, (GSourceFunc) gini_mcast_clean_expired, NULL);
}

