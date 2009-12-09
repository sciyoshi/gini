#include "multicast.h"
#include "igmp.h"
#include "cli.h"

static GTree *grtr_mcast_memberships[MAX_INTERFACES];

static gint
grtr_inet_address_cmp (GiniInetAddress a,
                       GiniInetAddress b)
{
	return a - b;
}

void
grtr_mcast_membership_add (GiniInterface   *interface,
                           GiniInetAddress  group_address)
{
	GTimeVal time;
	gchar tmp1[64], tmp2[64];
	GTree **memberships = grtr_mcast_memberships + interface->interface_id;

	if (!*memberships) {
		*memberships = g_tree_new ((GCompareFunc) grtr_inet_address_cmp);
	}

	g_get_current_time (&time);

	g_debug ("adding membership on interface %s to multicast group %s",
		gini_ntoa (tmp1, interface->ip_addr),
		gini_ntoa (tmp2, (char *) &group_address));

	g_tree_replace (*memberships, GINT_TO_POINTER (group_address), GINT_TO_POINTER (time.tv_sec));
}

void
grtr_mcast_membership_remove (GiniInterface   *interface,
                              GiniInetAddress  group_address)
{
	GTree *memberships = grtr_mcast_memberships[interface->interface_id];

	if (memberships) {
		g_tree_remove (memberships, GINT_TO_POINTER (group_address));
	}
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
	if (info->current.tv_sec - last_time > GRTR_MCAST_MEMBERSHIP_EXPIRATION_TIME) {
		info->expired = g_slist_prepend (info->expired, GINT_TO_POINTER (group_address));
	}
}

static gboolean
grtr_mcast_clean_expired (gpointer data)
{
	ExpireInfo info;
	char tmp1[64], tmp2[64];
	int i;

	g_get_current_time (&info.current);
	info.expired = NULL;

	for (i = 0; i < MAX_INTERFACES; i++) {
		if (!grtr_mcast_memberships[i]) {
			continue;
		}

		g_tree_foreach (grtr_mcast_memberships[i], (GTraverseFunc) add_expired, &info);

		while (info.expired) {
			GiniInterface *iface = grtr_iface_get (i);

			if (iface) {
				g_debug ("removing membership on interface %s to multicast group %s",
					gini_ntoa (tmp1, iface->ip_addr),
					gini_ntoa (tmp2, (char *) &(info.expired->data)));

				grtr_mcast_membership_remove (iface, GPOINTER_TO_INT (info.expired->data));
			}

			info.expired = g_slist_delete_link (info.expired, info.expired);
		}
	}

	return TRUE;
}

void
grtr_mcast_incoming (GiniPacket *packet)
{
	if (GINI_IP_HEADER (packet)->ip_prot == GINI_IGMP_PROTOCOL) {
		grtr_igmp_process (packet);
	}
}

static GOptionEntry grtr_mcast_cli_entries[] = {
	{ NULL }
};

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

	g_printf ("%-9s | %-17s | %-17s | %ds ago\n",
		info->iface->device_name,
		gini_ntoa (tmp1, info->iface->ip_addr),
		gini_ntoa (tmp2, (char *) &group_address),
		info->now.tv_sec - last_time);
}

static void
grtr_mcast_cli (int argc, char *argv[])
{
	MembershipInfo info;
	int i;
	char tmp[64];

	g_get_current_time (&info.now);

	g_printf ("----------+-------------------+-------------------+-------------\n");
	g_printf ("Interface | Interface IP      | Multicast Group   | Last Report \n");
	g_printf ("----------+-------------------+-------------------+-------------\n");

	for (i = 0; i < MAX_INTERFACES; i++) {
		GTree *memberships = grtr_mcast_memberships[i];

		info.iface = grtr_iface_get (i);

		if (!info.iface || !memberships) {
			continue;
		}

		g_tree_foreach (memberships, (GTraverseFunc) print_membership, &info);

		g_printf ("----------+-------------------+-------------------+-------------\n");
	}
}

void
grtr_mcast_init (void)
{
	grtr_igmp_init ();

	grtr_cli_register ("mcast", grtr_mcast_cli, NULL);

	g_timeout_add_seconds (30, (GSourceFunc) grtr_mcast_clean_expired, NULL);
}
