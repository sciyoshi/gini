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
	GTree **memberships = grtr_mcast_memberships + interface->interface_id;

	if (!*memberships) {
		*memberships = g_tree_new ((GCompareFunc) grtr_inet_address_cmp);
	}

	g_get_current_time (&time);

	g_tree_replace (*memberships, GINT_TO_POINTER (group_address), GINT_TO_POINTER (time.tv_sec));
}

typedef struct {
	GTimeVal  current;
	GSList   *expired;
} ExpireInfo;

static void
grtr_mcast_add_expired (GiniInetAddress  group_address,
                        gulong           last_time,
                        ExpireInfo      *info)
{
	if (info->current.tv_sec - last_time > GRTR_MCAST_MEMBERSHIP_EXPIRATION_TIME) {
		info->expired = g_slist_prepend (info->expired, GINT_TO_POINTER (group_address));
	}
}

gboolean
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

		g_tree_foreach (grtr_mcast_memberships[i], (GTraverseFunc) grtr_mcast_add_expired, &info);

		while (info.expired) {
			if (grtr_iface_get (i)) {
				*(guint32 *) tmp2 = g_ntohl ((GiniInetAddress) GPOINTER_TO_INT (info.expired->data));

				g_debug ("removing membership on interface %s to multicast group %s",
					gini_ntoa (tmp1, grtr_iface_get (i)->ip_addr),
					gini_ntoa (tmp2, tmp2));
			}

			g_tree_remove (grtr_mcast_memberships[i], info.expired->data);

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

static void
grtr_mcast_cli (int argc, char *argv[])
{
	g_debug ("Hi!");
}

void
grtr_mcast_init (void)
{
	grtr_igmp_init ();

	grtr_cli_register ("mcast", grtr_mcast_cli, grtr_mcast_cli_entries);

	g_timeout_add_seconds (30, (GSourceFunc) grtr_mcast_clean_expired, NULL);
}

