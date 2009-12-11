#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib/gstdio.h>

#include "udp.h"

#define DEST_UNREACHABLE_ORIG(ip) (GINI_IP_HEADER_SIZE(ip) + 8)
#define DEST_UNREACHABLE_SIZE(ip) (sizeof (GiniIcmpHeader) + DEST_UNREACHABLE_ORIG(ip))

guint32
gini_checksum_partial (guint32  checksum,
                       guchar  *buffer,
                       gsize    words)
{
	for (; words > 0; words--) {
		checksum += *(buffer++) << 8;
		checksum += *(buffer++);
	}

	// add in all carries
	while (checksum >> 16) {
		checksum = (checksum & 0xffff) + (checksum >> 16);
	}

	return checksum;
}

static void
gini_icmp_send (GiniPacket   *packet,
                GiniIcmpType  type,
                GiniIcmpCode  code)
{
	GiniInetAddress dst;
	GiniIpHeader *ip = (GiniIpHeader *) (packet->data.data);
	GiniIcmpHeader *icmp = (GiniIcmpHeader *) (ip + 1);
	guchar *data = (guchar *) (icmp + 1);

	// include original IP header + 64 payload bits
	g_memmove (data, ip, DEST_UNREACHABLE_ORIG(ip));

	// set up the ICMP header
	memset (icmp, 0, sizeof (GiniIcmpHeader));

	icmp->type = type;
	icmp->code = code;
	icmp->checksum = g_htons (gini_checksum ((guchar *) icmp, DEST_UNREACHABLE_SIZE(ip) / 2));

	// set the return address
	dst = g_ntohl (*(GiniInetAddress *) (ip->ip_src));

	// send it out
	gini_ip_outgoing (packet, (guchar *) &dst, DEST_UNREACHABLE_SIZE(ip), 1, GINI_ICMP_PROTOCOL);
}

static GStaticMutex gini_udp_mutex = G_STATIC_MUTEX_INIT;

static GAsyncQueue *gini_udp_queue;
static gushort gini_udp_listen_port = 0;

gushort
gini_udp_checksum (GiniPacket *packet)
{
	GiniIpHeader *ip = packet->ip;
	GiniUdpHeader *udp = packet->udp;
	guint32 checksum;

	// calculate the checksum
	checksum = GINI_UDP_PROTOCOL + g_ntohs (udp->length);
	// src and dst IP addresses
	checksum = gini_checksum_partial (checksum, (guchar *) &(ip->ip_src), 4);
	checksum = gini_checksum_partial (checksum, (guchar *) udp, (g_ntohs (udp->length) + 1) / 2);

	checksum = g_htons (~checksum);

	return checksum;
}

void
gini_udp_send (GiniSocketAddress *dst,
               guint16            src_port,
               gchar             *data,
               gsize              length)
{
	GiniPacket *packet = g_new0 (GiniPacket, 1);
	GiniIpHeader *ip = packet->ip = (GiniIpHeader *) (packet->data.data);
	GiniUdpHeader *udp = packet->udp = (GiniUdpHeader *) (ip + 1);

	g_return_if_fail (length + sizeof (GiniUdpHeader) <= G_MAXUINT16);

	udp->dst_port = dst->port;
	udp->src_port = src_port;
	udp->length = g_htons (length + sizeof (GiniUdpHeader));

	// clear out rest of packet
	memset (udp + 1, 0, ((length + 1) >> 1) << 1);

	// copy data into packet
	memcpy (udp + 1, data, length);

	// prepare the packet
	gini_ip_prepare (packet, (guchar *) &(dst->address), length + sizeof (GiniUdpHeader), 1, GINI_UDP_PROTOCOL);

	// calculate checksum
	udp->checksum = gini_udp_checksum (packet);

	// RFC 768: set checksum to 0xffff it is 0
	if (udp->checksum == 0) {
		udp->checksum = 0xffff;
	}

	// send it
	gini_ip_send (packet);
}

gsize
gini_udp_recv (GiniSocketAddress *dst,
               guint16            src_port,
               gchar             *data,
               gsize              length)
{
	GiniPacket *packet;
	GiniIpHeader *ip;
	GiniUdpHeader *udp;

	// set the port we are listening on
	g_static_mutex_lock (&gini_udp_mutex);
	gini_udp_listen_port = src_port;
	g_static_mutex_unlock (&gini_udp_mutex);

	// pop a verified packet from the queue
	packet = g_async_queue_pop (gini_udp_queue);

	// unset the listen port
	g_static_mutex_lock (&gini_udp_mutex);
	gini_udp_listen_port = 0;
	g_static_mutex_unlock (&gini_udp_mutex);

	ip = (GiniIpHeader *) (packet->data.data);
	udp = (GiniUdpHeader *) (ip + 1);

	length = MIN (g_ntohs (udp->length), length);

	// give the data back to the caller
	memcpy (data, udp + 1, length);

	return length;
}

void
gini_udp_process (GiniPacket *packet)
{
	GiniUdpHeader *udp = packet->udp;

	gushort port;

	if (udp->checksum != 0) {
		// calculating packet checksum should be zero, since checksum field will be 1's complement
		if (gini_udp_checksum (packet) != 0) {
			// RFC 1122, section 4.1.3.4
			// silently discard UDP packets with nonzero and invalid checksum
			g_debug ("discarding UDP packet with invalid checksum %04x", udp->checksum);
			return;
		}
	}

	g_static_mutex_lock (&gini_udp_mutex);
	port = gini_udp_listen_port;
	g_static_mutex_unlock (&gini_udp_mutex);

	// in a more complex system, might need to do lookup in a table of waiting processes
	// and push to appropriate queue

	if (port == 0 || port != udp->dst_port) {
		// RFC 1122, section 4.1.3.1
		// nobody is waiting for packet, so send ICMP Port Unreachable
		g_debug ("sending ICMP port unreachable for UDP packet sent to port %d", g_ntohs (udp->dst_port));
		gini_icmp_send (packet,
		                GINI_ICMP_TYPE_DEST_UNREACHABLE,
		                GINI_ICMP_CODE_PORT_UNREACHABLE);

		return;
	}

	// push the packet
	g_async_queue_push (gini_udp_queue, packet);
}

void
gini_udp_init (void)
{
	gini_udp_queue = g_async_queue_new ();
}

static guint local_port = 0;
static guint remote_port = 0;

static GOptionEntry grtr_cli_udp_entries[] = {
	{ "local-port", 'l', 0, G_OPTION_ARG_INT, &local_port, "Local UDP port", "port" },
	{ "remote-port", 'r', 0, G_OPTION_ARG_INT, &remote_port, "Remote UDP port", "port" },
	{ NULL }
};

void
grtr_cli_udp (gchar *cmd)
{
	GError *error = NULL;
	GOptionContext *context;
	GiniSocketAddress dst;
	gint argc;
	gchar **argv;
	gsize len;
	gchar buffer[LINE_MAX];

	if (!g_shell_parse_argv (cmd, &argc, &argv, &error)) {
		g_printerr ("Could not parse command: %s\n", error->message);
		g_clear_error (&error);
		return;
	}

	local_port = remote_port = 0;

	context = g_option_context_new ("- UDP test");
	g_option_context_add_main_entries (context, grtr_cli_udp_entries, NULL);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		g_printerr ("Could not parse options: %s\n", error->message);
		g_clear_error (&error);
		return;
	}

	gini_aton(argv[1], (guchar *) &(dst.address));

	dst.port = g_htons (remote_port);

	do {
		fgets (buffer, LINE_MAX, stdin);

		if (*buffer == '\n' || *buffer == '\r') {
			break;
		}

		gini_udp_send (&dst, g_htons (local_port), buffer, strlen (buffer));

		if (local_port != 0) {
			len = gini_udp_recv (&dst, g_htons (local_port), buffer, LINE_MAX);
		}

		buffer[len] = '\0';

		g_printf ("%s", buffer);
	} while (TRUE);

	g_strfreev (argv);
}

