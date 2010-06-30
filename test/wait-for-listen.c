
/*
 * Copyright 2009 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/*
 * wait-for-listen: Wait for a server port to open. This is not a real "test".
 * It only delays other tests so they run without errors.
 */

#define _GNU_SOURCE
#include "tabled-config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <httputil.h>
#include "test.h"

#define ADDRSIZE	24	/* Enough for IPv6, including port. */

struct server_node {
	unsigned		alen;
	union {
		struct sockaddr addr;
		unsigned char x[ADDRSIZE];
	} a;
};

static int node_resolve(struct server_node *sn,
    const char *hostname, const char *portstr)
{
	struct addrinfo hints;
	struct addrinfo *res, *res0;
	int rc;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	rc = getaddrinfo(hostname, portstr, &hints, &res0);
	if (rc) {
		fprintf(stderr, "getaddrinfo(%s:%s) failed: %s\n",
		       hostname, portstr, gai_strerror(rc));
		exit(1);
	}

	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family != AF_INET && res->ai_family != AF_INET6)
			continue;

		if (res->ai_addrlen > ADDRSIZE)		/* should not happen */
			continue;

		memcpy(&sn->a.addr, res->ai_addr, res->ai_addrlen);
		sn->alen = res->ai_addrlen;

		freeaddrinfo(res0);
		return 0;
	}

	freeaddrinfo(res0);
	return -1;
}

int main(int argc, char **argv)
{
	struct server_node snode, *sn = &snode;
	time_t start_time;
	const static char accname[] = TEST_FILE_TB;
	char accbuf[80];
	char *s;
	int cnt;
	int sfd;
	int rc;

	cnt = 0;
	for (;;) {
		rc = tb_readport(accname, accbuf, sizeof(accbuf));
		if (rc > 0)
			break;
		if (++cnt >= 5) {	/* should not take long */
			if (rc == 0) {
				fprintf(stderr, "Nothing to read in %s\n",
					accname);
				exit(1);
			}
			if (rc < 0) {
				fprintf(stderr, "Failed to read %s: %s\n",
					accname, strerror(-rc));
				exit(1);
			}
		}
		sleep(1);
	}

	s = strchr(accbuf, ':');
	if (!s)
		s = "80";
	else
		*s++ = 0;

	memset(sn, 0, sizeof(struct server_node));
	if (node_resolve(sn, accbuf, s) != 0) {
		fprintf(stderr,
			"Unable to resolve host %s port %s\n", accbuf, s);
		exit(1);
	}

	start_time = time(NULL);
	for (;;) {
		/*
 		 * Vote in DB4 replication takes about 12-13s.
		 * In addition we may have retries when tabled polls for
		 * Chunk daemons to come up. On busy boxes we may miss 20s.
		 */
		if (time(NULL) >= start_time + 25) {
			fprintf(stderr, "server is not up after 25 s\n");
			exit(1);
		}

		sfd = socket(sn->a.addr.sa_family, SOCK_STREAM, 0);
		if (sfd < 0) {
			fprintf(stderr, "socket: %s\n", strerror(errno));
			exit(1);
		}

		rc = connect(sfd, &sn->a.addr, sn->alen);
		if (rc == 0) {
			close(sfd);
			break;
		}
		if (errno != ECONNREFUSED) {
			fprintf(stderr, "connect: %s\n", strerror(errno));
			exit(1);
		}

		close(sfd);

		sleep(2);
	}

	printf("      wait-for-listen: tabled went up after %ld s\n",
	       (long)time(NULL) - start_time);
	return 0;
}

