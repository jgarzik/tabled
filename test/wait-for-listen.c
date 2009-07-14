/*
 * wait-for-listen: Wait for a server port to open. This is not a real "test".
 * It only delays other tests so they run without errors.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>

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

int main()
{
	struct server_node snode, *sn = &snode;
	time_t start_time;
	int sfd;
	int rc;

	/*
	 * We hardcode host and port because we don't know an easy way
	 * to pass parameters to tests.
	 */
	memset(sn, 0, sizeof(struct server_node));
	if (node_resolve(sn, "localhost", "18080") != 0) {
		fprintf(stderr,
			"Unable to resolve host localhost port 18080\n");
		exit(1);
	}

	start_time = time(NULL);
	for (;;) {
		/*
 		 * Vote in DB4 replication takes about 12-13s.
 		 */
		if (time(NULL) >= start_time + 20) {
			fprintf(stderr, "server is not up after 20 s\n");
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
	return 0;
}

