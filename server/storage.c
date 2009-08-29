/*
 * Copyright (c) 2009, Red Hat, Inc.
 */
#define _GNU_SOURCE
#include "tabled-config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <glib.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <event.h>
#include <chunkc.h>
#include <netdb.h>
#include "tabled.h"

static const char stor_key_fmt[] = "%016llx";
#define STOR_KEY_SLEN  16

static int stor_new_stc(struct storage_node *stn, struct st_client **stcp)
{
	struct st_client *stc;
	struct sockaddr_in *a4;
	struct sockaddr_in6 *a6;
	unsigned short port;

	if (stn->addr_af == AF_INET) {
		a4 = (struct sockaddr_in *) &stn->addr;
		port = ntohs(a4->sin_port);
	} else if (stn->addr_af == AF_INET6) {
		a6 = &stn->addr;
		port = ntohs(a6->sin6_port);
	} else {
		return -EINVAL;
	}

	stc = stc_new(stn->hostname, port,
		      tabled_srv.chunk_user, tabled_srv.chunk_key,
		      false);
	if (!stc)
		return -EDOM;

	*stcp = stc;
	return 0;
}

static void stor_read_event(int fd, short events, void *userdata)
{
	struct open_chunk *cep = userdata;

	cep->r_armed = 0;
	if (cep->rcb)
		(*cep->rcb)(cep);
}

/*
 * Open *cep using stn, set up chunk session if needed.
 */
int stor_open(struct open_chunk *cep, struct storage_node *stn)
{
	int rc;

	if (cep->stc)
		return 0;

	if ((rc = stor_new_stc(stn, &cep->stc)) < 0) {
		if (debugging)
			applog(LOG_INFO, "Failed to open Chunk (%d)\n", rc);
		return rc;
	}

	cep->node = stn;
	stn->nchu++;

	/* cep->stc->verbose = 1; */

	return 0;
}

int stor_put_start(struct open_chunk *cep, uint64_t key, uint64_t size)
{
	char stckey[STOR_KEY_SLEN+1];

	if (!cep->stc)
		return -EINVAL;

	/*
	 * Set up the putting.
	 */
	sprintf(stckey, stor_key_fmt, (unsigned long long) key);
	if (!stc_put_start(cep->stc, stckey, size, &cep->wfd)) {
		if (debugging)
			applog(LOG_INFO, "stor put %s new for %lld error",
			       stckey, (long long) size);
		return -EIO;
	}
	cep->wtogo = size;
	cep->wkey = key;
	if (debugging)
		applog(LOG_INFO, "stor put %s new for %lld",
		       stckey, (long long) size);

	return 0;
}

/*
 * It should be ok to return
 */
int stor_open_read(struct open_chunk *cep, void (*cb)(struct open_chunk *),
		   uint64_t key, uint64_t *psize)
{
	char stckey[STOR_KEY_SLEN+1];
	size_t size;

	if (!cep->stc)
		return -EINVAL;

	if (cep->rsize && cep->roff != cep->rsize) {
		applog(LOG_ERR, "Unfinished Get (%ld,%ld)",
		       (long)cep->roff, (long)cep->rsize);
		cep->rsize = 0;
	}

	sprintf(stckey, stor_key_fmt, (unsigned long long) key);
	if (!stc_get_start(cep->stc, stckey, &cep->rfd, &size)) {
		if (debugging)
			applog(LOG_INFO, "stor put %s error", stckey);
		return -EIO;
	}
	*psize = size;
	cep->rsize = size;
	cep->roff = 0;
	cep->rcb = cb;
	event_set(&cep->revt, cep->rfd, EV_READ, stor_read_event, cep);

	if (debugging)
		applog(LOG_INFO, "stor get %s size %lld",
		       stckey, (long long) size);

	return 0;
}

/*
 * FIXME We don't cache sessions while tabled is being debugged. Maybe later.
 */
void stor_close(struct open_chunk *cep)
{
	if (cep->stc) {
		--cep->node->nchu;
		cep->node = NULL;
		stc_free(cep->stc);
		cep->stc = NULL;
	}

	if (cep->r_armed) {
		event_del(&cep->revt);
		cep->r_armed = 0;
	}
	cep->rsize = 0;
}

/*
 * The stor_abort has an annoying convention of being possibly called
 * on an unopened open_chunk. We deal with that.
 *
 * There's no "abort" call for an existing transfer. We could complete
 * the transfer instead of trashing the whole session, but that may involve
 * sending or receiving gigabytes. So we just cycle the session.
 */
void stor_abort(struct open_chunk *cep)
{
	char stckey[STOR_KEY_SLEN+1];
	int rc;

	if (!cep->stc)
		return;

	if (debugging)
		applog(LOG_INFO, "stor aborting\n");

	stc_free(cep->stc);
	cep->stc = NULL;

	rc = stor_new_stc(cep->node, &cep->stc);
	if (rc < 0) {
		--cep->node->nchu;
		cep->node = NULL;

		if (debugging)
			applog(LOG_INFO, "Failed to reopen Chunk (%d)\n", rc);
		return;
	}

	if (cep->wtogo) {
		sprintf(stckey, stor_key_fmt, (unsigned long long) cep->wkey);
		stc_del(cep->stc, stckey);
		cep->wtogo = 0;
	}

	if (cep->r_armed) {
		event_del(&cep->revt);
		cep->r_armed = 0;
	}
	cep->rsize = 0;
}

ssize_t stor_put_buf(struct open_chunk *cep, void *data, size_t len)
{
	if (len > cep->wtogo) {
		applog(LOG_ERR, "Put size %ld remaining %ld",
		       (long) len, (long) cep->wtogo);
		if (cep->wtogo == 0)
			return -EIO;	/* will spin otherwise, better error */
		len = cep->wtogo;
		cep->wtogo = 0;
	} else {
		cep->wtogo -= len;
	}

	if (cep->stc)
		return stc_put_send(cep->stc, data, len);
	return -EPIPE;
}

bool stor_put_end(struct open_chunk *cep)
{
	if (!cep->stc)
		return true;
	return stc_put_sync(cep->stc);
}

/*
 * Too smart: We auto-arm libevent if not the whole len was returned.
 * This saves the object.c from the trouble of arming and disarming it,
 * at the cost of rather subtle semantics.
 */
ssize_t stor_get_buf(struct open_chunk *cep, void *data, size_t req_len)
{
	size_t xfer_len;
	ssize_t ret;

	if (!cep->stc)
		return -EDOM;

	if (cep->roff + req_len < cep->roff)	/* wrap */
		return -EINVAL;
	if (cep->roff + req_len > cep->rsize)
		xfer_len = cep->rsize - cep->roff;
	else
		xfer_len = req_len;
	if (xfer_len == 0)
		return 0;
	ret = stc_get_recv(cep->stc, data, xfer_len);
	if (ret < 0)
		return -EIO;

	cep->roff += ret;
	if (cep->roff == cep->rsize) {
		cep->roff = 0;
		cep->rsize = 0;
	}

	if (xfer_len != ret && cep->rsize && !cep->r_armed) {
		cep->r_armed = 1;
		if (event_add(&cep->revt, NULL))
			cep->r_armed = 0;
	}

	return ret;
}

void stor_get_enable(struct open_chunk *cep)
{
	if (!cep->stc) {	/* never happens */
		applog(LOG_ERR, "Unopened chunk in stor_get_enable");
		return;
	}

}

int stor_obj_del(struct storage_node *stn, uint64_t key)
{
	struct st_client *stc;
	char stckey[STOR_KEY_SLEN+1];
	int rc;

	rc = stor_new_stc(stn, &stc);
	if (rc < 0)
		return rc;

	sprintf(stckey, stor_key_fmt, (unsigned long long) key);
	rc = stc_del(stc, stckey) ? 0 : -EIO;

	stc_free(stc);

	return rc;
}

bool stor_obj_test(struct open_chunk *cep, uint64_t key)
{
	struct st_keylist *klist;

	if (!cep->stc)
		return false;

	klist = stc_keys(cep->stc);
	if (!klist)
		return false;
	stc_free_keylist(klist);
	return true;
}

void stor_add_node(uint32_t nid, const char *hostname, const char *portstr,
		   struct geo *locp)
{
	struct addrinfo hints;
	struct addrinfo *res, *res0;
	struct storage_node *sn;
	int rc;

	/* XXX FIXME search all_stor for dup NIDs */

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	rc = getaddrinfo(hostname, portstr, &hints, &res0);
	if (rc) {
		applog(LOG_WARNING, "getaddrinfo(%s:%s) failed: %s",
		       hostname, portstr, gai_strerror(rc));
		return;
	}

	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family != AF_INET && res->ai_family != AF_INET6)
			continue;

		if (res->ai_addrlen > ADDRSIZE)		/* should not happen */
			continue;

		if ((sn = malloc(sizeof(struct storage_node))) == NULL) {
			applog(LOG_WARNING, "No core (%ld)",
			       (long) sizeof(struct storage_node));
			break;
		}
		memset(sn, 0, sizeof(struct storage_node));

		sn->id = nid;

		memcpy(&sn->addr, res->ai_addr, res->ai_addrlen);
		sn->addr_af = res->ai_family;
		sn->alen = res->ai_addrlen;

		if ((sn->hostname = strdup(hostname)) == NULL) {
			applog(LOG_WARNING, "No core");
			free(sn);
			break;
		}

		if (debugging) {
			char nhost[41];
			char nport[6];
			if (getnameinfo((struct sockaddr *) &sn->addr, sn->alen,
					nhost, sizeof(nhost),
				        nport, sizeof(nport),
					NI_NUMERICHOST|NI_NUMERICSERV) == 0) {
				applog(LOG_INFO, "Found Chunk host %s port %s",
				       nhost, nport);
			} else {
				applog(LOG_INFO, "Found Chunk host");
			}
		}

		list_add(&sn->all_link, &tabled_srv.all_stor);
		tabled_srv.num_stor++;
	}

	freeaddrinfo(res0);
	return;
}

/* Return 0 if the node checks out ok */
int stor_node_check(struct storage_node *stn)
{
	struct st_client *stc;
	char host[41];
	char port[6];
	int rc;

	rc = stor_new_stc(stn, &stc);
	if (rc < 0) {
		if (rc == -EINVAL) {
			if (getnameinfo((struct sockaddr *) &stn->addr,
					stn->alen, host, sizeof(host),
					port, sizeof(port),
					NI_NUMERICHOST|NI_NUMERICSERV) == 0) {
				applog(LOG_INFO, "Error connecting to chunkd"
				       " on host %s port %s",
				       host, port);
			} else {
				applog(LOG_INFO, "Error connecting to chunkd");
			}
		} else {
			applog(LOG_INFO, "Error %d connecting to chunkd", rc);
		}
		return -1;
	}

	stc_free(stc);
	return 0;
}

