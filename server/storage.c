
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

struct storage_node *stor_node_get(struct storage_node *sn)
{
	sn->ref++;
	if (sn->ref == 103) {		/* FIXME debugging test */
		applog(LOG_ERR, "ref leak in storage node nid %u", sn->id);
	}
	return sn;
}

void stor_node_put(struct storage_node *sn)
{

	/* Would be an error in the current code, we never free them. */
	if (sn->ref == 1) {
		applog(LOG_ERR, "freeing storage node nid %u", sn->id);
		return;
	}
	--sn->ref;
}

static int stor_new_stc(struct storage_node *stn, struct st_client **stcp)
{
	struct st_client *stc;
	struct sockaddr_in *a4;
	struct sockaddr_in6 *a6;
	unsigned short port;

	if (stn->addr.sin6_family == AF_INET) {
		a4 = (struct sockaddr_in *) &stn->addr;
		port = ntohs(a4->sin_port);
	} else if (stn->addr.sin6_family == AF_INET6) {
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

	if (!stc_table_openz(stc, "tabled", CHF_TBL_CREAT)) {
		stc_free(stc);
		return -EDOM;
	}

	*stcp = stc;
	return 0;
}

static void stor_read_event(int fd, short events, void *userdata)
{
	struct open_chunk *cep = userdata;

	cep->r_armed = false;		/* no EV_PERSIST */
	if (cep->ocb)
		(*cep->ocb)(cep);
}

static void stor_write_event(int fd, short events, void *userdata)
{
	struct open_chunk *cep = userdata;

	cep->w_armed = false;		/* no EV_PERSIST */
	if (cep->ocb)
		(*cep->ocb)(cep);
}

/*
 * Open *cep using stn, set up chunk session if needed.
 */
int stor_open(struct open_chunk *cep, struct storage_node *stn,
	      struct event_base *ev_base)
{
	int rc;

	if (cep->stc)
		return 0;

	if ((rc = stor_new_stc(stn, &cep->stc)) < 0)
		return rc;

	cep->evbase = ev_base;
	cep->node = stor_node_get(stn);

	/* cep->stc->verbose = 1; */

	return 0;
}

int stor_put_start(struct open_chunk *cep, void (*cb)(struct open_chunk *),
		   uint64_t key, uint64_t size)
{
	char stckey[STOR_KEY_SLEN+1];

	if (cep->key)
		return -EBUSY;
	if (!cep->stc)
		return -EINVAL;

	/*
	 * Set up the putting.
	 */
	sprintf(stckey, stor_key_fmt, (unsigned long long) key);
	if (!stc_put_startz(cep->stc, stckey, size, &cep->wfd, 0)) {
		if (debugging)
			applog(LOG_INFO,
			       "stor nid %u put %s new for %lld error",
			       cep->node->id, stckey, (long long) size);
		return -EIO;
	}
	cep->size = size;
	cep->done = 0;
	cep->key = key;
	cep->ocb = cb;
	event_set(&cep->wevt, cep->wfd, EV_WRITE, stor_write_event, cep);
	event_base_set(cep->evbase, &cep->wevt);

	if (debugging)
		applog(LOG_INFO, "stor nid %u put %s new for %lld",
		       cep->node->id, stckey, (long long) size);

	return 0;
}

/*
 * It should be ok to return
 */
int stor_open_read(struct open_chunk *cep, void (*cb)(struct open_chunk *),
		   uint64_t key, uint64_t *psize)
{
	char stckey[STOR_KEY_SLEN+1];
	uint64_t size;

	if (cep->key)
		return -EBUSY;
	if (!cep->stc)
		return -EINVAL;

	if (cep->size && cep->done != cep->size) {
		applog(LOG_ERR, "Unfinished Get (%ld,%ld)",
		       (long)cep->done, (long)cep->size);
		cep->size = 0;
	}

	sprintf(stckey, stor_key_fmt, (unsigned long long) key);
	if (!stc_get_startz(cep->stc, stckey, &cep->rfd, &size)) {
		if (debugging)
			applog(LOG_INFO, "stor nid %u get %s error",
			       cep->node->id, stckey);
		return -EIO;
	}
	*psize = size;
	cep->size = size;
	cep->done = 0;
	cep->key = key;
	cep->ocb = cb;
	event_set(&cep->revt, cep->rfd, EV_READ, stor_read_event, cep);
	event_base_set(cep->evbase, &cep->revt);

	if (debugging)
		applog(LOG_INFO, "stor nid %u get %s size %lld",
		       cep->node->id, stckey, (long long) size);

	return 0;
}

/*
 * FIXME We don't cache sessions while tabled is being debugged. Maybe later.
 */
void stor_close(struct open_chunk *cep)
{
	if (cep->stc) {
		stor_node_put(cep->node);
		cep->node = NULL;
		stc_free(cep->stc);
		cep->stc = NULL;
	}

	if (cep->r_armed) {
		event_del(&cep->revt);
		cep->r_armed = false;
	}
	cep->size = 0;

	if (cep->w_armed) {
		event_del(&cep->wevt);
		cep->w_armed = false;
	}

	cep->key = 0;
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
		applog(LOG_INFO, "stor aborting");

	stc_free(cep->stc);
	cep->stc = NULL;

	rc = stor_new_stc(cep->node, &cep->stc);
	if (rc < 0) {
		stor_node_put(cep->node);
		cep->node = NULL;

		if (debugging)
			applog(LOG_INFO, "Failed to reopen Chunk nid %u (%d)",
			       cep->node->id, rc);

		cep->size = 0;
		cep->done = 0;
		cep->key = 0;
		return;
	}

	if (cep->done != cep->size) {
		sprintf(stckey, stor_key_fmt, (unsigned long long) cep->key);
		stc_delz(cep->stc, stckey);
	}

	if (cep->r_armed) {
		event_del(&cep->revt);
		cep->r_armed = false;
	}

	if (cep->w_armed) {
		event_del(&cep->wevt);
		cep->w_armed = false;
	}

	cep->size = 0;
	cep->done = 0;

	cep->key = 0;
}

ssize_t stor_put_buf(struct open_chunk *cep, void *data, size_t len)
{
	int rc;

	if (cep->done + len > cep->size) {
		applog(LOG_ERR, "Put size %ld remaining %ld",
		       (long) len, (long) (cep->size - cep->done));
		if (cep->done == cep->size)
			return -EIO;	/* will spin otherwise, better error */
		len = cep->size - cep->done;
	}

	if (!cep->stc)
		return -EPIPE;
	rc = stc_put_send(cep->stc, data, len);
	if (rc < len && !cep->w_armed) {
		event_add(&cep->wevt, NULL);
		cep->w_armed = true;
	}
	cep->done += rc;
	return rc;
}

bool stor_put_end(struct open_chunk *cep)
{
	if (!cep->stc)
		return true;
	if (cep->w_armed) {
		event_del(&cep->wevt);
		cep->w_armed = false;
	}
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

	if (cep->done + req_len < cep->done)	/* wrap */
		return -EINVAL;
	if (cep->done + req_len > cep->size)
		xfer_len = cep->size - cep->done;
	else
		xfer_len = req_len;
	if (xfer_len == 0)
		return 0;
	ret = stc_get_recv(cep->stc, data, xfer_len);
	if (ret < 0)
		return -EIO;

	cep->done += ret;
	if (cep->done == cep->size) {
		cep->done = 0;
		cep->size = 0;
	}

	if (xfer_len != ret && cep->size && !cep->r_armed) {
		cep->r_armed = true;
		if (event_add(&cep->revt, NULL))
			cep->r_armed = false;
	}

	return ret;
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
	rc = stc_delz(stc, stckey) ? 0 : -EIO;

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

static struct storage_node *_stor_node_by_nid(uint32_t nid)
{
	struct storage_node *sn;

	list_for_each_entry(sn, &tabled_srv.all_stor, all_link) {
		if (sn->id == nid)
			return sn;
	}
	return NULL;
}

struct storage_node *stor_node_by_nid(uint32_t nid)
{
	struct storage_node *sn;

	g_mutex_lock(tabled_srv.bigmutex);
	sn = _stor_node_by_nid(nid);
	if (sn)
		stor_node_get(sn);
	g_mutex_unlock(tabled_srv.bigmutex);
	return sn;
}

static int stor_add_node_addr(struct storage_node *sn,
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
		applog(LOG_WARNING, "getaddrinfo(%s:%s) failed: %s",
		       hostname, portstr, gai_strerror(rc));
		return -1;
	}

	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family != AF_INET && res->ai_family != AF_INET6)
			continue;

		if (res->ai_addrlen > ADDRSIZE)		/* should not happen */
			continue;

		sn->alen = res->ai_addrlen;
		memcpy(&sn->addr, res->ai_addr, sn->alen);
		sn->addr.sin6_family = res->ai_family;

		/* Use just the first address for now. */
		freeaddrinfo(res0);
		return 0;
	}

	freeaddrinfo(res0);

	applog(LOG_WARNING, "No useful addresses for host %s port %s",
	       hostname, portstr);
	return -1;
}

void stor_add_node(uint32_t nid, const char *hostname, const char *portstr,
		   struct geo *locp)
{
	struct storage_node *sn;

	g_mutex_lock(tabled_srv.bigmutex);
	sn = _stor_node_by_nid(nid);
	if (sn) {
		stor_add_node_addr(sn, hostname, portstr);
	} else {
		if ((sn = malloc(sizeof(struct storage_node))) == NULL) {
			applog(LOG_WARNING, "No core (%ld)",
			       (long) sizeof(struct storage_node));
			g_mutex_unlock(tabled_srv.bigmutex);
			return;
		}
		memset(sn, 0, sizeof(struct storage_node));
		sn->id = nid;

		if ((sn->hostname = strdup(hostname)) == NULL) {
			applog(LOG_WARNING, "No core");
			free(sn);
			g_mutex_unlock(tabled_srv.bigmutex);
			return;
		}

		if (stor_add_node_addr(sn, hostname, portstr)) {
			free(sn->hostname);
			free(sn);
			g_mutex_unlock(tabled_srv.bigmutex);
			return;
		}

		stor_node_get(sn);

		list_add(&sn->all_link, &tabled_srv.all_stor);
		tabled_srv.num_stor++;
	}
	g_mutex_unlock(tabled_srv.bigmutex);
}

/* Return 0 if the node checks out ok */
int stor_node_check(struct storage_node *stn)
{
	struct st_client *stc;
	int rc;

	rc = stor_new_stc(stn, &stc);
	if (rc < 0) {
		applog(LOG_INFO,
		       "Error %d connecting to chunkd on host %s",
		       rc, stn->hostname);
		return -1;
	}

	stc_free(stc);
	return 0;
}

void stor_stats()
{
	struct storage_node *sn;
	time_t now;

	g_mutex_lock(tabled_srv.bigmutex);
	now = time(NULL);
	list_for_each_entry(sn, &tabled_srv.all_stor, all_link) {
		if (sn->last_up) {
			applog(LOG_INFO,
			       "SN: nid %u %s ref %d name %s last %lu (+ %ld)",
			       sn->id, sn->up? "up": "down",
			       sn->ref, sn->hostname,
			       (long) sn->last_up, (long) (now - sn->last_up));
		} else {
			applog(LOG_INFO,
			       "SN: nid %u %s ref %d name %s",
			       sn->id, sn->up? "up": "down",
			       sn->ref, sn->hostname);
		}
	}
	g_mutex_unlock(tabled_srv.bigmutex);
}

bool stor_status(struct client *cli, GList *content)
{
	struct storage_node *sn;
	static char tag_down[] =
		"<span style=\"background-color:red\">down</span>";
	time_t now;
	char *str;
	int rc;

	g_mutex_lock(tabled_srv.bigmutex);
	now = time(NULL);
	list_for_each_entry(sn, &tabled_srv.all_stor, all_link) {
		if (sn->last_up) {
			rc = asprintf(&str,
				     "SN: nid %u %s ref %d name %s"
				     " last %lu (+ %ld)<br />\r\n",
				     sn->id, sn->up? "up": tag_down,
				     sn->ref, sn->hostname,
				     (long) sn->last_up,
				     (long) (now - sn->last_up));
		} else {
			rc = asprintf(&str,
				     "SN: nid %u %s ref %d name %s<br />\r\n",
				     sn->id, sn->up? "up": tag_down,
				     sn->ref, sn->hostname);
		}
		if (rc < 0)
			break;
		content = g_list_append(content, str);
	}
	g_mutex_unlock(tabled_srv.bigmutex);
	return true;
}

