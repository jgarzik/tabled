
/*
 * Copyright 2010 Red Hat, Inc.
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
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <glib.h>
#include <event.h>
#include <chunkc.h>
#include "tabled.h"

static const char stor_key_fmt[] = STOR_KEY_FMT;

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

/*
 * Open *cep using stn, set up chunk session if needed.
 */
static int chunk_open(struct open_chunk *cep, struct storage_node *stn,
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

static int chunk_put_start(struct open_chunk *cep,
			   void (*cb)(struct open_chunk *),
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
		applog(LOG_INFO, "stor nid %u put %s size %lld",
		       cep->node->id, stckey, (long long) size);

	return 0;
}

static int chunk_open_read(struct open_chunk *cep,
			   void (*cb)(struct open_chunk *),
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
static void chunk_close(struct open_chunk *cep)
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
 * There's no "abort" call for an existing transfer. We could complete
 * the transfer instead of trashing the whole session, but that may involve
 * sending or receiving gigabytes. So we just cycle the session.
 */
static void chunk_abort(struct open_chunk *cep)
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

static ssize_t chunk_put_buf(struct open_chunk *cep, void *data, size_t len)
{
	int rc;

	if (cep->done + len > cep->size) {
		/* P3 */ applog(LOG_ERR, "Put length %ld remaining %ld",
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

static bool chunk_put_end(struct open_chunk *cep)
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
static ssize_t chunk_get_buf(struct open_chunk *cep, void *data, size_t req_len)
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

static int chunk_obj_del(struct storage_node *stn, uint64_t key)
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

/*
 * XXX WTF?! This accidentially tests a node instead of object! FIXME
 */
static bool chunk_obj_test(struct open_chunk *cep, uint64_t key)
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

/* Return 0 if the node checks out ok */
static int chunk_node_check(struct storage_node *stn)
{
	struct st_client *stc;
	int rc;

	if (!stn->hostname)
		return -1;

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

struct st_node_ops stor_ops_chunk = {
	.open =		chunk_open,
	.open_read =	chunk_open_read,
	.close =	chunk_close,
	.abort =	chunk_abort,
	.put_start =	chunk_put_start,
	.put_buf =	chunk_put_buf,
	.put_end =	chunk_put_end,
	.get_buf =	chunk_get_buf,
	.obj_del =	chunk_obj_del,
	.obj_test =	chunk_obj_test,
	.node_check =	chunk_node_check,
};

