
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
#include <sys/time.h>
#include <glib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <event.h>
#include <errno.h>
#include <cldc.h>
#include <elist.h>
#include "tabled.h"

#define ALIGN8(n)	((8 - ((n) & 7)) & 7)

struct chunk_node {
	struct list_head link;
	char name[65];
};

#define N_CLD		10	/* 5 * (v4+v6) */

struct cld_host {
	int known;
	struct cldc_host h;
};

struct cld_session {
	bool forced_hosts;		/* Administrator overrode default CLD */
	bool sess_open;
	struct cldc_udp *lib;		/* library state */
	struct event lib_timer;
	int retry_cnt;
	int last_recv_err;

	/*
	 * For code sanity and being isomorphic with conventional programming
	 * using sleep(), neither of the timers must ever be active simultane-
	 * ously with any other. But using one timer structure is too annoying.
	 */
	struct event tm_retry;
	struct event tm_rescan;
	struct event tm_reopen;

	int actx;		/* Active host cldv[actx] */
	struct cld_host cldv[N_CLD];

	char *thisgroup;
	char *thishost;
	struct event ev;	/* Associated with fd */
	char *cfname;		/* /tabled-group directory */
	struct cldc_fh *cfh;	/* /tabled-group directory, keep open for scan */
	char *ffname;		/* /tabled-group/thishost */
	struct cldc_fh *ffh;	/* /tabled-group/thishost, keep open for lock */
	char *xfname;		/* /chunk-GROUP directory */
	struct cldc_fh *xfh;	/* /chunk-GROUP directory */
	char *yfname;		/* /chunk-GROUP/NID file */
	struct cldc_fh *yfh;	/* /chunk-GROUP/NID file */

	struct list_head chunks;	/* found in xfname, struct chunk_node */
};

static int cldu_set_cldc(struct cld_session *sp, int newactive);
static int cldu_new_sess(struct cldc_call_opts *carg, enum cle_err_codes errc);
static int cldu_open_c_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static int cldu_open_f_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static int cldu_lock_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static int cldu_put_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static int cldu_get_1_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static void try_open_x(struct cld_session *sp);
static int cldu_open_x_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static int cldu_get_x_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static int cldu_close_x_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static void next_chunk(struct cld_session *sp);
static int cldu_open_y_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static int cldu_get_y_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static int cldu_close_y_cb(struct cldc_call_opts *carg, enum cle_err_codes errc);
static void add_remote(const char *name);
static void add_chunk_node(struct cld_session *sp, const char *name);

static struct timeval cldu_retry_delay = { 5, 0 };
static struct timeval cldu_rescan_delay = { 50, 0 };
static struct timeval cldu_reopen_delay = { 3, 0 };

struct hail_log cldu_hail_log = {
	.func		= applog,
};

/*
 * Identify the next host to be tried.
 *
 * In theory we should at least look at priorities, if not weights. Maybe later.
 */
static int cldu_nextactive(struct cld_session *sp)
{
	int i;
	int n;

	if ((n = sp->actx + 1) >= N_CLD)
		n = 0;
	for (i = 0; i < N_CLD; i++) {
		if (sp->cldv[n].known)
			return n;
		if (++n >= N_CLD)
			n = 0;
	}
	/* Full circle, end on the old actx */
	return sp->actx;
}

/*
 * Notice that for now we use the same group name for both tabled and the
 * chunkservers that it uses, so this function only takes one group argument.
 */
static int cldu_setgroup(struct cld_session *sp,
			const char *thisgroup, const char *thishost)
{
	char *mem;

	if (thisgroup == NULL) {
		thisgroup = "default";
	}

	sp->thisgroup = strdup(thisgroup);
	if (!sp->thisgroup)
		goto err_oom;
	sp->thishost = strdup(thishost);
	if (!sp->thishost)
		goto err_oom;

	if (asprintf(&mem, "/tabled-%s", thisgroup) == -1)
		goto err_oom;
	sp->cfname = mem;

	if (asprintf(&mem, "/tabled-%s/%s", thisgroup, thishost) == -1)
		goto err_oom;
	sp->ffname = mem;

	if (asprintf(&mem, "/chunk-%s", thisgroup) == -1)
		goto err_oom;
	sp->xfname = mem;

	return 0;

err_oom:
	applog(LOG_WARNING, "OOM in cldu");
	return 0;
}

static void cldu_tm_retry(int fd, short events, void *userdata)
{
	struct cld_session *sp = userdata;

	if (++sp->retry_cnt >= 5) {
		applog(LOG_INFO, "Out of retries for %s, bailing", sp->xfname);
		exit(1);
	}
	if (debugging)
		applog(LOG_DEBUG, "Trying to open %s", sp->xfname);
	try_open_x(sp);
}

static void cldu_tm_rescan(int fd, short events, void *userdata)
{
	struct cld_session *sp = userdata;

	/* Add rescanning for tabled nodes as well. FIXME */
	if (debugging)
		applog(LOG_DEBUG, "Rescanning for Chunks in %s", sp->xfname);
	try_open_x(sp);
}

static void cldu_tm_reopen(int fd, short events, void *userdata)
{
	struct cld_session *sp = userdata;

	if (debugging)
		applog(LOG_DEBUG, "Trying to reopen %d storage nodes",
		       tabled_srv.num_stor);
	if (stor_update_cb() < 1)
		evtimer_add(&sp->tm_reopen, &cldu_reopen_delay);
}

static void cldu_event(int fd, short events, void *userdata)
{
	struct cld_session *sp = userdata;
	int rc;

	if (!sp->lib) {
		applog(LOG_WARNING, "Stray UDP event");
		return;
	}

	rc = cldc_udp_receive_pkt(sp->lib);
	if (rc) {
		if (rc != sp->last_recv_err) {
			if (rc < -1000)		/* our internal code */
				applog(LOG_INFO,
				       "cldc_udp_receive_pkt failed: %d", rc);
			else
				applog(LOG_INFO,
				       "cldc_udp_receive_pkt failed: %s",
				       strerror(-rc));
			sp->last_recv_err = rc;
		}
		/*
		 * Reacting to ICMP messages is a bad idea, because
		 *  - it makes us loop hard in case CLD is down, unless we
		 *    insert additional tricky timeouts
		 *  - it deals poorly with transient problems like CLD reboots
		 */
#if 0
		if (rc == -ECONNREFUSED) {	/* ICMP tells us */
			int newactive;
			// evtimer_del(&sp->tm);
			cldc_kill_sess(sp->lib->sess);
			sp->lib->sess = NULL;
			newactive = cldu_nextactive(sp);
			if (cldu_set_cldc(sp, newactive))
				return;
			// evtimer_add(&sp->tm, &cldc_to_delay);
		}
		return;
#endif
	}
}

static bool cldu_p_timer_ctl(void *priv, bool add,
			     int (*cb)(struct cldc_session *, void *),
			     void *cb_priv, time_t secs)
{
	struct cld_session *sp = priv;
	struct cldc_udp *udp = sp->lib;
	struct timeval tv = { secs, 0 };

	if (add) {
		udp->cb = cb;
		udp->cb_private = cb_priv;
		return evtimer_add(&sp->lib_timer, &tv) == 0;
	} else {
		return evtimer_del(&sp->lib_timer) == 0;
	}
}

static int cldu_p_pkt_send(void *priv, const void *addr, size_t addrlen,
			       const void *buf, size_t buflen)
{
	struct cld_session *sp = priv;
	return cldc_udp_pkt_send(sp->lib, addr, addrlen, buf, buflen);
}

static void cldu_udp_timer_event(int fd, short events, void *userdata)

{
	struct cld_session *sp = userdata;
	struct cldc_udp *udp = sp->lib;

	if (udp->cb)
		udp->cb(udp->sess, udp->cb_private);
}

static void cldu_p_event(void *priv, struct cldc_session *csp,
			 struct cldc_fh *fh, uint32_t what)
{
	struct cld_session *sp = priv;
	int newactive;

	if (what == CE_SESS_FAILED) {
		sp->sess_open = false;
		if (sp->lib->sess != csp)
			applog(LOG_ERR, "Stray session failed, sid " SIDFMT,
			       SIDARG(csp->sid));
		else
			applog(LOG_ERR, "Session failed, sid " SIDFMT,
			       SIDARG(csp->sid));
		// evtimer_del(&sp->tm);
		sp->lib->sess = NULL;
		newactive = cldu_nextactive(sp);
		if (cldu_set_cldc(sp, newactive))
			return;
		// evtimer_add(&sp->tm, &cldc_to_delay);
	} else {
		if (csp)
			applog(LOG_INFO, "cldc event 0x%x sid " SIDFMT,
			       what, SIDARG(csp->sid));
		else
			applog(LOG_INFO, "cldc event 0x%x no sid", what);
	}
}

static struct cldc_ops cld_ops = {
	.timer_ctl =	cldu_p_timer_ctl,
	.pkt_send =	cldu_p_pkt_send,
	.event =	cldu_p_event,
	.errlog =	applog,
};

/*
 * Open the library, start its session, and reguster its socket with libevent.
 * Our session remains consistent in case of an error in this function,
 * so that we can continue and retry meaningfuly.
 */
static int cldu_set_cldc(struct cld_session *sp, int newactive)
{
	struct cldc_host *hp;
	struct cldc_udp *lib;
	struct cldc_call_opts copts;
	int rc;

	if (sp->lib) {
		event_del(&sp->ev);
		cldc_udp_free(sp->lib);
		sp->lib = NULL;
	}

	sp->actx = newactive;
	if (!sp->cldv[sp->actx].known) {
		applog(LOG_ERR, "No CLD hosts");
		goto err_addr;
	}
	hp = &sp->cldv[sp->actx].h;

	evtimer_set(&sp->lib_timer, cldu_udp_timer_event, sp);

	rc = cldc_udp_new(hp->host, hp->port, &sp->lib);
	if (rc) {
		applog(LOG_ERR, "cldc_udp_new(%s,%u) error: %d",
		       hp->host, hp->port, rc);
		goto err_lib_new;
	}
	lib = sp->lib;

	if (debugging)
		applog(LOG_INFO, "Selected CLD host %s port %u",
		       hp->host, hp->port);

	/*
	 * This is a little iffy: we assume that it's ok to re-issue
	 * event_set() for an event that was unregistered with event_del().
	 * In any case, there's no other way to set the file descriptor.
	 */
	event_set(&sp->ev, sp->lib->fd, EV_READ | EV_PERSIST, cldu_event, sp);

	if (event_add(&sp->ev, NULL) < 0) {
		applog(LOG_INFO, "Failed to add CLD event");
		goto err_event;
	}

	memset(&copts, 0, sizeof(struct cldc_call_opts));
	copts.cb = cldu_new_sess;
	copts.private = sp;
	rc = cldc_new_sess(&cld_ops, &copts, lib->addr, lib->addr_len,
			   "tabled", "tabled", sp, &lib->sess);
	if (rc) {
		applog(LOG_INFO,
		       "Failed to start CLD session on host %s port %u",
		       hp->host, hp->port);
		goto err_sess;
	}

	// if (debugging)
	//	lib->sess->verbose = true;

	return 0;

err_sess:
err_event:
	cldc_udp_free(sp->lib);
	sp->lib = NULL;
err_lib_new:
err_addr:
	return -1;
}

static int cldu_new_sess(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		applog(LOG_INFO, "New CLD session creation failed: %d", errc);
		return 0;
	}

	sp->sess_open = true;
	applog(LOG_INFO, "New CLD session created, sid " SIDFMT,
	       SIDARG(sp->lib->sess->sid));

	/*
	 * First, make sure the base directory exists.
	 */
	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_open_c_cb;
	copts.private = sp;
	rc = cldc_open(sp->lib->sess, &copts, sp->cfname,
		       COM_READ | COM_WRITE | COM_CREATE | COM_DIRECTORY,
		       CE_MASTER_FAILOVER | CE_SESS_FAILED, &sp->cfh);
	if (rc) {
		applog(LOG_ERR, "cldc_open(%s) call error: %d", sp->cfname, rc);
	}
	return 0;
}

static int cldu_open_c_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		applog(LOG_ERR, "CLD open(%s) failed: %d", sp->cfname, errc);
		return 0;
	}
	if (sp->cfh == NULL) {
		applog(LOG_ERR, "CLD open(%s) failed: NULL fh", sp->cfname);
		return 0;
	}
	if (!sp->cfh->valid) {
		applog(LOG_ERR, "CLD open(%s) failed: invalid fh", sp->cfname);
		return 0;
	}

	if (debugging)
		applog(LOG_DEBUG, "CLD directory \"%s\" created", sp->cfname);

	/*
	 * Then, create the membership file for us.
	 */
	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_open_f_cb;
	copts.private = sp;
	rc = cldc_open(sp->lib->sess, &copts, sp->ffname,
		       COM_WRITE | COM_LOCK | COM_CREATE,
		       CE_MASTER_FAILOVER | CE_SESS_FAILED, &sp->ffh);
	if (rc) {
		applog(LOG_ERR, "cldc_open(%s) call error: %d", sp->ffname, rc);
	}
	return 0;
}

static int cldu_open_f_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		applog(LOG_ERR, "CLD open(%s) failed: %d", sp->ffname, errc);
		return 0;
	}
	if (sp->ffh == NULL) {
		applog(LOG_ERR, "CLD open(%s) failed: NULL fh", sp->ffname);
		return 0;
	}
	if (!sp->ffh->valid) {
		applog(LOG_ERR, "CLD open(%s) failed: invalid fh", sp->ffname);
		return 0;
	}

	if (debugging)
		applog(LOG_DEBUG, "CLD file \"%s\" created", sp->ffname);

	/*
	 * Lock the file, in case two hosts got the same hostname.
	 */
	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_lock_cb;
	copts.private = sp;
	rc = cldc_lock(sp->ffh, &copts, 0, false);
	if (rc) {
		applog(LOG_ERR, "cldc_lock call error %d", rc);
	}

	return 0;
}

static int cldu_lock_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	char buf[100];
	int len;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		applog(LOG_ERR, "CLD lock(%s) failed: %d", sp->ffname, errc);
		return 0;
	}

	/*
	 * Write the file with our connection parameters.
	 */
	len = snprintf(buf, sizeof(buf), "port: %u\n", tabled_srv.rep_port);
	if (len >= sizeof(buf)) {
		applog(LOG_ERR,
		       "internal error: overflow in cldu_lock_cb (%d)", len);
		return 0;
	}

	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_put_cb;
	copts.private = sp;
	rc = cldc_put(sp->ffh, &copts, buf, len);
	if (rc) {
		applog(LOG_ERR, "cldc_put(%s) call error: %d", sp->ffname, rc);
	}

	return 0;
}

static int cldu_put_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		applog(LOG_ERR, "CLD put(%s) failed: %d", sp->ffname, errc);
		return 0;
	}

	/*
	 * Read the directory.
	 */
	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_get_1_cb;
	copts.private = sp;
	rc = cldc_get(sp->cfh, &copts, false);
	if (rc) {
		applog(LOG_ERR, "cldc_get(%s) call error: %d", sp->cfname, rc);
	}

	return 0;
}

static int cldu_get_1_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	char *ptr;
	size_t dir_len;
	int total_len, rec_len, name_len;
	char buf[65];

	if (errc != CLE_OK) {
		applog(LOG_ERR, "CLD get(%s) failed: %d", sp->cfname, errc);
		return 0;
	}

	if (debugging)
		applog(LOG_DEBUG, "Known tabled nodes");

	cldc_call_opts_get_data(carg, &ptr, &dir_len);
	while (dir_len) {
		name_len = GUINT16_FROM_LE(*(uint16_t *)ptr);
		rec_len = name_len + 2;
		total_len = rec_len + ALIGN8(rec_len);

		strncpy(buf, ptr+2, 64);
		if (name_len < 64)
			buf[name_len] = 0;
		else
			buf[64] = 0;

		if (!strcmp(buf, sp->thishost)) {
			if (debugging)
				applog(LOG_DEBUG, " %s (ourselves)", buf);
		} else {
			if (debugging)
				applog(LOG_DEBUG, " %s", buf);
			add_remote(buf);
		}

		ptr += total_len;
		dir_len -= total_len;
	}

	/*
	 * If configuration gives us storage nodes, we shortcut scanning
	 * of CLD, because:
	 *  - the scanning may fail, and we should not care
	 *  - NIDs for configured nodes are auto-assigned and may conflict
	 * This will go away with the demise of <StorageNode>.
	 */
	if (tabled_srv.num_stor) {
		if (debugging)
			applog(LOG_DEBUG, "Trying to open %d storage nodes",
			       tabled_srv.num_stor);
		if (stor_update_cb() < 1) {
			evtimer_add(&sp->tm_reopen, &cldu_reopen_delay);
		}
		return 0;
	}

	sp->retry_cnt = 0;
	try_open_x(sp);
	return 0;
}

/*
 * Open the xfname, so we can collect registered Chunk servers.
 */
static void try_open_x(struct cld_session *sp)
{
	struct cldc_call_opts copts;
	int rc;

	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_open_x_cb;
	copts.private = sp;
	rc = cldc_open(sp->lib->sess, &copts, sp->xfname,
		       COM_READ | COM_DIRECTORY,
		       CE_MASTER_FAILOVER | CE_SESS_FAILED, &sp->xfh);
	if (rc) {
		applog(LOG_ERR, "cldc_open(%s) call error: %d", sp->xfname, rc);
	}
}

static int cldu_open_x_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		if (errc == CLE_INODE_INVAL || errc == CLE_NAME_INVAL) {
			applog(LOG_ERR, "%s: open failed, retrying",
			       sp->xfname);
			evtimer_add(&sp->tm_retry, &cldu_retry_delay);
		} else {
			applog(LOG_ERR, "CLD open(%s) failed: %d",
			       sp->xfname, errc);
			/* XXX we're dead, why not exit(1) right away? */
		}
		return 0;
	}
	if (sp->xfh == NULL) {
		applog(LOG_ERR, "CLD open(%s) failed: NULL fh", sp->xfname);
		return 0;
	}
	if (!sp->xfh->valid) {
		applog(LOG_ERR, "CLD open(%s) failed: invalid fh", sp->xfname);
		return 0;
	}

	/*
	 * Read the directory.
	 */
	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_get_x_cb;
	copts.private = sp;
	rc = cldc_get(sp->xfh, &copts, false);
	if (rc) {
		applog(LOG_ERR, "cldc_get(%s) call error: %d", sp->cfname, rc);
	}
	return 0;
}

static int cldu_get_x_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	struct cldc_call_opts copts;
	int rc;
	char *ptr;
	size_t dir_len;
	int total_len, rec_len, name_len;
	char buf[65];

	if (errc != CLE_OK) {
		applog(LOG_ERR, "CLD get(%s) failed: %d", sp->xfname, errc);
		return 0;
	}

	if (debugging)
		applog(LOG_DEBUG, "Known Chunk nodes");

	cldc_call_opts_get_data(carg, &ptr, &dir_len);
	while (dir_len) {
		name_len = GUINT16_FROM_LE(*(uint16_t *)ptr);
		rec_len = name_len + 2;
		total_len = rec_len + ALIGN8(rec_len);

		strncpy(buf, ptr+2, 64);
		if (name_len < 64)
			buf[name_len] = 0;
		else
			buf[64] = 0;

		if (debugging)
			applog(LOG_DEBUG, " %s", buf);
		add_chunk_node(sp, buf);

		ptr += total_len;
		dir_len -= total_len;
	}

	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_close_x_cb;
	copts.private = sp;
	rc = cldc_close(sp->xfh, &copts);
	if (rc) {
		applog(LOG_ERR, "cldc_close call error %d", rc);
	}
	return 0;
}

static int cldu_close_x_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	// struct cldc_call_opts copts;
	// int rc;

	if (errc != CLE_OK) {
		applog(LOG_ERR, "CLD close(%s) failed: %d", sp->xfname, errc);
		return 0;
	}

	if (list_empty(&sp->chunks)) {
		applog(LOG_INFO, "%s: No Chunk nodes found, retrying",
		       sp->xfname);
		if (evtimer_add(&sp->tm_retry, &cldu_retry_delay) != 0) {
			applog(LOG_ERR, "evtimer_add error %s",
			       strerror(errno));
		}
	} else {
		next_chunk(sp);
	}
	return 0;
}

static void next_chunk(struct cld_session *sp)
{
	struct chunk_node *np;
	char *mem;
	struct cldc_call_opts copts;
	int rc;

	np = list_entry(sp->chunks.next, struct chunk_node, link);

	if (asprintf(&mem, "/chunk-%s/%s", sp->thisgroup, np->name) == -1) {
		applog(LOG_WARNING, "OOM in cldu");
		return;
	}
	sp->yfname = mem;

	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_open_y_cb;
	copts.private = sp;
	rc = cldc_open(sp->lib->sess, &copts, sp->yfname,
		       COM_READ,
		       CE_MASTER_FAILOVER | CE_SESS_FAILED, &sp->yfh);
	if (rc) {
		applog(LOG_ERR, "cldc_open(%s) call error: %d", sp->yfname, rc);
	}
}

static int cldu_open_y_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	struct cldc_call_opts copts;
	int rc;

	if (errc != CLE_OK) {
		applog(LOG_ERR, "CLD open(%s) failed: %d", sp->yfname, errc);
		free(sp->yfname);
		sp->yfname = NULL;
		return 0;
	}
	if (sp->yfh == NULL) {
		applog(LOG_ERR, "CLD open(%s) failed: NULL fh", sp->yfname);
		free(sp->yfname);
		sp->yfname = NULL;
		return 0;
	}
	if (!sp->yfh->valid) {
		applog(LOG_ERR, "CLD open(%s) failed: invalid fh", sp->yfname);
		free(sp->yfname);
		sp->yfname = NULL;
		return 0;
	}

	/*
	 * Read the Chunk's parameter file.
	 */
	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_get_y_cb;
	copts.private = sp;
	rc = cldc_get(sp->yfh, &copts, false);
	if (rc) {
		applog(LOG_ERR, "cldc_get(%s) call error: %d", sp->yfname, rc);
	}
	return 0;
}

static int cldu_get_y_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	struct cldc_call_opts copts;
	int rc;
	char *ptr;
	size_t len;

	if (errc != CLE_OK) {
		applog(LOG_ERR, "CLD get(%s) failed: %d", sp->yfname, errc);
		goto close_and_next;	/* spaghetti */
	}

	cldc_call_opts_get_data(carg, &ptr, &len);
	stor_parse(sp->yfname, ptr, len);

close_and_next:
	memset(&copts, 0, sizeof(copts));
	copts.cb = cldu_close_y_cb;
	copts.private = sp;
	rc = cldc_close(sp->yfh, &copts);
	if (rc) {
		applog(LOG_ERR, "cldc_close call error %d", rc);
	}
	return 0;
}

static int cldu_close_y_cb(struct cldc_call_opts *carg, enum cle_err_codes errc)
{
	struct cld_session *sp = carg->private;
	struct chunk_node *np;
	// struct cldc_call_opts copts;
	// int rc;

	if (errc != CLE_OK) {
		applog(LOG_ERR, "CLD close(%s) failed: %d", sp->yfname, errc);
		return 0;
	}

	free(sp->yfname);
	sp->yfname = NULL;

	np = list_entry(sp->chunks.next, struct chunk_node, link);
	list_del(&np->link);

	if (!list_empty(&sp->chunks)) {
		next_chunk(sp);
		return 0;
	}

	/*
	 * No more chunks to consider in this cycle, we're all done.
	 * Now, poke the dispatch about the possible changes in the
	 * configuration of Chunk.
	 *
	 * It's possible that the CLD directories are full of all garbage,
	 * but no useable Chunk servers. In that case, treat everything
	 * like a usual retry.
	 *
	 * For the case of normal operation, we also set up a rescan, for now.
	 * In the future, we'll subscribe for change notification. FIXME.
	 */
	if (stor_update_cb()) {
		evtimer_add(&sp->tm_rescan, &cldu_rescan_delay);
	} else {
		if (evtimer_add(&sp->tm_retry, &cldu_retry_delay) != 0) {
			applog(LOG_ERR, "evtimer_add error %s",
			       strerror(errno));
		}
	}
	return 0;
}

/*
 * FIXME need to read port number from the file (port:<space>num).
 */
static void add_remote(const char *name)
{
	struct db_remote *rp;

	rp = malloc(sizeof(struct db_remote));
	if (!rp)
		return;

	rp->port = 8083;
	rp->host = strdup(name);
	if (!rp->host) {
		free(rp);
		return;
	}

	tabled_srv.rep_remotes = g_list_append(tabled_srv.rep_remotes, rp);
}

/*
 * Save the available chunk numbers into a local list temporarily,
 * because we don't want to hog the event thread with reading.
 */
static void add_chunk_node(struct cld_session *sp, const char *name)
{
	struct chunk_node *np;

	np = malloc(sizeof(*np));
	if (!np)
		return;

	strncpy(np->name, name, sizeof(np->name)-1);
	np->name[sizeof(np->name)-1] = 0;
	list_add_tail(&np->link, &sp->chunks);
}

/*
 */
static struct cld_session ses;

/*
 * Global and 1-instance initialization.
 */
void cld_init()
{
	cldc_init();

	// memset(&ses, 0, sizeof(struct cld_session));
	INIT_LIST_HEAD(&ses.chunks);
}

/*
 * This initiates our sole session with a CLD instance.
 */
int cld_begin(const char *thishost, const char *thisgroup)
{
	static struct cld_session *sp = &ses;

	evtimer_set(&ses.tm_retry, cldu_tm_retry, &ses);
	evtimer_set(&ses.tm_rescan, cldu_tm_rescan, &ses);
	evtimer_set(&ses.tm_reopen, cldu_tm_reopen, &ses);

	if (cldu_setgroup(sp, thisgroup, thishost)) {
		/* Already logged error */
		goto err_group;
	}

	if (!sp->forced_hosts) {
		GList *tmp, *host_list = NULL;
		int i;

		if (cldc_getaddr(&host_list, thishost, &cldu_hail_log)) {
			/* Already logged error */
			goto err_addr;
		}

		/* copy host_list into cld_session host array,
		 * taking ownership of alloc'd strings along the way
		 */
		i = 0;
		for (tmp = host_list; tmp; tmp = tmp->next) {
			struct cldc_host *hp = tmp->data;
			if (i < N_CLD) {
				memcpy(&sp->cldv[i].h, hp,
				       sizeof(struct cldc_host));
				sp->cldv[i].known = 1;
				i++;
			} else {
				free(hp->host);
			}
			free(hp);
		}

		g_list_free(host_list);
	}

	/*
	 * FIXME: We should find next suitable host according to
	 * the priority and weight (among those which are up).
	 * -- Actually, it only works when recovering from CLD failure.
	 *    Thereafter, any slave CLD redirects us to the master.
	 */
	if (cldu_set_cldc(sp, 0)) {
		/* Already logged error */
		goto err_net;
	}

	return 0;

err_net:
err_addr:
err_group:
	return -1;
}

void cldu_add_host(const char *hostname, unsigned int port)
{
	static struct cld_session *sp = &ses;
	struct cld_host *hp;
	int i;

	for (i = 0; i < N_CLD; i++) {
		hp = &sp->cldv[i];
		if (!hp->known)
			break;
	}
	if (i >= N_CLD)
		return;

	if (cldc_saveaddr(&hp->h, 100, 100, port, strlen(hostname), hostname,
			  &cldu_hail_log))
		return;
	hp->known = 1;

	sp->forced_hosts = true;
}

void cld_end(void)
{
	static struct cld_session *sp = &ses;
	int i;

	if (sp->lib) {
		event_del(&sp->ev);
		// if (sp->sess_open)	/* kill it always, include half-open */
		cldc_kill_sess(sp->lib->sess);
		cldc_udp_free(sp->lib);
		sp->lib = NULL;
	}

	if (!sp->forced_hosts) {
		for (i = 0; i < N_CLD; i++) {
			if (sp->cldv[i].known) {
				free(sp->cldv[i].h.host);
				sp->cldv[i].known = false;
			}
		}
	}

	evtimer_del(&sp->tm_retry);
	evtimer_del(&sp->tm_rescan);
	evtimer_del(&sp->tm_reopen);

	free(sp->cfname);
	sp->cfname = NULL;
	free(sp->ffname);
	sp->ffname = NULL;
	free(sp->xfname);
	sp->xfname = NULL;
	free(sp->yfname);
	sp->yfname = NULL;
	free(sp->thisgroup);
	sp->thisgroup = NULL;
	free(sp->thishost);
	sp->thishost = NULL;
}
