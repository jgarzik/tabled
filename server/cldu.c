
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
#include <elist.h>
#include <ncld.h>
#include "tabled.h"

#define ALIGN8(n)	((8 - ((n) & 7)) & 7)

#define MASTER_FILE	"MASTER"

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
	bool is_dead;
	struct ncld_sess *nsp;		/* library state */

	/*
	 * For code sanity and being isomorphic with conventional programming
	 * using sleep(), neither of the timers must ever be active simultane-
	 * ously with any other. But using one timer structure is too annoying.
	 */
	// struct event tm_relock;
	struct event tm_rescan;

	int actx;		/* Active host cldv[actx] */
	struct cld_host cldv[N_CLD];

	char *thisname;
	char *thisgroup;
	char *cfname;		/* /tabled-group directory */
	struct ncld_fh *cfh;	/* /tabled-group directory, keep open for scan */
	char *ffname;		/* /tabled-group/thisname */
	struct ncld_fh *ffh;	/* /tabled-group/thisname, keep open for lock */
	char *mfname;		/* /tabled-group/MASTER */
	struct ncld_fh *mfh;	/* /tabled-group/MASTER, keep open for lock */
	char *xfname;		/* /chunk-GROUP directory */

	struct list_head chunks;	/* found in xfname, struct chunk_node */
};

static int cldu_set_cldc(struct cld_session *sp, int newactive);
static int scan_peers(struct cld_session *sp);
static int scan_chunks(struct cld_session *sp);
static void next_chunk(struct cld_session *sp, struct chunk_node *np);
static void add_remote(const char *name);
static void add_chunk_node(struct cld_session *sp, const char *name);

static struct timeval cldu_rescan_delay = { 50, 0 };

static struct hail_log cldu_hail_log = {
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
			 const char *thisgroup, const char *thisname)
{
	char *mem;

	if (thisgroup == NULL) {
		thisgroup = "default";
	}

	sp->thisgroup = strdup(thisgroup);
	if (!sp->thisgroup)
		goto err_oom;
	sp->thisname = strdup(thisname);
	if (!sp->thisname)
		goto err_oom;

	if (asprintf(&mem, "/tabled-%s", thisgroup) == -1)
		goto err_oom;
	sp->cfname = mem;

	if (asprintf(&mem, "/tabled-%s/%s", thisgroup, thisname) == -1)
		goto err_oom;
	sp->ffname = mem;

	if (asprintf(&mem, "/tabled-%s/%s", thisgroup, MASTER_FILE) == -1)
		goto err_oom;
	sp->mfname = mem;

	if (asprintf(&mem, "/chunk-%s", thisgroup) == -1)
		goto err_oom;
	sp->xfname = mem;

	return 0;

err_oom:
	applog(LOG_WARNING, "OOM in cldu");
	return 0;
}

/*
 * Ugh, side effects on tabled_srv.rep_master.
 */
static void cldu_parse_master(const char *mfname, const char *mfile, long len)
{
	enum lex_state { lex_tag, lex_colon, lex_val };
	const char *tag, *val;
	int taglen;
	const char *name, *host, *port;
	int namelen, hostlen, portlen;
	char namebuf[65], hostbuf[65], portbuf[15];
	long portnum;
	enum lex_state state;
	struct db_remote *rp;
	const char *p;
	char c;

	name = NULL;
	namelen = 0;
	host = NULL;
	hostlen = 0;
	port = NULL;
	portlen = 0;

	p = mfile;
	tag = p;
	val = NULL;
	state = lex_tag;
	for (;;) {
		if (p >= mfile+len)
			break;
		c = *p++;
		if (state == lex_tag) {
			if (c == ':') {
				val = p;
				state = lex_colon;
				taglen = (p-1) - tag;
			} else if (c == '\n') {
				if (debugging)
					applog(LOG_DEBUG,
					       "%s: No colon", mfname);
				tag = p;
				val = NULL;
				state = lex_tag;
			}
		} else if (state == lex_colon) {
			if (c == ' ') {
				val = p;
			} else if (c == '\n') {
				if (debugging)
					applog(LOG_DEBUG,
					       "%s: Empty value", mfname);
				tag = p;
				val = NULL;
				state = lex_tag;
			} else {
				state = lex_val;
			}
		} else if (state == lex_val) {
			if (c == '\n') {
				if (taglen == sizeof("name")-1 &&
				    memcmp(tag, "name", taglen) == 0) {
					name = val;
					namelen = (p-1) - val;
				} else if (taglen == sizeof("host")-1 &&
				    memcmp(tag, "host", taglen) == 0) {
					host = val;
					hostlen = (p-1) - val;
				} else if (taglen == sizeof("port")-1 &&
				    memcmp(tag, "port", taglen) == 0) {
					port = val;
					portlen = (p-1) - val;
				} else {
					if (debugging)
						applog(LOG_DEBUG,
						       "%s: Unknown tag %c[%d]",
						       mfname, tag[0], taglen);
				}
				tag = p;
				val = NULL;
				state = lex_tag;
			}
		} else {
			return;
		}
	}

	if (!name || !namelen) {
		if (debugging)
			applog(LOG_DEBUG, "%s: No name", mfname);
		return;
	}
	if (namelen >= sizeof(namebuf)) {
		applog(LOG_ERR, "Long master name");
		return;
	}
	memcpy(namebuf, name, namelen);
	namebuf[namelen] = 0;

	if (!host || !hostlen) {
		if (debugging)
			applog(LOG_DEBUG, "%s: No host", mfname);
		hostlen = 0;
	}
	if (!port || !portlen) {
		if (debugging)
			applog(LOG_DEBUG, "%s: No port", mfname);
		portlen = 0;
	}

	if (hostlen != 0 && portlen != 0) {

		if (hostlen >= sizeof(hostbuf)) {
			applog(LOG_ERR, "Long host");
			return;
		}
		memcpy(hostbuf, host, hostlen);
		hostbuf[hostlen] = 0;

		if (portlen >= sizeof(portbuf)) {
			applog(LOG_ERR, "Long port");
			return;
		}
		memcpy(portbuf, port, portlen);
		portbuf[portlen] = 0;
		portnum = strtol(port, NULL, 10);
		if (portnum <= 0 || portnum >= 65536) {
			applog(LOG_ERR, "Bad port %s", portbuf);
			return;
		}

		rp = tdb_find_remote_byname(namebuf);
		if (!rp) {
			if (debugging)
				applog(LOG_DEBUG, "%s: Not found master %s",
				       mfname, namebuf);
			return;
		}
		if (debugging)
			applog(LOG_DEBUG, "Found master %s host %s port %u",
			       namebuf, hostbuf, portnum);

		free(rp->host);
		rp->host = strdup(hostbuf);
		rp->port = portnum;
		if (!rp->host)
			return;
	} else {

		rp = tdb_find_remote_byname(namebuf);
		if (!rp) {
			if (debugging)
				applog(LOG_DEBUG, "%s: Not found master %s",
				       mfname, namebuf);
			return;
		}
		if (debugging)
			applog(LOG_DEBUG, "Found master %s", namebuf);

		/*
		 * At this point some other node owns the MASTER file, but
		 * it did not supply the host and port. There is no reason
		 * to rely on obsolete contact information, so remove it.
		 */
		free(rp->host);
		rp->host = NULL;
		rp->port = 0;
	}
	tabled_srv.rep_master = rp;
}

static void cldu_get_master(const char *mfname, struct ncld_fh *mfh)
{
	struct ncld_read *nrp;
	struct timespec tm;
	int error;

	nrp = ncld_get(mfh, &error);
	if (!nrp) {
		applog(LOG_ERR, "CLD get(%s) failed: %d", mfname, error);
		return;
	}

	if (nrp->length < 3) {
		ncld_read_free(nrp);

		/*
		 * Since master opens, locks, and writes, in that order,
		 * there's a gap between the lock and write. So, unrace a bit.
		 */
		tm.tv_sec = 2;
		tm.tv_nsec = 0;
		nanosleep(&tm, NULL);

		nrp = ncld_get(mfh, &error);
		if (!nrp) {
			applog(LOG_ERR, "CLD get(%s) failed: %d", mfname, error);
			return;
		}

		if (nrp->length < 3) {
			applog(LOG_ERR, "CLD master(%s) is empty", mfname);
			ncld_read_free(nrp);
			return;
		}
	}

	cldu_parse_master(mfname, nrp->ptr, nrp->length);
	ncld_read_free(nrp);
}

/*
 * Lock the MASTER file, write or read it as needed.
 * N.B. Only call this if you know that mfh is closed or never open:
 * right after cldu_set_cldc (disposing of session closes handles),
 * or when we were slave and so should not kept mfh ...
 */
static int cldu_set_master(struct cld_session *sp)
{
	char *buf;
	int len;
	int error;
	int rc;

	if (!sp->nsp)
		return -1;

	/* Maybe drop this later, after notifications work. */
	if (debugging) {
		rc = g_list_length(sp->nsp->handles);
		applog(LOG_DEBUG, "open handles %d", rc);
	}

	sp->mfh = ncld_open(sp->nsp, sp->mfname,
			    COM_READ | COM_WRITE | COM_LOCK | COM_CREATE,
			    &error, 0, NULL, NULL);
	if (!sp->mfh) {
		applog(LOG_ERR, "CLD open(%s) failed: %d", sp->mfname, error);
		goto err_open;
	}

	error = ncld_trylock(sp->mfh);
	if (error) {
		applog(LOG_INFO, "CLD lock(%s) failed: %d", sp->mfname, error);
		cldu_get_master(sp->mfname, sp->mfh);
		goto err_lock;
	}

	/*
	 * If "auto" is used, we do not know the replication socket host
	 * and port at this time, so we just write the name and expect
	 * the caller to update the MASTER file later. In case of a fixed
	 * host and port we can write it here, but there is no point.
	 */
	len = asprintf(&buf, "name: %s\n", sp->thisname);
	if (len < 0) {
		applog(LOG_ERR, "internal error: no core");
		goto err_wmem;
	}

	rc = ncld_write(sp->mfh, buf, len);
	if (rc) {
		applog(LOG_ERR, "CLD put(%s) failed: %d", sp->mfname, rc);
		goto err_write;
	}

	free(buf);
	return 0;

err_write:
	free(buf);
err_wmem:
	/* ncld_unlock() - close will unlock */
err_lock:
	ncld_close(sp->mfh);
err_open:
	return -1;
}

static void cldu_tm_rescan(int fd, short events, void *userdata)
{
	struct cld_session *sp = userdata;
	int newactive;

	/* Add rescanning for tabled nodes as well. FIXME */
	if (debugging)
		applog(LOG_DEBUG, "Rescanning for Chunks in %s", sp->xfname);

	if (sp->is_dead) {
		if (sp->nsp) {
			ncld_sess_close(sp->nsp);
			sp->nsp = NULL;
		}
		newactive = cldu_nextactive(sp);
		if (cldu_set_cldc(sp, newactive))
			goto out;

		if (cldu_set_master(sp) == 0) {
			tabled_srv.state_want = ST_W_MASTER;
		} else {
			if (debugging)
				applog(LOG_DEBUG, "Unable to relock %s",
				       sp->mfname);
			tabled_srv.state_want = ST_W_SLAVE;
		}
		cld_update_cb();

		sp->is_dead = false;
	} else {
		if (tabled_srv.state_want == ST_W_SLAVE) {
			if (cldu_set_master(sp) == 0) {
				tabled_srv.state_want = ST_W_MASTER;
			} else {
				if (debugging)
					applog(LOG_DEBUG, "Unable to lock %s",
					       sp->mfname);
			}
		}
	}

	if (scan_peers(sp) != 0)
		goto out;
	scan_chunks(sp);

 out:
	evtimer_add(&sp->tm_rescan, &cldu_rescan_delay);
}

static void cldu_sess_event(void *priv, uint32_t what)
{
	struct cld_session *sp = priv;

	if (what == CE_SESS_FAILED) {
		if (sp->nsp)
			applog(LOG_ERR, "Session failed, sid " SIDFMT,
				       SIDARG(sp->nsp->udp->sess->sid));
		else
			applog(LOG_ERR, "Session open failed");
		sp->is_dead = true;
	} else {
		if (sp->nsp)
			applog(LOG_INFO, "cldc event 0x%x sid " SIDFMT,
			       what, SIDARG(sp->nsp->udp->sess->sid));
		else
			applog(LOG_INFO, "cldc event 0x%x no sid", what);
	}
}

/*
 * Open the library, start its session, pre-open files, and set timers.
 * Our session remains consistent in case of an error in this function,
 * so that we can continue and retry meaningfuly.
 */
static int cldu_set_cldc(struct cld_session *sp, int newactive)
{
	struct cldc_host *hp;
	struct timespec tm;
	int error;
	int rc;

	if (sp->nsp) {
		ncld_sess_close(sp->nsp);
		sp->nsp = NULL;
	}

	sp->actx = newactive;
	if (!sp->cldv[sp->actx].known) {
		applog(LOG_ERR, "No CLD hosts");
		goto err_addr;
	}
	hp = &sp->cldv[sp->actx].h;

	if (debugging)
		applog(LOG_INFO, "Selected CLD host %s port %u",
		       hp->host, hp->port);

	sp->nsp = ncld_sess_open(hp->host, hp->port, &error,
				 cldu_sess_event, sp, "tabled", "tabled",
				 &cldu_hail_log);
	if (sp->nsp == NULL) {
		if (error < 1000) {
			applog(LOG_ERR, "ncld_sess_open(%s,%u) error: %s",
			       hp->host, hp->port, strerror(error));
		} else {
			applog(LOG_ERR, "ncld_sess_open(%s,%u) error: %d",
			       hp->host, hp->port, error);
		}
		goto err_nsess;
	}

	applog(LOG_INFO, "New CLD session created, sid " SIDFMT,
	       SIDARG(sp->nsp->udp->sess->sid));

	/*
	 * First, make sure the base directory exists.
	 */
	sp->cfh = ncld_open(sp->nsp, sp->cfname,
			    COM_READ | COM_WRITE | COM_CREATE | COM_DIRECTORY,
			    &error, 0 /* CE_MASTER_FAILOVER | CE_SESS_FAILED */,
			    NULL, NULL);
	if (!sp->cfh) {
		applog(LOG_ERR, "CLD open(%s) failed: %d", sp->cfname, error);
		goto err_copen;
	}

	if (debugging)
		applog(LOG_DEBUG, "CLD directory \"%s\" created", sp->cfname);

	/*
	 * Then, create the membership file for us.
	 * We lock it in case of two tabled running with same name by mistake.
	 */
	sp->ffh = ncld_open(sp->nsp, sp->ffname,
			    COM_WRITE | COM_LOCK | COM_CREATE,
			    &error, 0, NULL, NULL);
	if (!sp->ffh) {
		applog(LOG_ERR, "CLD open(%s) failed: %d", sp->ffname, error);
		goto err_fopen;
	}

	if (debugging)
		applog(LOG_DEBUG, "CLD file \"%s\" created", sp->ffname);

	for (;;) {
		rc = ncld_trylock(sp->ffh);
		if (!rc)
			break;

		applog(LOG_ERR, "CLD lock(%s) failed: %d", sp->ffname, rc);
		if (rc != CLE_LOCK_CONFLICT + 1100)
			goto err_lock;

		/*
		 * The usual reason why we get a lock conflict is
		 * restarting too quickly and hitting the previous lock
		 * that is going to disappear soon. Just wait it out.
		 */
		tm.tv_sec = 10;
		tm.tv_nsec = 0;
		nanosleep(&tm, NULL);
	}

	/*
	 * Write the file with our connection parameters.
	 */
	rc = ncld_write(sp->ffh, "-\n", 2);
	if (rc) {
		applog(LOG_ERR, "CLD put(%s) failed: %d", sp->ffname, rc);
		goto err_write;
	}

	/*
	 * Finally, scan cfh to find peers, add with global effects.
	 */
	if (scan_peers(sp) != 0)
		goto err_pscan;

	return 0;

err_pscan:
err_write:
err_lock:
	ncld_close(sp->ffh);	/* session-close closes these, maybe drop */
err_fopen:
	ncld_close(sp->cfh);
err_copen:
	ncld_sess_close(sp->nsp);
	sp->nsp = NULL;
err_nsess:
err_addr:
	return -1;
}

static int scan_peers(struct cld_session *sp)
{
	struct ncld_read *nrp;
	char buf[65];
	const char *ptr;
	int dir_len;
	int total_len, rec_len, name_len;
	int error;

	nrp = ncld_get(sp->cfh, &error);
	if (!nrp) {
		applog(LOG_ERR, "CLD get(%s) failed: %d", sp->cfname, error);
		goto err_dread;
	}

	if (debugging)
		applog(LOG_DEBUG, "Known tabled nodes");

	ptr = nrp->ptr;
	dir_len = nrp->length;
	while (dir_len) {
		name_len = GUINT16_FROM_LE(*(uint16_t *)ptr);
		rec_len = name_len + 2;
		total_len = rec_len + ALIGN8(rec_len);

		strncpy(buf, ptr+2, 64);
		if (name_len < 64)
			buf[name_len] = 0;
		else
			buf[64] = 0;

		if (!strcmp(buf, MASTER_FILE)) {
			; /* ignore special entry */
		} else if (!strcmp(buf, sp->thisname)) {
			if (debugging)
				applog(LOG_DEBUG, " %s (ourselves)", buf);
		} else {
			if (tdb_find_remote_byname(buf)) {
				if (debugging)
					applog(LOG_DEBUG, " %s", buf);
			} else {
				if (debugging)
					applog(LOG_DEBUG, " %s (new)", buf);
				add_remote(buf);
			}
		}

		ptr += total_len;
		dir_len -= total_len;
	}

	ncld_read_free(nrp);
	return 0;

err_dread:
	return -1;
}

static int scan_chunks(struct cld_session *sp)
{
	struct ncld_fh *xfh;	/* /chunk-GROUP directory */
	struct ncld_read *nrp;
	struct chunk_node *np;
	const char *ptr;
	int dir_len;
	int total_len, rec_len, name_len;
	char buf[65];
	int error;

	xfh = ncld_open(sp->nsp, sp->xfname, COM_READ | COM_DIRECTORY,
			&error, 0 /* CE_MASTER_FAILOVER | CE_SESS_FAILED */,
			NULL, NULL);
	if (!xfh) {
		if (error == CLE_INODE_INVAL + 1100 ||
		    error == CLE_NAME_INVAL + 1100) {
			applog(LOG_ERR, "%s: open failed, retrying",
			       sp->xfname);
			return 1;
		} else {
			applog(LOG_ERR, "CLD open(%s) failed: %d",
			       sp->xfname, error);
			/* XXX we're dead, why not exit(1) right away? */
			return -1;
		}
	}

	/*
	 * Read the directory.
	 */
	nrp = ncld_get(xfh, &error);
	if (!nrp) {
		ncld_close(xfh);
		applog(LOG_ERR, "CLD get(%s) failed: %d", sp->xfname, error);
		return -1;
	}

	if (debugging)
		applog(LOG_DEBUG, "Known Chunk nodes");

	ptr = nrp->ptr;
	dir_len = nrp->length;
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

	ncld_read_free(nrp);
	ncld_close(xfh);

	/*
	 * Scan the collected directory contents and fill the entries.
	 */
	if (list_empty(&sp->chunks)) {
		applog(LOG_INFO, "%s: No Chunk nodes found, retrying",
		       sp->xfname);
		return 1;
	}
	while (!list_empty(&sp->chunks)) {
		np = list_entry(sp->chunks.next, struct chunk_node, link);
		next_chunk(sp, np);
		list_del(&np->link);
	}

	/*
	 * Poke the dispatch about the possible changes in the
	 * configuration of Chunk.
	 *
	 * It's possible that the CLD directories have many entries,
	 * but no useable Chunk servers. In that case, treat everything
	 * like a usual retry.
	 *
	 * For the case of normal operation, we also set up a rescan, for now.
	 * In the future, we'll subscribe for change notification. FIXME.
	 */
	if (!stor_update_cb())
		return 1;

	return 0;
}

static void next_chunk(struct cld_session *sp, struct chunk_node *np)
{
	char *mem;
	char *yfname;		/* /chunk-GROUP/NID file */
	struct ncld_fh *yfh;	/* /chunk-GROUP/NID file */
	struct ncld_read *nrp;
	int error;

	if (asprintf(&mem, "/chunk-%s/%s", sp->thisgroup, np->name) == -1) {
		applog(LOG_WARNING, "OOM in cldu");
		goto err_mem;
	}
	yfname = mem;

	yfh = ncld_open(sp->nsp, yfname, COM_READ, &error,
			0 /* CE_MASTER_FAILOVER | CE_SESS_FAILED */,
			NULL, NULL);
	if (!yfh) {
		applog(LOG_ERR, "CLD open(%s) failed: %d", yfname, error);
		goto err_open;
	}

	/*
	 * Read the Chunk's parameter file.
	 */
	nrp = ncld_get(yfh, &error);
	if (!nrp) {
		applog(LOG_ERR, "CLD get(%s) failed: %d", yfname, error);
		goto err_get;
	}
	stor_parse(yfname, nrp->ptr, nrp->length);
	ncld_read_free(nrp);
	ncld_close(yfh);
	free(yfname);
	return;

err_get:
	ncld_close(yfh);
err_open:
	free(yfname);
err_mem:
	return;
}

static void add_remote(const char *name)
{
	struct db_remote *rp;

	rp = malloc(sizeof(struct db_remote));
	if (!rp)
		return;
	memset(rp, 0, sizeof(struct db_remote));

	/*
	 * Master assigns global IDs now, distributes them in login protocol.
	 */
	rp->dbid = DBID_NONE;

	rp->name = strdup(name);
	if (!rp->name) {
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
	ncld_init();

	// memset(&ses, 0, sizeof(struct cld_session));
	INIT_LIST_HEAD(&ses.chunks);
}

/*
 * This initiates our sole session with a CLD instance.
 */
int cld_begin(const char *thishost, const char *thisgroup,
	      const char *thisname, int verbose)
{
	static struct cld_session *sp = &ses;
	struct timespec tm;
	int newactive;
	int retry_cnt;

	cldu_hail_log.verbose = verbose;

	evtimer_set(&ses.tm_rescan, cldu_tm_rescan, &ses);

	if (cldu_setgroup(sp, thisgroup, thisname)) {
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
	newactive = 0;
	retry_cnt = 0;
	for (;;) {
		if (!cldu_set_cldc(sp, newactive))
			break;
		/* Already logged error */
		if (++retry_cnt == 5)
			goto err_net;
		newactive = cldu_nextactive(sp);
	}

	if (cldu_set_master(sp) == 0) {
		if (debugging)
			applog(LOG_DEBUG, "Locked %s", sp->mfname);
		tabled_srv.state_want = ST_W_MASTER;
	} else {
		tabled_srv.state_want = ST_W_SLAVE;
	}

	retry_cnt = 0;
	for (;;) {
		if (!scan_chunks(sp))
			break;
		if (++retry_cnt == 5)
			goto err_scan;
		tm.tv_sec = 5;
		tm.tv_nsec = 0;
		nanosleep(&tm, NULL);
	}

	evtimer_add(&sp->tm_rescan, &cldu_rescan_delay);
	return 0;

err_scan:
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

void cld_post_rep_conn(const char *rep_host, unsigned int rep_port)
{
	static struct cld_session *sp = &ses;
	char *buf;
	int len;
	int rc;

	if (!sp->nsp || sp->is_dead)
		return;
	if (!sp->mfh) {
		/*
		 * We should only get here when we are a master, and since
		 * the session is up, the MASTER handle must be present.
		 * Report an internal error.
		 */
		applog(LOG_WARNING,
		       "Unable to post connection, no MASTER file");
		return;
	}

	len = asprintf(&buf, "name: %s\nhost: %s\nport: %u\n",
		       sp->thisname, rep_host, rep_port);
	if (len < 0) {
		applog(LOG_ERR, "internal error: no core");
		goto err_wmem;
	}

	rc = ncld_write(sp->mfh, buf, len);
	if (rc) {
		applog(LOG_ERR, "CLD put(%s) failed: %d", sp->mfname, rc);
		goto err_write;
	}

	free(buf);
	return;

 err_write:
	free(buf);
 err_wmem:
	return;
}

void cld_end(void)
{
	static struct cld_session *sp = &ses;
	int i;

	if (sp->nsp) {
		ncld_sess_close(sp->nsp);
		sp->nsp = NULL;
	}

	if (!sp->forced_hosts) {
		for (i = 0; i < N_CLD; i++) {
			if (sp->cldv[i].known) {
				free(sp->cldv[i].h.host);
				sp->cldv[i].known = false;
			}
		}
	}

	evtimer_del(&sp->tm_rescan);

	free(sp->cfname);
	sp->cfname = NULL;
	free(sp->ffname);
	sp->ffname = NULL;
	free(sp->xfname);
	sp->xfname = NULL;
	free(sp->mfname);
	sp->mfname = NULL;
	free(sp->thisgroup);
	sp->thisgroup = NULL;
	free(sp->thisname);
	sp->thisname = NULL;
}
