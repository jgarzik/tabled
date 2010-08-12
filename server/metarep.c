
/*
 * Copyright 2008-2009 Red Hat, Inc.
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
#include <sys/ioctl.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <glib.h>
#include <tdb.h>
#include <netdb.h>
#include <netinet/in.h>
#include "tabled.h"

/* #define offsetof(type, member)	\
	(((unsigned char *)&((type *)0)->member) - (unsigned char *)0) */

/*
 * flags:
 *   <31:28>  version (currently 1)
 *   <27:8>   unused
 *    <7:0>   rep_msg_type
 */
enum rep_msg_type {  REP_MSG_NOP, REP_MSG_LOGIN, REP_MSG_LOGOK, REP_MSG_DATA };
struct rep_msg_hdr {
	unsigned int	flags;
	unsigned int	lenctl;
	unsigned int	lendata;
	unsigned short	dst, src;
};

/*
 * The naming convention is to identify the context in which the function runs.
 */
static int rtdb_master_login_reply(struct db_conn *dbc, unsigned char *msgbuf);

/*
 * Note that the invalid dbid is zero, not -1.
 */
static int make_remote_id(void)
{
	int id;

	for (;;) {
		id = rand() % (DBID_MAX+1 - DBID_MIN) + DBID_MIN;
		if (!tdb_find_remote_byid(id))
			return id;
	}
}

static int dbl_init(struct db_link *dbl)
{
	dbl->fd = -1;
	dbl->state = DBC_INIT;

	dbl->obuflen = 500;
	dbl->obuf = malloc(dbl->obuflen);
	if (!dbl->obuf)
		return -1;

	dbl->ibuflen = sizeof(struct rep_msg_hdr);
	dbl->ibuf = malloc(dbl->ibuflen);
	if (!dbl->ibuf) {
		free(dbl->obuf);
		return -1;
	}
	dbl->cnt = 0;
	dbl->explen = 1;

	return 0;
}

static int dbl_irealloc(struct db_link *dbl, int len)
{
	unsigned char *newbuf;

	if (len > dbl->ibuflen) {
		if (!(newbuf = malloc(len)))
			return -1;
		memcpy(newbuf, dbl->ibuf, dbl->ibuflen);
		free(dbl->ibuf);
		dbl->ibuf = newbuf;
		dbl->ibuflen = len;
	}
	return 0;
}

/*
 * Expect the dbl->explen, return accumulated dbl->cnt.
 */
static int dbl_expect(struct db_link *dbl)
{
	int rc;

	rc = read(dbl->fd, dbl->ibuf + dbl->cnt, dbl->explen - dbl->cnt);
	if (rc < 0) {
		if (errno == EAGAIN)
			return dbl->cnt;
		applog(LOG_ERR, "network read: %s", strerror(errno));
		return -1;
	}
	if (rc == 0) {
		applog(LOG_ERR, "EOF from peer"); /* P3 */
		return -1;
	}
	dbl->cnt += rc;
	return dbl->cnt;
}

static int dbl_hdr_validate(struct rep_msg_hdr *hdr, int thisid)
{
	unsigned int msgflags;
	int srcid, dstid;

	msgflags = GUINT32_FROM_BE(hdr->flags);
	if ((msgflags >> 28) != 1) {
		applog(LOG_ERR, "Link: bad protocol, flags 0x%08x", msgflags);
		return -1;
	}

	srcid = GUINT16_TO_BE(hdr->src);
	dstid = GUINT16_TO_BE(hdr->dst);
	if (srcid == dstid) {
		applog(LOG_ERR, "Link: loopback, dbid %d", dstid);
		return -1;
	}
	if (srcid < DBID_MIN || srcid > DBID_MAX) {
		applog(LOG_ERR, "Link: bad src dbid %d", srcid);
		return -1;
	}
	if (dstid < DBID_MIN || dstid > DBID_MAX) {
		applog(LOG_ERR, "Link: bad dst dbid %d", dstid);
		return -1;
	}

	if (thisid != 0 && dstid != thisid) {
		applog(LOG_ERR, "Link: misdirected, dst dbid %d our dbid %d",
		       dstid, thisid);
		return -1;
	}

	return 0;
}

/*
 * Login message is different in two ways:
 *  - src and/or dst may be not set
 *  - lenctl is the dst name, lendata is the src name
 *    (but contents not available for validation)
 */
static int dbl_hdr_validate_login(struct rep_msg_hdr *hdr, int thisid)
{
	unsigned int msgflags;
	unsigned int len;

	msgflags = GUINT32_FROM_BE(hdr->flags);
	if ((msgflags >> 28) != 1) {
		applog(LOG_ERR, "Link: bad protocol, flags 0x%08x", msgflags);
		return -1;
	}
	if ((msgflags & 0xff) != REP_MSG_LOGIN) {
		applog(LOG_ERR, "Link: bad login request, flags 0x%08x",
		       msgflags);
		return -1;
	}

#if 0 /* A bad idea as long as names are the persistent identifiers. */
	int dstid;
	dstid = GUINT32_FROM_BE(hdr->dst);
	if (dstid && dstid != thisid) {
		applog(LOG_ERR, "Link: login to wrong dbid %d", dstid);
		return -1;
	}
#endif

	len = GUINT32_FROM_BE(hdr->lenctl);
	if (len == 0 || len > 64) {
		applog(LOG_ERR, "Link: bad login dst len %u", len);
		return -1;
	}

	len = GUINT32_FROM_BE(hdr->lendata);
	if (len == 0 || len > 64) {
		applog(LOG_ERR, "Link: bad login src len %u", len);
		return -1;
	}

	return 0;
}

static void dbl_fini(struct db_link *dbl)
{
	if (dbl->writing) {
		event_del(&dbl->wrev);
		dbl->writing = false;
	}
	if (dbl->fd >= 0) {
		event_del(&dbl->rcev);
		close(dbl->fd);
	}
	if (dbl->ibuf)
		free(dbl->ibuf);
	if (dbl->obuf)
		free(dbl->obuf);
}

static struct db_conn *tdb_find_byid(struct tablerep *rtdb, int id)
{
	struct db_conn *dbc;

	list_for_each_entry(dbc, &rtdb->conns, link) {
		if (dbc->remote && dbc->remote->dbid == id)
			return dbc;
	}
	return NULL;
}

static struct db_conn *dbc_alloc(struct tablerep *rtdb, struct db_remote *rem)
{
	struct db_conn *dbc;

	dbc = malloc(sizeof(*dbc));
	if (!dbc)
		goto out_mem;
	memset(dbc, 0, sizeof(*dbc));
	dbc->rtdb = rtdb;
	dbc->remote = rem;
	if (dbl_init(&dbc->lk))
		goto out_dbl;
	return dbc;

 out_dbl:
	free(dbc);
 out_mem:
	return NULL;
}

static void dbc_free(struct db_conn *dbc)
{
	dbl_fini(&dbc->lk);
	free(dbc);
}

/*
 * The dbc->remote is known here, see callers.
 *
 * The db4 code assumes that it is all right to block when sending. Of course
 * in our case that means blocking the whole (single-threaded) server.
 * It is also all right to drop messages, which is said to hurt performance
 * in other ways. Still, as long as tabled is single-theaded we have no choice.
 *
 * Since we can only send complete messages, and even blocking sockets can
 * return short writes, we must buffer output. But we do not create any
 * additional queues beyond what is required for the atomicity.
 */
static int tdb_rep_send(struct tablerep *rtdb, struct db_link *dbl,
			int dstid, const DBT *ctl, const DBT *rec,
			bool easydrop)
{
	unsigned char *p;
	struct rep_msg_hdr *hdr;
	unsigned int msgflags;
	ssize_t len;
	ssize_t rc;

	if (dbl->togo) {
		/* Maybe poke the output here? Should not be necessary. */
		return 1;
	}

	len = sizeof(struct rep_msg_hdr) + ctl->size + rec->size;
	if (dbl->obuflen < len) {
		free(dbl->obuf);
		dbl->obuflen = 0;
		dbl->obuf = malloc(len);
		if (!dbl->obuf) {
			applog(LOG_WARNING, "No core (%ld)", (long) len);
			return -1;
		}
		dbl->obuflen = len;
	}

	hdr = (struct rep_msg_hdr *) dbl->obuf;
	p = dbl->obuf;

	memset(hdr, 0, sizeof(struct rep_msg_hdr));
	msgflags = (1 << 28) | (REP_MSG_DATA);
	hdr->flags = GUINT32_TO_BE(msgflags);
	hdr->dst = GUINT16_TO_BE((unsigned short)dstid);
	hdr->src = GUINT16_TO_BE((unsigned short)rtdb->thisid);
	p += sizeof(struct rep_msg_hdr);
	if (ctl->size) {
		hdr->lenctl = GUINT32_TO_BE(ctl->size);
		memcpy(p, ctl->data, ctl->size);
		p += ctl->size;
	}
	if (rec->size) {
		hdr->lendata = GUINT32_TO_BE(rec->size);
		memcpy(p, rec->data, rec->size);
		p += rec->size;
	}

	dbl->done = 0;
	dbl->togo = p - dbl->obuf;

	rc = write(dbl->fd, dbl->obuf + dbl->done, dbl->togo);
	if (rc < 0) {
		dbl->done = 0;
		dbl->togo = 0;
		applog(LOG_ERR, "socket write error, peer dbid %d: %s",
		       dstid, strerror(errno));
		return -1;
	}
	if (rc < dbl->togo) {
		if (!dbl->writing) {
			if (event_add(&dbl->wrev, NULL))
				applog(LOG_ERR, "event_add failed (write)");
			else
				dbl->writing = true;
		}
	}
	dbl->done += rc;
	dbl->togo -= rc;
	return 0;
}

static int db4_rep_send(DB_ENV *dbenv, const DBT *ctl, const DBT *rec,
			const DB_LSN *lsnp, int envid, uint32_t flags)
{
	struct tablerep *rtdb;
	struct db_conn *dbc;
	int cnt;
	int rc;

	rtdb = (struct tablerep *)
		((char *)dbenv->app_private - offsetof(struct tablerep, tdb));

	if (envid == DB_EID_BROADCAST) {
		cnt = 0;
		list_for_each_entry(dbc, &rtdb->conns, link) {
			if (dbc->lk.state == DBC_OPEN) {
				rc = tdb_rep_send(rtdb, &dbc->lk,
						  dbc->remote->dbid,
						  ctl, rec, true);
				if (!rc)
					cnt++;
				if (rc < 0)
					dbc->lk.state = DBC_DEAD;
			}
		}
		if (!cnt)
			return DB_REP_UNAVAIL;
	} else {
		dbc = tdb_find_byid(rtdb, envid);
		if (dbc && dbc->lk.state == DBC_OPEN) {
			rc = tdb_rep_send(rtdb, &dbc->lk,
					  dbc->remote->dbid, ctl, rec, false);
			if (rc < 0) {
				dbc->lk.state = DBC_DEAD;
				return DB_REP_UNAVAIL;
			}
			if (rc)
				return DB_REP_UNAVAIL;
		} else {
			applog(LOG_INFO, "Send: dbid %d not found", envid);
			return DB_REP_UNAVAIL;
		}
	}
	return 0;
}

static int rtdb_process(struct db_conn *dbc, unsigned char *msgbuf)
{
	struct rep_msg_hdr *hdr = (struct rep_msg_hdr *) msgbuf;
	DB_ENV *dbenv = dbc->rtdb->tdb.env;
	DBT pctl, prec;
	DB_LSN lsn;
	struct db_remote *peer;
	int rc;

	peer = tdb_find_remote_byid(GUINT16_FROM_BE(hdr->src));
	if (!peer) {
		applog(LOG_INFO, "Unknown peer dbid %d",
		       GUINT16_FROM_BE(hdr->src));
		return -1;
	}

	memset(&pctl, 0, sizeof(pctl));
	pctl.data = msgbuf + sizeof(struct rep_msg_hdr);
	pctl.size = GUINT32_FROM_BE(hdr->lenctl);
	memset(&prec, 0, sizeof(prec));
	prec.data = pctl.data + pctl.size;
	prec.size = GUINT32_FROM_BE(hdr->lendata);
	rc = dbenv->rep_process_message(dbenv, &pctl, &prec, peer->dbid, &lsn);
	switch (rc) {
	case DB_REP_ISPERM:
		/*
		 * The "record is written" is normal in db4 operations,
		 * and shows up so much that we do not print it even under
		 * if (debugging).
		 */
		break;
	case DB_REP_DUPMASTER:		/* DB thinks we have 2 */
	case DB_REP_HANDLE_DEAD:	/* what handle? */
	case DB_REP_HOLDELECTION:	/* maybe just rep_init it */
	case DB_REP_IGNORE:		/* well, whatever */
	case DB_REP_JOIN_FAILURE:
	case DB_REP_LEASE_EXPIRED:
	case DB_REP_LOCKOUT:
	case DB_REP_NEWSITE:
	case DB_REP_NOTPERM:
	case DB_REP_UNAVAIL:
	default:
		if (rc) {
			applog(LOG_INFO, "rep_process_message: %d (%s)",
			       rc, db_strerror(rc));
		}
	}

	return 0;
}

static int rtdb_send_more(struct db_link *dbl)
{
	ssize_t rc;

	if (!dbl->togo) {
 /* P3 */ applog(LOG_INFO, "stray write event");
		event_del(&dbl->wrev);
		dbl->writing = false;
		return 0;
	}

	rc = write(dbl->fd, dbl->obuf + dbl->done, dbl->togo);
	if (rc < 0) {
		applog(LOG_ERR, "socket write error: %s", strerror(errno));
		dbl->done = 0;
		dbl->togo = 0;
		return -1;
	}
	if (rc < dbl->togo) {
		dbl->done += rc;
		dbl->togo -= rc;
		if (!dbl->writing) {
			if (event_add(&dbl->wrev, NULL))
				applog(LOG_ERR, "event_add failed (write)");
			else
				dbl->writing = true;
		}
	} else {
		dbl->done = 0;
		dbl->togo = 0;
		if (dbl->writing) {
			event_del(&dbl->wrev);
			dbl->writing = false;
		}
	}
	return 0;
}

static void rtdb_wr_event(int fd, short events, void *userdata)
{
	struct db_link *dbl = userdata;

	if (rtdb_send_more(dbl))
		dbl->state = DBC_DEAD;
}

static void rtdb_master_tcp_event(int fd, short events, void *userdata)
{
	struct db_conn *dbc = userdata;
	struct rep_msg_hdr *hdr;
	unsigned msgflags;
	int ctllen, reclen;
	int len;
	int rc;

	switch (dbc->lk.state) {
	case DBC_LOGIN:
		rc = dbl_expect(&dbc->lk);
		if (rc < 0)
			goto out_bad_dbc;
		if (rc < dbc->lk.explen)
			return;

		if (dbc->lk.explen == sizeof(struct rep_msg_hdr)) {
			hdr = (struct rep_msg_hdr *) dbc->lk.ibuf;
			if (dbl_hdr_validate_login(hdr, dbc->rtdb->thisid))
				goto out_bad_dbc;

			ctllen = GUINT32_FROM_BE(hdr->lenctl);
			reclen = GUINT32_FROM_BE(hdr->lendata);
			len = sizeof(struct rep_msg_hdr) + ctllen + reclen;
			if (dbl_irealloc(&dbc->lk, len) < 0) {
				applog(LOG_ERR, "No core (%d)", len);
				goto out_bad_dbc;
			}
			dbc->lk.explen = len;
		} else {
			if (rtdb_master_login_reply(dbc, dbc->lk.ibuf))
				goto out_bad_dbc;

			dbc->lk.state = DBC_OPEN;
			dbc->lk.cnt = 0;
			dbc->lk.explen = sizeof(struct rep_msg_hdr);
		}
		break;
	case DBC_OPEN:
		rc = dbl_expect(&dbc->lk);
		if (rc < 0)
			goto out_bad_dbc;
		if (rc < dbc->lk.explen)
			return;

		if (dbc->lk.explen == sizeof(struct rep_msg_hdr)) {
			hdr = (struct rep_msg_hdr *) dbc->lk.ibuf;
			if (dbl_hdr_validate(hdr, dbc->rtdb->thisid))
				goto out_bad_dbc;
			msgflags = GUINT32_FROM_BE(hdr->flags);
			if ((msgflags & 0xff) != REP_MSG_DATA) {
				applog(LOG_ERR,
				       "Bad data message, flags 0x%08x",
				       msgflags);
				goto out_bad_dbc;
			}

			ctllen = GUINT32_FROM_BE(hdr->lenctl);
			reclen = GUINT32_FROM_BE(hdr->lendata);
			len = sizeof(struct rep_msg_hdr) + ctllen + reclen;
			if (dbl_irealloc(&dbc->lk, len) < 0) {
				applog(LOG_ERR, "No core (%d)", len);
				goto out_bad_dbc;
			}
			dbc->lk.explen = len;
		} else {
			if (rtdb_process(dbc, dbc->lk.ibuf))
				goto out_bad_dbc;

			dbc->lk.state = DBC_OPEN;
			dbc->lk.cnt = 0;
			dbc->lk.explen = sizeof(struct rep_msg_hdr);
		}
		break;
	default: // DBC_DEAD
		if (dbc->remote) {
			applog(LOG_INFO,
			       "Event on a dead slave socket, slave %s",
			       dbc->remote->host);
		} else {
			applog(LOG_INFO,
			       "Event on a dead slave socket");
		}
		tdb_conn_scrub_cb();
	}
	return;

 out_bad_dbc:
	dbc->lk.state = DBC_DEAD;
	tdb_conn_scrub_cb();
	return;
}

static void tdb_conn_event(int fd, short events, void *userdata)
{
	struct tablerep *rtdb = userdata;
	struct db_conn *dbc;
	struct sockaddr_in6 addr;
	socklen_t addrlen;
	char host[65], port[15];

	dbc = dbc_alloc(rtdb, NULL);
	if (!dbc)
		goto out_dbc;
	dbc->lk.explen = sizeof(struct rep_msg_hdr);
	dbc->lk.state = DBC_LOGIN;

	addrlen = sizeof(addr);
	dbc->lk.fd = accept(fd, (struct sockaddr *) &addr, &addrlen);
	if (dbc->lk.fd < 0) {
		applog(LOG_ERR, "accept: %s", strerror(errno));
		goto out_accept;
	}

	getnameinfo((struct sockaddr *) &addr, addrlen,
		    host, sizeof(host), port, sizeof(port),
		    NI_NUMERICHOST|NI_NUMERICSERV);
	applog(LOG_INFO, "db slave host %s port %s", host, port);

	if (fcntl(dbc->lk.fd, F_SETFL, O_NONBLOCK) < 0) {
		applog(LOG_ERR, "fcntl: %s", strerror(errno));
		goto out_flags;
	}

	event_set(&dbc->lk.rcev, dbc->lk.fd, EV_READ | EV_PERSIST,
		  rtdb_master_tcp_event, dbc);
	event_set(&dbc->lk.wrev, dbc->lk.fd, EV_WRITE | EV_PERSIST,
		  rtdb_wr_event, &dbc->lk);
	if (event_add(&dbc->lk.rcev, NULL) < 0) {
		applog(LOG_ERR, "event_add failed");
		goto out_add;
	}
	list_add_tail(&dbc->link, &rtdb->conns);
	return;

 out_add:
 out_flags:
	close(dbc->lk.fd);
 out_accept:
	dbc_free(dbc);
 out_dbc:
	return;
}

static int tdb_rep_listen_open(struct sockaddr_in *addr, int addr_len)
{
	int fd;
	int on;
	int rc;

	fd = socket(addr->sin_family, SOCK_STREAM, 0);
	if (fd < 0)
		return -errno;

	on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		rc = -errno;
		goto out_err;
	}

	if (bind(fd, addr, addr_len) < 0) {
		rc = -errno;
		goto out_err;
	}

	// rc = fsetflags("tcp server", fd, O_NONBLOCK);
	// if (rc) {
	// 	rc = -errno;
	// 	goto out_err;
	// }

	if (listen(fd, 100) < 0) {
		rc = -errno;
		goto out_err;
	}

	return fd;

 out_err:
	close(fd);
	return rc;
}

static int rtdb_rep_listen(struct tablerep *rtdb, unsigned short port)
{
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	int rc;

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(port);
	memcpy(&addr6.sin6_addr, &in6addr_any, sizeof(struct in6_addr));
	rc = tdb_rep_listen_open((struct sockaddr_in *)&addr6, sizeof(addr6));
	if (rc < 0) {
		if (debugging)
			applog(LOG_DEBUG,
			       "tdb_rep_listen_open(v6, %u) failed: %s",
			       port, strerror(-rc));
	} else {
		rtdb->sockfd6 = rc;
		event_set(&rtdb->lsev6, rtdb->sockfd6, EV_READ | EV_PERSIST,
			  tdb_conn_event, rtdb);
		if (event_add(&rtdb->lsev6, NULL) < 0)
			applog(LOG_ERR, "event_add failed");
	}

	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons(port);
	addr4.sin_addr.s_addr = htonl(INADDR_ANY);
	rc = tdb_rep_listen_open((struct sockaddr_in *)&addr4, sizeof(addr4));
	if (rc < 0) {
		if (debugging)
			applog(LOG_DEBUG,
			       "tdb_rep_listen_open(v4, %u) failed: %s",
			       port, strerror(-rc));
	} else {
		rtdb->sockfd4 = rc;
		event_set(&rtdb->lsev4, rtdb->sockfd4, EV_READ | EV_PERSIST,
			  tdb_conn_event, rtdb);
		if (event_add(&rtdb->lsev4, NULL) < 0)
			applog(LOG_ERR, "event_add failed");
	}

	return 0;
}

static void rtdb_slave_tcp_event(int fd, short events, void *userdata)
{
	struct db_conn *dbc = userdata;
	struct tablerep *rtdb = dbc->rtdb;
	struct rep_msg_hdr *hdr;
	unsigned msgflags;
	int srcid, dstid;
	int ctllen, reclen;
	int len;
	int rc;

	switch (dbc->lk.state) {
	case DBC_LOGIN:
		rc = dbl_expect(&dbc->lk);
		if (rc < 0)
			goto out_bad_dbc;
		if (rc < dbc->lk.explen)
			return;

		hdr = (struct rep_msg_hdr *) dbc->lk.ibuf;
		if (dbl_hdr_validate(hdr, rtdb->thisid))
			goto out_bad_dbc;
		msgflags = GUINT32_FROM_BE(hdr->flags);
		if ((msgflags & 0xff) != REP_MSG_LOGOK) {
			applog(LOG_ERR, "Bad login reply, flags 0x%08x",
			       msgflags);
			goto out_bad_dbc;
		}
		srcid = GUINT16_FROM_BE(hdr->src);
		dstid = GUINT16_FROM_BE(hdr->dst);

		if (rtdb->thisid == 0) {
			applog(LOG_INFO, "Assigned local dbid %d", dstid);
		} else {
			if (rtdb->thisid != dstid) {
				/*
				 * Oracle people posted that db won't like this,
				 * but what can we do. At worst, blow away the
				 * local db on slave by hand and let it resync.
				 */
				applog(LOG_INFO,
				       "Reassigned local dbid from %d to %d",
				       rtdb->thisid, dstid);
				rtdb->thisid = dstid;
			}
		}
		rtdb->thisid = dstid;

		dbc->lk.state = DBC_OPEN;
		dbc->lk.cnt = 0;
		dbc->lk.explen = sizeof(struct rep_msg_hdr);

		if (tdb_slave_login_cb(srcid))
			goto out_bad_dbc;
		break;
	case DBC_OPEN:
		rc = dbl_expect(&dbc->lk);
		if (rc < 0)
			goto out_bad_dbc;
		if (rc < dbc->lk.explen)
			return;

		if (dbc->lk.explen == sizeof(struct rep_msg_hdr)) {
			hdr = (struct rep_msg_hdr *) dbc->lk.ibuf;
			if (dbl_hdr_validate(hdr, rtdb->thisid))
				goto out_bad_dbc;
			msgflags = GUINT32_FROM_BE(hdr->flags);
			if ((msgflags & 0xff) != REP_MSG_DATA) {
				applog(LOG_ERR,
				       "Bad data message, flags 0x%08x",
				       msgflags);
				goto out_bad_dbc;
			}

			ctllen = GUINT32_FROM_BE(hdr->lenctl);
			reclen = GUINT32_FROM_BE(hdr->lendata);
			len = sizeof(struct rep_msg_hdr) + ctllen + reclen;
			if (dbl_irealloc(&dbc->lk, len) < 0) {
				applog(LOG_ERR, "No core (%d)", len);
				goto out_bad_dbc;
			}
			dbc->lk.explen = len;
		} else {
			if (rtdb_process(dbc, dbc->lk.ibuf))
				goto out_bad_dbc;

			dbc->lk.state = DBC_OPEN;
			dbc->lk.cnt = 0;
			dbc->lk.explen = sizeof(struct rep_msg_hdr);
		}
		break;
	case DBC_DEAD:
		tdb_slave_disc_cb();
		break;
	default:
		/* P3 */ applog(LOG_INFO, "Event on a unready socket");
	}
	return;

 out_bad_dbc:
	dbc->lk.state = DBC_DEAD;
	tdb_conn_scrub_cb();
	return;
}

static int rtdb_master_login_reply(struct db_conn *dbc, unsigned char *msgbuf)
{
	struct tablerep *rtdb = dbc->rtdb;
	struct rep_msg_hdr *hdr = (struct rep_msg_hdr *) msgbuf;
	int srclen, dstlen;
	char *srcname, *dstname;
	struct db_conn *tmp;
	struct db_remote *slave;
	int newid;
	struct rep_msg_hdr hdrb;
	unsigned int msgflags;
	int rc;

	/*
	 * Before proceeding, extract and zero-terminate src and dst names.
	 */
	dstlen = GUINT32_FROM_BE(hdr->lenctl);
	dstname = malloc(dstlen + 1);
	if (!dstname) {
		applog(LOG_ERR, "No core");
		return -1;
	}
	memcpy(dstname, msgbuf + sizeof(struct rep_msg_hdr), dstlen);
	dstname[dstlen] = 0;

	srclen = GUINT32_FROM_BE(hdr->lendata);
	srcname = malloc(srclen + 1);
	if (!srcname) {
		applog(LOG_ERR, "No core");
		free(dstname);
		return -1;
	}
	memcpy(srcname, msgbuf + sizeof(struct rep_msg_hdr) + dstlen, srclen);
	srcname[srclen] = 0;

	if (dbc->remote) {
		/* Never happens even with bad clients, our internal problem. */
		applog(LOG_ERR, "Redone login for slave %s (src %s)",
		       dbc->remote->host, srcname);
		goto out_err;
	}

	if (strcmp(srcname, rtdb->thisname) == 0) {
		applog(LOG_ERR, "Login from aliasing slave %s", srcname);
		goto out_err;
	}

	slave = tdb_find_remote_byname(srcname);
	if (!slave) {
		applog(LOG_INFO, "Unknown slave \"%s\"", srcname);
		goto out_err;
	}

	if (slave->dbid == DBID_NONE) {
		newid = GUINT16_FROM_BE(hdr->src);
		if (newid == 0 || newid < DBID_MIN || newid > DBID_MAX) {
			newid = make_remote_id();
		}
		slave->dbid = newid;
	}
	if (debugging)
		applog(LOG_DEBUG, "Link login, slave %s dbid %d",
		       slave->name, slave->dbid);

	/*
	 * Dispose of all existing connections. Our current implementation
	 * provides no security, so it is a proper thing to do. We assume
	 * that the slave knows what it's doing, maybe it detected a loss
	 * of TCP connection that we missed.
	 */
	list_for_each_entry(tmp, &rtdb->conns, link) {
		if (tmp->remote == slave)
			tmp->lk.state = DBC_DEAD;
	}

	dbc->remote = slave;

	memset(&hdrb, 0, sizeof(hdrb));
	msgflags = (1 << 28) | (REP_MSG_LOGOK);
	hdrb.flags = GUINT32_TO_BE(msgflags);
	hdrb.dst = GUINT16_TO_BE((unsigned short)slave->dbid);
	hdrb.src = GUINT16_TO_BE((unsigned short)rtdb->thisid);

	rc = write(dbc->lk.fd, &hdrb, sizeof(hdrb));
	if (rc < 0) {
		applog(LOG_INFO, "Write error to peer %s: %s", slave->host,
		       strerror(errno));
		goto out_err;
	}
	if (rc < sizeof(hdrb)) {
		applog(LOG_INFO, "Write short to peer %s: %d", slave->host, rc);
		goto out_err;
	}

	return 0;

 out_err:
	free(srcname);
	free(dstname);
	return -1;
}

static int rtdb_slave_login(struct db_conn *dbc)
{
	struct rep_msg_hdr *hdr;
	unsigned char *msgbuf;
	unsigned int msgflags;
	int dstlen, srclen;
	int len;

	dstlen = strlen(dbc->remote->host);
	srclen = strlen(dbc->rtdb->thisname);
	len = sizeof(struct rep_msg_hdr) + dstlen + srclen;
	msgbuf = malloc(len);
	if (!msgbuf)
		return -1;

	hdr = (struct rep_msg_hdr *) msgbuf;
	// memset(hdr, 0, sizeof(struct rep_msg_hdr));  /* no holes */
	msgflags = (1 << 28) | (REP_MSG_LOGIN);
	hdr->flags = GUINT32_TO_BE(msgflags);
	hdr->lenctl = GUINT32_TO_BE(dstlen);
	hdr->lendata = GUINT32_TO_BE(srclen);
	hdr->dst = GUINT16_TO_BE((unsigned short)dbc->remote->dbid);
	hdr->src = GUINT16_TO_BE((unsigned short)dbc->rtdb->thisid);
	memcpy(msgbuf + sizeof(struct rep_msg_hdr), dbc->remote->host, dstlen);
	memcpy(msgbuf + sizeof(struct rep_msg_hdr) + dstlen,
	       dbc->rtdb->thisname, srclen);

	if (write(dbc->lk.fd, msgbuf, len) < len) {
		dbc->lk.state = DBC_DEAD;
		free(msgbuf);
		return -1;
	}
	dbc->lk.state = DBC_LOGIN;
	dbc->lk.explen = sizeof(struct rep_msg_hdr);
	dbc->lk.cnt = 0;
	free(msgbuf);
	return 0;
}

static int tdb_rep_resolve(struct tablerep *rtdb, int *family,
			   int addrsize, unsigned char *addr, int *addrlen,
			   const char *hostname, unsigned short port)
{
	char portstr[15];
	struct addrinfo hints;
	struct addrinfo *res, *res0;
	int rc;

	snprintf(portstr, sizeof(portstr), "%u", port);

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

		if (res->ai_addrlen > addrsize)		/* should not happen */
			continue;

		memcpy(addr, res->ai_addr, res->ai_addrlen);
		*addrlen = res->ai_addrlen;
		*family = res->ai_family;

		freeaddrinfo(res0);
		return 0;
	}

	freeaddrinfo(res0);

	applog(LOG_WARNING, "getaddrinfo(%s:%s): nothing suitable",
	       hostname, portstr);
	return -1;
}

static int rtdb_rep_connect(struct db_conn *dbc)
{
	struct db_link *dbl = &dbc->lk;
	struct db_remote *master = dbc->remote;
	int family;
	unsigned char addr[32];
	int addrlen;
	int rc;

	rc = tdb_rep_resolve(dbc->rtdb, &family, sizeof(addr), addr, &addrlen,
			     master->host, master->port);
	if (rc < 0)
		return -1;

	rc = socket(family, SOCK_STREAM, 0);
	if (rc < 0) {
		applog(LOG_WARNING, "socket: %s", strerror(errno));
		return -1;
	}
	dbl->fd = rc;

	if (connect(dbl->fd, (struct sockaddr *)addr, addrlen)) {
		applog(LOG_WARNING, "connect(host %s port %u): %s",
		       master->host, master->port, strerror(errno));
		close(dbl->fd);
		return -1;
	}

	if (fcntl(dbl->fd, F_SETFL, O_NONBLOCK) < 0) {
		applog(LOG_ERR, "fcntl: %s", strerror(errno));
		close(dbl->fd);
		return -1;
	}

	event_set(&dbl->rcev, dbl->fd, EV_READ | EV_PERSIST,
		  rtdb_slave_tcp_event, dbc);
	if (event_add(&dbl->rcev, NULL) < 0) {
		applog(LOG_ERR, "event_add failed");
		close(dbl->fd);
		return -1;
	}
	event_set(&dbl->wrev, dbl->fd, EV_WRITE | EV_PERSIST,
		  rtdb_wr_event, dbl);
	return 0;
}

static void __rtdb_fini(struct tablerep *rtdb)
{
	struct db_conn *dbc;

	if (rtdb->sockfd4 >= 0) {
		event_del(&rtdb->lsev4);
		close(rtdb->sockfd4);
		rtdb->sockfd4 = -1;
	}
	if (rtdb->sockfd6 >= 0) {
		event_del(&rtdb->lsev6);
		close(rtdb->sockfd6);
		rtdb->sockfd6 = -1;
	}

	while (!list_empty(&rtdb->conns)) {
		dbc = list_entry(rtdb->conns.next, struct db_conn, link);
		list_del(&dbc->link);
		dbc_free(dbc);
	}
	rtdb->mdbc = NULL;
}

/*
 * return:
 *  -1 - there was an error, things are in disarray, must call __rtdb_fini.
 *   0 - all is up, may call tdb_init if desired.
 *   1 - not done yet, just return to dispatch.
 */
static int __rtdb_start(struct tablerep *rtdb, bool we_are_master,
			struct db_remote *rep_master, unsigned short rep_port)
{
	struct db_conn *dbc;

	if (we_are_master) {
		if (rtdb->thisid == DBID_NONE)
			rtdb->thisid = make_remote_id();
		if (rtdb_rep_listen(rtdb, rep_port))
			return -1;
	} else {
		if (!rep_master) {
			applog(LOG_INFO, "No master yet"); /* P3 */
			return -1;
		}
		if (!rtdb->mdbc) {
			dbc = dbc_alloc(rtdb, rep_master);
			if (!dbc)
				return -1;
			dbc->lk.explen = sizeof(struct rep_msg_hdr);
			dbc->lk.state = DBC_INIT;
			list_add_tail(&dbc->link, &rtdb->conns);
			rtdb->mdbc = dbc;
		}
		switch (rtdb->mdbc->lk.state) {
		case DBC_OPEN:
			break;
		case DBC_INIT:
			if (rtdb_rep_connect(rtdb->mdbc))
				return -1;
			if (rtdb_slave_login(rtdb->mdbc))
				return -1;
			return 1;
		case DBC_LOGIN:
			/* P3 */ applog(LOG_INFO, "start: no answer");
			return -1;
		default:
			/* P3 */ applog(LOG_INFO, "start: confusion (state %d)",
						 rtdb->mdbc->lk.state);
			return -1;
		}
	}
	return 0;
}

int rtdb_init(struct tablerep *rtdb, const char *thisname)
{
	rtdb->thisname = thisname;

	INIT_LIST_HEAD(&rtdb->conns);
	rtdb->sockfd4 = -1;
	rtdb->sockfd6 = -1;

	// rtdb->mdbc = dbc_alloc(rtdb, NULL);
	// if (!rtdb->mdbc)
	// 	return -1;
	// rtdb->mdbc->lk.explen = sizeof(struct rep_msg_hdr);
	// rtdb->mdbc->lk.state = DBC_INIT;
	// list_add_tail(&rtdb->mdbc.link, &rtdb->conns);
	return 0;
}

int rtdb_start(struct tablerep *rtdb,
	       const char *db_home,
	       bool we_are_master,
	       struct db_remote *rep_master, unsigned short rep_port,
	       void (*cb)(enum db_event))
{
	int rc;

	rc = __rtdb_start(rtdb, we_are_master, rep_master, rep_port);
	if (rc < 0)
		goto err_out;
	if (rc > 0)
		return 0;

	/*
	 * Note that we only get here if either we're master, or slave
	 * and link is DBC_OPEN. In both cases rtdb->thidid must be set.
	 */
	if (rtdb->thisid == 0) {		/* never happens */
		applog(LOG_WARNING, "Zero own dbid, master %d", we_are_master);
		goto err_out;
	}
	if (tdb_init(&rtdb->tdb, db_home, NULL, "tabled", true,
		     rtdb->thisid, db4_rep_send, we_are_master, cb)) {
		goto err_out;
	}
	return 0;

err_out:
	__rtdb_fini(rtdb);
	return -1;
}

void rtdb_mc_reset(struct tablerep *rtdb, bool we_are_master,
		   struct db_remote *rep_master, unsigned short rep_port)
{
	int rc;

	__rtdb_fini(rtdb);
	rc = __rtdb_start(rtdb, we_are_master, rep_master, rep_port);
	if (rc < 0) {
		/*
		 * If we failed to reconnect immediately, we do not retry.
		 * This is because db4 has its own timeouts, so there's really
		 * no point in doing anything else: we would only interfere.
		 * From now on, rely on CLD to drive the attempts to reconnect.
		 */
		/* P3 */ applog(LOG_INFO, "failed to reconnect (%d)", rc);
	}
}

void rtdb_dbc_scrub(struct tablerep *rtdb)
{
	struct db_conn *dbc, *tmp;

	list_for_each_entry_safe(dbc, tmp, &rtdb->conns, link) {
		if (dbc->lk.state == DBC_DEAD) {
			/*
			 * This prinout is misleading, since every remote
			 * may have several connections. But how to fix it?
			 */
			if (dbc->remote) {
				applog(LOG_INFO, "Closing, peer %s",
				       dbc->remote->host);
			} else {
				applog(LOG_INFO, "Closing");
			}
			if (dbc == rtdb->mdbc)
				rtdb->mdbc = NULL;
			list_del(&dbc->link);
			dbc_free(dbc);
		}
	}
}

/*
 * This wants to be both in here and in tdb.c. Problem.
 */
int rtdb_restart(struct tablerep *rtdb, bool we_are_master)
{
	DB_ENV *dbenv = rtdb->tdb.env;
	unsigned int rep_flags;
	int rc;

	rep_flags = we_are_master ? DB_REP_MASTER : DB_REP_CLIENT;
	rc = dbenv->rep_start(dbenv, NULL, rep_flags);
	if (rc) {
		dbenv->err(dbenv, rc, "rep_start(0x%x)", rep_flags);
		return -1;
	}
	return 0;
}

void rtdb_fini(struct tablerep *rtdb)
{
	__rtdb_fini(rtdb);
	/*
	 * This check is ewwww, but unfortunately there's potentially a gap
	 * between DB going master and us bringing up the environment.
	 * If we condition the tdb_fini on DB status, we'll end crashing
	 * if the server terminates during the gap.
	 */
	if (rtdb->tdb.env)
		tdb_fini(&rtdb->tdb);
}

