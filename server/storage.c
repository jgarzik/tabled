
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
#include <netdb.h>
#include "tabled.h"

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

void stor_read_event(int fd, short events, void *userdata)
{
	struct open_chunk *cep = userdata;

	cep->r_armed = false;		/* no EV_PERSIST */
	if (cep->ocb)
		(*cep->ocb)(cep);
}

void stor_write_event(int fd, short events, void *userdata)
{
	struct open_chunk *cep = userdata;

	cep->w_armed = false;		/* no EV_PERSIST */
	if (cep->ocb)
		(*cep->ocb)(cep);
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

	if (sn->hostname == NULL || strcmp(sn->hostname, hostname) != 0) {
		free(sn->hostname);
		sn->hostname = strdup(hostname);
		if (!sn->hostname) {
			applog(LOG_WARNING, "No core");
			return -1;
		}
		sn->reported = false;
	}

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

static int stor_add_node_base(struct storage_node *sn, const char *base)
{
	if (sn->basepath == NULL || strcmp(sn->basepath, base) != 0) {
		free(sn->basepath);
		sn->basepath = strdup(base);
		if (!sn->basepath) {
			applog(LOG_WARNING, "No core");
			return -1;
		}
		sn->reported = false;
	}
	return 0;
}

static int stor_add_node_this(struct storage_node *sn,
			      enum storage_type type, const char *base,
			      const char *hostname, const char *portstr)
{
	sn->type = type;
	switch (type) {
	case STT_POSIX:
		sn->ops = &stor_ops_posix;
		return stor_add_node_base(sn, base);
	case STT_SWIFT:
		sn->ops = &stor_ops_swift;
		return stor_add_node_addr(sn, hostname, portstr);
	default:
		sn->ops = &stor_ops_chunk;
		return stor_add_node_addr(sn, hostname, portstr);
	}
}

void stor_add_node(uint32_t nid, enum storage_type type, const char *base,
		   const char *hostname, const char *portstr,
		   struct geo *locp)
{
	struct storage_node *sn;

	g_mutex_lock(tabled_srv.bigmutex);
	sn = _stor_node_by_nid(nid);
	if (sn) {
		stor_add_node_this(sn, type, base, hostname, portstr);
	} else {
		if ((sn = malloc(sizeof(struct storage_node))) == NULL) {
			applog(LOG_WARNING, "No core (%ld)",
			       (long) sizeof(struct storage_node));
			g_mutex_unlock(tabled_srv.bigmutex);
			return;
		}
		memset(sn, 0, sizeof(struct storage_node));
		sn->id = nid;

		if (stor_add_node_this(sn, type, base, hostname, portstr)) {
			free(sn->hostname);
			free(sn->basepath);
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

void stor_stats()
{
	struct storage_node *sn;
	time_t now;

	g_mutex_lock(tabled_srv.bigmutex);
	now = time(NULL);
	list_for_each_entry(sn, &tabled_srv.all_stor, all_link) {
		if (sn->last_up) {
			switch (sn->type) {
			case STT_POSIX:
				applog(LOG_INFO, "SN: nid %u %s ref %d"
				       " path %s last %lu (+ %ld)",
				       sn->id, sn->up? "up": "down",
				       sn->ref, sn->basepath,
				       (long) sn->last_up,
				       (long) (now - sn->last_up));
				break;
			default:
				applog(LOG_INFO, "SN: nid %u %s ref %d"
				       " name %s last %lu (+ %ld)",
				       sn->id, sn->up? "up": "down",
				       sn->ref, sn->hostname,
				       (long) sn->last_up,
				       (long) (now - sn->last_up));
			}
		} else {
			switch (sn->type) {
			case STT_POSIX:
				applog(LOG_INFO,
				       "SN: nid %u %s ref %d path %s",
				       sn->id, sn->up? "up": "down",
				       sn->ref, sn->basepath);
				break;
			default:
				applog(LOG_INFO,
				       "SN: nid %u %s ref %d name %s",
				       sn->id, sn->up? "up": "down",
				       sn->ref, sn->hostname);
			}
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
			switch (sn->type) {
			case STT_POSIX:
				rc = asprintf(&str,
					      "SN: nid %u %s ref %d path %s"
					      " last %lu (+ %ld)<br />\r\n",
					      sn->id, sn->up? "up": tag_down,
					      sn->ref, sn->basepath,
					      (long) sn->last_up,
					      (long) (now - sn->last_up));
				break;
			default:
				rc = asprintf(&str,
					      "SN: nid %u %s ref %d name %s"
					      " last %lu (+ %ld)<br />\r\n",
					      sn->id, sn->up? "up": tag_down,
					      sn->ref, sn->hostname,
					      (long) sn->last_up,
					      (long) (now - sn->last_up));
			}
		} else {
			switch (sn->type) {
			case STT_POSIX:
				rc = asprintf(&str, "SN: nid %u %s ref %d"
					      "path %s<br />\r\n",
					      sn->id, sn->up? "up": tag_down,
					      sn->ref, sn->basepath);
				break;
			default:
				rc = asprintf(&str, "SN: nid %u %s ref %d"
					      "name %s<br />\r\n",
					      sn->id, sn->up? "up": tag_down,
					      sn->ref, sn->hostname);
			}
		}
		if (rc < 0)
			break;
		content = g_list_append(content, str);
	}
	g_mutex_unlock(tabled_srv.bigmutex);
	return true;
}

