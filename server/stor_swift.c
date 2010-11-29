
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
#include <sys/socket.h>
#include <sys/select.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <glib.h>
#include <event.h>
#include "tabled.h"

/* #define SWIFT_AUTH_PORT 11000 */
#define SWIFT_ACCOUNT   "tabled"	/* hardcoded. add with swift-add-user */
#define SWIFT_CONTAINER "td"

static const char stor_key_fmt[] = STOR_KEY_FMT;

static size_t swift_fulfill(struct open_chunk *cep, void *buf, size_t req_len)
{
	struct open_buf *bp;
	size_t req_done;
	size_t len1;

	req_done = 0;
	for (;;) {
		if (req_done == req_len)
			break;
		if (list_empty(&cep->buf_list))
			break;
		bp = list_entry(cep->buf_list.next, struct open_buf, link);
/* P3 */ applog(LOG_INFO, "swift_fulfill req %ld/%ld bp %ld/%ld",
 (long)req_done, (long)req_len, (long)bp->done, (long)bp->length);
		len1 = bp->length - bp->done;
		if (len1 > req_len - req_done)
			len1 = req_len - req_done;
		memcpy(buf + req_done, bp->buf + bp->done, len1);
		bp->done += len1;
		if (bp->done == bp->length) {
			list_del(&bp->link);
			free(bp->buf);
			free(bp);
		}
		req_done += len1;
	}
/* P3 */ applog(LOG_INFO, "swift_fulfill return req %ld/%ld",
 (long)req_done, (long)req_len);
	return req_done;
}

static void swift_event(int fd, short events, void *arg)
{
	struct open_event *evt = arg;
	struct open_chunk *cep = evt->chunk;
	int		action_mask;
	int		numrun;
	CURLMcode	rcm;

	evt->armed = false;

	action_mask = 0;
	if (events & EV_READ)
		action_mask |= CURL_CSELECT_IN;
	if (events & EV_WRITE)
		action_mask |= CURL_CSELECT_OUT;
/* P3 */ applog(LOG_INFO, "swift evented action fd %d a.mask 0x%x", fd, action_mask);
	rcm = curl_multi_socket_action(cep->cmh, evt->fd, action_mask, &numrun);
	if (rcm == CURLM_CALL_MULTI_PERFORM) {
		/*
		 * Ignore the MULTI. Because... What to do now?
		 * The libevent's main loop cannot support the do_multi kludge.
		 */
		return;
	}
	if (rcm) {
		applog(LOG_ERR, "curl_multi_socket_action: %s",
		       curl_multi_strerror(rcm));
	}
}

static void swift_timeout(int fd, short events, void *arg)
{
	struct open_chunk *cep = arg;
	int		numrun;
	CURLMcode	rcm;

/* P3 */ applog(LOG_INFO, "swift_timeout action");
	cep->timeout = 0;
	rcm = curl_multi_socket_action(cep->cmh, CURL_SOCKET_TIMEOUT, 0,
				       &numrun);
	if (rcm == CURLM_CALL_MULTI_PERFORM) {
		/*
		 * Ignore the MULTI. Because... What to do now?
		 * The libevent's main loop cannot support the do_multi kludge.
		 */
/* P3 */ applog(LOG_INFO, "swift_timeout action, multi, numrun %d", numrun);
		return;
	}
	if (rcm) {
		applog(LOG_ERR, "curl_multi_socket_action: %s",
		       curl_multi_strerror(rcm));
	}
/* P3 */ applog(LOG_INFO, "swift_timeout action, nomulti, numrun %d", numrun);
}

/*
 * This is called when debugging is set, so use LOG_DEBUG indiscriminately.
 */
static int swift_dbcb(CURL *curl, curl_infotype type, char *text, size_t size,
		      void *arg)
{
	enum { IN_TEXT, IN_EOL } state;
	char tag;
	const char *s, *line;
	char *p;

	switch (type) {
	case CURLINFO_TEXT:
		tag = '*';
		break;
	case CURLINFO_HEADER_IN:
		tag = '<';
		break;
	case CURLINFO_HEADER_OUT:
		tag = '>';
		break;
	default:	/* ignoring data */
		return 0;
	}

	state = IN_TEXT;
	line = text;
	for (s = text; s < text + size && *s != 0; s++) {
		if (state == IN_TEXT) {
			if (*s == '\r' || *s == '\n') {
				p = strndup(line, s-line);
				if (p) {
					applog(LOG_DEBUG, "%c %s", tag, p);
					free(p);
				}
				state = IN_EOL;
			}
		} else {
			if (*s != '\r' && *s != '\n') {
				state = IN_TEXT;
				line = s;
			}
		}
	}
	if (state == IN_TEXT && s != line) {
		p = strndup(line, s-line);
		if (p) {
			applog(LOG_DEBUG, "%c %s", tag, p);
			free(p);
		}
	}
	return 0;
}

static int swift_tcb(CURLM *multi, long timeout_ms, void *arg)
{
	struct open_chunk *cep = arg;
	struct timeval tm;

/* P3 */ applog(LOG_INFO, "swift_tcb timeout %ld", timeout_ms);
	if (timeout_ms == -1) {
		if (cep->timeout) {
			event_del(&cep->timer);
			cep->timeout = 0;
		}
	} else {
		/*
		 * This will fail if curl ever wants to change the value of
		 * a pending timeout. Although, probably not worth fixing.
		 */
		if (!cep->timeout) {
			tm.tv_sec = timeout_ms / 1000;
			tm.tv_usec = (timeout_ms % 1000) * 1000;
			evtimer_add(&cep->timer, &tm);
			cep->timeout = timeout_ms+1;
		}
	}
	return 0;
}

static struct open_event *swift_fd_to_evt(struct open_chunk *cep, int fd)
{
	struct open_event *evt;

	list_for_each_entry(evt, &cep->evt_list, link) {
		if (evt->fd == fd)
			return evt;
	}
	return NULL;
}

static void swift_setup_evt(struct open_chunk *cep, int fd,
			    unsigned int new_mask)
{
	struct open_event *evt;

	evt = swift_fd_to_evt(cep, fd);
	if (evt) {
/* P3 */ applog(LOG_INFO, "swift setup existing fd %d mask 0x%x>0x%x", fd, evt->mask, new_mask);
		if (evt->armed) {
			event_del(&evt->evt);
			evt->armed = false;
		}
	} else {
/* P3 */ applog(LOG_INFO, "swift setup new fd %d mask 0>0x%x", fd, new_mask);
		evt = malloc(sizeof(struct open_event));
		if (!evt) {
			applog(LOG_ERR, "no core for event");
			return;
		}
		memset(evt, 0, sizeof(struct open_event));
		evt->chunk = cep;
		evt->fd = fd;
		list_add_tail(&evt->link, &cep->evt_list);
	}

	event_set(&evt->evt, fd, new_mask, swift_event, evt);
	event_base_set(cep->evbase, &evt->evt);
	if (new_mask) {
		event_add(&evt->evt, NULL);
		evt->armed = true;
	}
	evt->mask = new_mask;
}

/*
 * Docs promise to link s and s_arg, but obviously they can't link anything
 * when s is new and being registered. Maybe we can check for NULL s_arg,
 * but it's not documented. Therefore we must look up anyway.
 */
static int swift_scb(CURL *easy, curl_socket_t fd, int action, void *arg,
		     void *s_arg)
{
	struct open_chunk *cep = arg;
	struct open_event *evt;

	switch (action) {
	case CURL_POLL_NONE:
		swift_setup_evt(cep, fd, 0);
		break;
	case CURL_POLL_IN:
		swift_setup_evt(cep, fd, EV_READ);
		break;
	case CURL_POLL_OUT:
		swift_setup_evt(cep, fd, EV_WRITE);
		break;
	case CURL_POLL_INOUT:
		swift_setup_evt(cep, fd, EV_READ|EV_WRITE);
		break;
	case CURL_POLL_REMOVE:
		evt = swift_fd_to_evt(cep, fd);
		if (!evt) {
			applog(LOG_ERR, "removing non-existing socket %d", fd);
			break;
		}
/* P3 */ applog(LOG_INFO, "swift scb remove fd %d", fd);
		list_del(&evt->link);
		if (evt->armed)
			event_del(&evt->evt);
		free(evt);
		break;
	default:
/* P3 */ applog(LOG_INFO, "swift_scb unknown action %d", action);
		;
	}
	return 0;
}

static size_t swift_wcb_discard(void *ptr, size_t bsz, size_t nmemb, void *p)
{
	return bsz*nmemb;
}

static size_t swift_rcb_null(void *ptr, size_t bsz, size_t nmemb, void *p)
{
	return 0;
}

/*
 * Curl has a weird convention where "write" callback is called when
 * it wants to "write" something into the application, and not when
 * application needs to write something to the webserver. So, backwards.
 */
static size_t swift_wcb(void *ptr, size_t bsz, size_t nmemb, void *arg)
{
	struct open_chunk *cep = arg;
	unsigned char *buf;
	struct open_buf *bp;

	/*
	 * Before anything else, we save the incoming data, because if we
	 * consume more, curl may abort the transfer.
	 */
	bp = malloc(sizeof(struct open_buf));
	if (!bp)
		return 0;
	buf = malloc(nmemb);
	if (!buf) {
		free(bp);
		return 0;
	}
	memcpy(buf, ptr, nmemb);
	bp->buf = buf;
	bp->length = nmemb;
	bp->done = 0;
	list_add_tail(&bp->link, &cep->buf_list);
/* P3 */ applog(LOG_INFO, "swift_wcb added bp 0/%ld", (long)bp->length);

#if 0 /* actually, what's the worst that can happen? */
	struct open_event *pos;
	/*
	 * With data saved, let's consider flow control. Note that if we had
	 * a 1:1 relationship between swift_event and swift_wcb, we would not
	 * need to do anything here, since our events are auto-clearing.
	 * However, in case curl gets too smart, choke them all.
	 */
	list_for_each_entry(pos, &cep->evt_list, link) {
		if (pos->armed) {
			event_del(&pos->evt);
			pos->armed = false;
		}
	}
#endif

	if (cep->ocb)
		(*cep->ocb)(cep);

	return nmemb;
}

static size_t swift_rcb(void *ptr, size_t bsz, size_t nmemb, void *arg)
{
	struct open_chunk *cep = arg;
	ssize_t req_done;
	struct open_event *evt;

/* P3 */ applog(LOG_INFO, "swift_rcb cep %p", cep);
	req_done = swift_fulfill(cep, ptr, nmemb);
	if (req_done == 0) {
/* P3 */ applog(LOG_INFO, "swift_rcb no data");
		list_for_each_entry(evt, &cep->evt_list, link) {
			if (evt->armed) {
				event_del(&evt->evt);
				evt->armed = false;
			}
		}
	}
	return req_done;
}

/*
 * Extract value after the colon in an http header, usually not nul-terminated.
 */
static char *http_tokval(const char *buf, size_t size)
{
	const char *s;
	const char *val;
	char *ret;
	size_t len;

	s = buf;
	for (;;) {
		if (s >= buf + size)
			goto drop;
		if (*s != ' ')
			break;
		s++;
	}
	val = s;
	for (;;) {
		if (s >= buf + size)
			break;
		if (*s == '\r' || *s == '\n' || *s == 0)
			break;
		s++;
	}
	len = s - val;
	ret = malloc(len + 1);
	if (!ret)
		goto drop;
	memcpy(ret, val, len);
	ret[len] = 0;
	return ret;

 drop:
	return NULL;
}

struct swift_auth_ctx {
	char *token;
	char *url;
};

static size_t swift_hcb_auth(void *ptr, size_t bsz, size_t nmemb, void *arg)
{
	struct swift_auth_ctx *ctx = arg;
	char *buf = ptr;
	char *s;
	static const char tokstr[] = "X-Storage-Token";
	static const char urlstr[] = "X-Storage-Url";

	s = memchr(buf, ':', nmemb);
	if (!s)
		goto drop;
	if (buf >= s)
		goto drop;
	if (s-buf == sizeof(tokstr)-1 &&
	    memcmp(buf, tokstr, sizeof(tokstr)-1) == 0) { /* XXX memcasecmp? */
		s++;	// skip colon
		s = http_tokval(s, buf + nmemb - s);
		if (!s)
			goto drop;
		free(ctx->token);
		ctx->token = s;
	} else if (s-buf == sizeof(urlstr)-1 &&
		   memcmp(buf, urlstr, sizeof(urlstr)-1) == 0) {
		s++;	// skip colon
		s = http_tokval(s, buf + nmemb - s);
		if (!s)
			goto drop;
		free(ctx->url);
		ctx->url = s;
	}
 drop:
	return nmemb;
}

struct swift_read_ctx {
	uint64_t size;
	bool headers_done;
	bool size_known;
};

static size_t swift_hcb_read(void *ptr, size_t bsz, size_t nmemb, void *arg)
{
	struct swift_read_ctx *ctx = arg;
	long long size;
	char *buf = ptr;
	char *s;
	static const char lenstr[] = "Content-Length";

/* P3 */ applog(LOG_INFO, "swift hcb_read [%d]", (int) nmemb);
	s = memchr(buf, ':', nmemb);
	if (!s) {
		if (buf[0] == '\r' || buf[0] == '\n')
			ctx->headers_done = true;
		goto drop;
	}
	if (buf >= s)
		goto drop;
	if (s-buf == sizeof(lenstr)-1 &&
	    memcmp(buf, lenstr, sizeof(lenstr)-1) == 0) { /* XXX memcasecmp? */
		s++;	// skip colon
		s = http_tokval(s, buf + nmemb - s);
		if (!s)
			goto drop;
		size = strtoll(s, NULL, 10);
		if (size < 0) {
			free(s);
			goto drop;
		}
		ctx->size = size;
		ctx->size_known = true;
		free(s);
	}
 drop:
	return nmemb;
}

static int swift_runcurl(struct open_chunk *cep)
{
	fd_set rset, wset, eset;
	struct open_event *evt;
	int		numrun;
	int		nfds;
	struct timeval	tmo;
	int		action_mask;
	int		i;
	CURLMcode	rcm;
	int		rc;

	nfds = 0;
	FD_ZERO(&rset);
	FD_ZERO(&wset);
	FD_ZERO(&eset);
	list_for_each_entry(evt, &cep->evt_list, link) {
/* P3 */ applog(LOG_INFO, "swift runcurl fd %d mask 0x%x", evt->fd, evt->mask);
		if (evt->fd >= nfds)
			nfds = evt->fd + 1;
		if (evt->mask & EV_READ)
			FD_SET(evt->fd, &rset);
		if (evt->mask & EV_WRITE)
			FD_SET(evt->fd, &wset);
		if (evt->mask & (EV_READ|EV_WRITE))
			FD_SET(evt->fd, &eset);
	}

	/*
	 * This is rather bogus, because multi is not always a timeout.
	 * Perhaps this is why it's supposed to be removed from libcurl.
	 * For now, support it as well as we can.
	 */
	if (cep->do_multi) {
		cep->do_multi = false;
/* P3 */ applog(LOG_INFO, "swift runcurl multi action");
		rcm = curl_multi_socket_action(cep->cmh, CURL_SOCKET_TIMEOUT, 0,
					       &numrun);
		if (rcm == CURLM_CALL_MULTI_PERFORM) {
			cep->do_multi = true;
/* P3 */ applog(LOG_INFO, "swift runcurl multi done, multi, numrun %d", numrun);
			return 0;
		}
		if (rcm)
			applog(LOG_ERR, "curl_multi_socket_action failed: %s",
			       curl_multi_strerror(rcm));
/* P3 */ applog(LOG_INFO, "swift runcurl multi done, nomulti, numrun %d", numrun);
		return 0;
	}

	if (cep->timeout) {
/* P3 */ applog(LOG_INFO, "swift runcurl timeout %ld", cep->timeout);
		tmo.tv_sec = cep->timeout / 1000;
		tmo.tv_usec = (cep->timeout % 1000) * 1000;
		rc = select(nfds, &rset, &wset, &eset, &tmo);
	} else {
/* P3 */ applog(LOG_INFO, "swift runcurl select");
		rc = select(nfds, &rset, &wset, &eset, NULL);
	}
	if (rc < 0) {
		applog(LOG_ERR, "select error: %s", strerror(errno));
		return -1;
	}
	if (rc == 0) {
		cep->do_multi = false;
/* P3 */ applog(LOG_INFO, "swift runcurl timed out action");
		rcm = curl_multi_socket_action(cep->cmh, CURL_SOCKET_TIMEOUT, 0,
					       &numrun);
		if (rcm == CURLM_CALL_MULTI_PERFORM) {
			cep->do_multi = true;
/* P3 */ applog(LOG_INFO, "swift runcurl timeout done, multi, numrun %d", numrun);
			return 0;
		}
		if (rcm)
			applog(LOG_ERR, "curl_multi_socket_action failed: %s",
			       curl_multi_strerror(rcm));
/* P3 */ applog(LOG_INFO, "swift runcurl timeout done, nomulti, numrun %d", numrun);
		return 0;
	}

	numrun = -1;
	for (i = 0; i < nfds; i++) {
		action_mask = 0;
		/*
		 * Not checking the curl registration mask here because
		 * we account for it when populate the bit sets above.
		 */
		if (FD_ISSET(i, &rset))
			action_mask |= CURL_CSELECT_IN;
		if (FD_ISSET(i, &wset))
			action_mask |= CURL_CSELECT_OUT;
		if (FD_ISSET(i, &eset))
			action_mask |= CURL_CSELECT_ERR;
		if (action_mask) {
			cep->do_multi = false;
/* P3 */ applog(LOG_INFO, "swift runcurl selected action fd %d a.mask 0x%x", i, action_mask);
			rcm = curl_multi_socket_action(cep->cmh, i, action_mask,
						       &numrun);
			if (rcm == CURLM_CALL_MULTI_PERFORM)
				cep->do_multi = true;
			if (rcm) {
				applog(LOG_ERR,
				       "curl_multi_socket_action error: %s",
				       curl_multi_strerror(rcm));
			}
		}
	}

/* P3 */ applog(LOG_INFO, "swift runcurl done, multi %d, numrun %d", cep->do_multi, numrun);
	return 0;
}

static void swift_dispose(struct open_chunk *cep)
{
	struct open_event *evt;
	struct open_buf *bp;

	while (!list_empty(&cep->evt_list)) {
		evt = list_entry(cep->evt_list.next, struct open_event, link);
		list_del(&evt->link);
		if (evt->armed)
			event_del(&evt->evt);
		free(evt);
	}
	while (!list_empty(&cep->buf_list)) {
		bp = list_entry(cep->buf_list.next, struct open_buf, link);
		list_del(&bp->link);
/* P3 */ applog(LOG_INFO, "swift_dispose bp %ld/%ld",
 (long)bp->done, (long)bp->length);
		free(bp->buf);
		free(bp);
	}
}

static int cf_open(struct open_chunk *cep, struct storage_node *stn,
		   struct event_base *ev_base)
{
	if (cep->cmh)
		return -EBUSY;

	cep->cmh = curl_multi_init();
	if (!cep->cmh)
		return -ENOMEM;

	curl_multi_setopt(cep->cmh, CURLMOPT_SOCKETFUNCTION, swift_scb);
	curl_multi_setopt(cep->cmh, CURLMOPT_SOCKETDATA, cep);
	curl_multi_setopt(cep->cmh, CURLMOPT_TIMERFUNCTION, swift_tcb);
	curl_multi_setopt(cep->cmh, CURLMOPT_TIMERDATA, cep);

	cep->evbase = ev_base;
	cep->node = stor_node_get(stn);
	evtimer_set(&cep->timer, swift_timeout, cep);
	event_base_set(ev_base, &cep->timer);

	return 0;
}

static int cf_open_read(struct open_chunk *cep,
			void (*cb)(struct open_chunk *),
			uint64_t key, uint64_t *psize)
{
	char stckey[STOR_KEY_SLEN+1];
	struct curl_slist *req_hdrs, *h;
	struct swift_read_ctx rsp_ctx;
	char		*url, *tok;
	CURL		*curl;
	CURLMcode	rcm;
	int		rc;

	if (cep->key)		/* this also allows to make do with one c1h */
		return -EBUSY;
	if (!cep->cmh)
		return -EINVAL;

	req_hdrs = NULL;
	memset(&rsp_ctx, 0, sizeof(struct swift_read_ctx));

	sprintf(stckey, stor_key_fmt, (unsigned long long) key);
	rc = asprintf(&url, "%s/%s/%s",
		      cep->node->auth_url, SWIFT_CONTAINER, stckey);
	if (rc < 0)
		goto err_url;
	rc = asprintf(&tok, "X-Auth-Token: %s", cep->node->auth_token);
	if (rc < 0)
		goto err_tok;

	curl = curl_easy_init();
	if (!curl)
		goto err_curl;

	h = curl_slist_append(req_hdrs, tok);
	if (!h)
		goto err_hdr_1;
	req_hdrs = h;
	h = curl_slist_append(req_hdrs, "Content-Type: binary/octet-stream");
	if (!h)
		goto err_hdr_all;
	req_hdrs = h;

	// curl_easy_reset(curl);  /* not needed after curl_easy_init */
	curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, swift_dbcb);
	if (debugging) /* if (verbose) */
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_hdrs);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, swift_wcb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, cep);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, swift_hcb_read);
	curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &rsp_ctx);

	/* this sets a fake timeout for bootstrapping */
	rcm = curl_multi_add_handle(cep->cmh, curl);
	if (rcm) {
		applog(LOG_ERR, "curl_multi_add_handle error: %s",
		       curl_multi_strerror(rcm));
		goto err_multi_add_handle;
	}

/* P3 */ applog(LOG_INFO, "swift open_read %s runcurling", stckey);
	/*
	 * If we exit this loop as soon as rsp_ctx.size_known is set,
	 * swift_hcb_read gets called with a wild argument pointer. So don't.
	 *
	 * Also, note that we go runcurl with ocb NULL. This prevents
	 * object_get_poke from crashing with NULL cli, since it's not yet
	 * ready to take any callbacks when opening the chunk.
	 */
	while (!rsp_ctx.headers_done) {
		rc = swift_runcurl(cep);
		if (rc)
			return -EIO;
	}
	if (!rsp_ctx.size_known) {
		/*
		 * XXX This may happen in recoverable conditions, such as
		 * authentication token expired (it lives for 24 hours).
		 */
		applog(LOG_WARNING, "size of object %llX on nid %u is unknown",
		       key, cep->node->id);
		return -EIO;
	}
/* P3 */ applog(LOG_INFO, "size of object %llX on nid %u is %ld",
  key, cep->node->id, (long)rsp_ctx.size);

	*psize = rsp_ctx.size;
	cep->size = rsp_ctx.size;
	cep->done = 0;
	cep->key = key;
	cep->ocb = cb;
	cep->c1h = curl;

	if (debugging)
		applog(LOG_INFO, "swift nid %u get %s size %lld",
		       cep->node->id, stckey, (long long) rsp_ctx.size);
	return 0;

 err_multi_add_handle:
 err_hdr_all:
	curl_slist_free_all(req_hdrs);
 err_hdr_1:
	curl_easy_cleanup(curl);
 err_curl:
	free(tok);
 err_tok:
	free(url);
 err_url:
	return -ENOMEM;
}

static void cf_close(struct open_chunk *cep)
{

	if (cep->timeout) {
		event_del(&cep->timer);
		cep->timeout = 0;
	}

	if (cep->cmh) {
		if (cep->c1h) {
			curl_multi_remove_handle(cep->cmh, cep->c1h);
			curl_easy_cleanup(cep->c1h);
			cep->c1h = NULL;
		}
		stor_node_put(cep->node);
		cep->node = NULL;
		curl_multi_cleanup(cep->cmh);
		cep->cmh = NULL;
	}

	swift_dispose(cep);
	cep->key = 0;
}

static void cf_abort(struct open_chunk *cep)
{
	if (cep->timeout) {
		event_del(&cep->timer);
		cep->timeout = 0;
	}
	if (cep->cmh) {
		if (cep->c1h) {
			curl_multi_remove_handle(cep->cmh, cep->c1h);
			curl_easy_cleanup(cep->c1h);
			cep->c1h = NULL;
		}
	}
	swift_dispose(cep);

	/* XXX delete the unfinished object */
	cep->key = 0;
}

static int cf_put_start(struct open_chunk *cep,
			void (*cb)(struct open_chunk *),
			uint64_t key, uint64_t size)
{
	char stckey[STOR_KEY_SLEN+1];
	struct curl_slist *req_hdrs, *h;
	char		*url, *tok, *len;
	CURL		*curl;
	int		numrun;
	CURLMcode	rcm;
	int		rc;

	if (cep->key)		/* this also allows to make do with one c1h */
		return -EBUSY;
	if (!cep->cmh)
		return -EINVAL;

	req_hdrs = NULL;

	sprintf(stckey, stor_key_fmt, (unsigned long long) key);
	rc = asprintf(&url, "%s/%s/%s",
		      cep->node->auth_url, SWIFT_CONTAINER, stckey);
	if (rc < 0)
		goto err_url;
	rc = asprintf(&tok, "X-Auth-Token: %s", cep->node->auth_token);
	if (rc < 0)
		goto err_tok;
	rc = asprintf(&len, "Content-Length: %lld", (long long) size);
	if (rc < 0)
		goto err_len;

	curl = curl_easy_init();
	if (!curl)
		goto err_curl;

	h = curl_slist_append(req_hdrs, tok);
	if (!h)
		goto err_hdr_1;
	req_hdrs = h;
	/*
	 * 5.2 Storage Services
	 *  No response body is returned. A status code of 201 (Created)
	 *  indicates a successful write, status 412 (Length Required) denotes
	 *  a missing Content-Length or Content-Type header in the request.
	 *  If the MD5 checksum of the data written to the storage system does
	 *  NOT match the (optionally) supplied ETag value, a 422 (Unproces-
	 *  sable Entity) response is returned.
	 */
	h = curl_slist_append(req_hdrs, len);
	if (!h)
		goto err_hdr_all;
	req_hdrs = h;
	h = curl_slist_append(req_hdrs, "Content-Type: binary/octet-stream");
	if (!h)
		goto err_hdr_all;
	req_hdrs = h;

	// curl_easy_reset(curl);  /* not needed after curl_easy_init */
	curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, swift_dbcb);
	if (debugging) /* if (verbose) */
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_hdrs);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)size);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, swift_rcb);
	curl_easy_setopt(curl, CURLOPT_READDATA, cep);

	rcm = curl_multi_add_handle(cep->cmh, curl);
	if (rcm) {
		applog(LOG_ERR, "curl_multi_add_handle error: %s",
		       curl_multi_strerror(rcm));
		goto err_multi_add_handle;
	}

	cep->size = size;
	cep->done = 0;
	cep->key = key;
	cep->ocb = cb;
	cep->c1h = curl;

	rcm = curl_multi_socket_action(cep->cmh, CURL_SOCKET_TIMEOUT, 0,
				       &numrun);
	if (rcm == CURLM_CALL_MULTI_PERFORM) {
		/* P3 */ applog(LOG_INFO, "swift put_start booted to Multi");
	} else if (rcm) {
		/* P3 */ applog(LOG_INFO, "swift put_start booted to error: %s",
		       curl_multi_strerror(rcm));
	} else {
		/* P3 */ applog(LOG_INFO, "swift put_start booted ok");
	}
	if (debugging)
		applog(LOG_INFO, "swift nid %u put %s size %lld",
		       cep->node->id, stckey, (long long) size);
	return 0;

 err_multi_add_handle:
 err_hdr_all:
	curl_slist_free_all(req_hdrs);
 err_hdr_1:
	curl_easy_cleanup(curl);
 err_curl:
	free(len);
 err_len:
	free(tok);
 err_tok:
	free(url);
 err_url:
	return -ENOMEM;
}

static ssize_t cf_put_buf(struct open_chunk *cep, void *data, size_t len)
{
	unsigned char *buf;
	struct open_buf *bp;
	struct open_event *evt;

	/*
	 * Try to implement highwater of 1. Sure to damage performance,
	 * but let's just get things running first.
	 */
	if (!list_empty(&cep->buf_list)) {
 /* P3 */ applog(LOG_INFO, "swift put_buf full, len %ld", (long)len);
		len = 0;
	} else {
		bp = malloc(sizeof(struct open_buf));
		if (!bp)
			return 0;
		buf = malloc(len);
		if (!buf) {
			if (debugging)
				applog(LOG_DEBUG, "no buf, len %ld", (long)len);
			free(bp);
			return 0;
		}
		memcpy(buf, data, len);
		bp->buf = buf;
		bp->length = len;
		bp->done = 0;
		list_add_tail(&bp->link, &cep->buf_list);
 /* P3 */ applog(LOG_INFO, "swift put_buf done cep %p, bp 0/%ld", cep, (long)len);
	}

	list_for_each_entry(evt, &cep->evt_list, link) {
		if (evt->mask && !evt->armed) {
			event_add(&evt->evt, NULL);
			evt->armed = true;
		}
	}
	return len;
}

/*
 * This basically waits for network buffers to drain. Unfortunately,
 * unlike chunk, in swift's case we have our own buffers to drain.
 * Solution: runcurl again. Oh well. Kernel buffers can get us stuck too,
 * and the problem is insoluble until we go full threads.
 */
static bool cf_put_end(struct open_chunk *cep)
{
	struct open_event *evt;
	int rc;

	if (!cep->cmh)
		return true;
	while (!list_empty(&cep->buf_list)) {
		rc = swift_runcurl(cep);
		if (rc)
			return false;
	}

	/*
	 * In chunk, we kill off events ahead of time for simplicity,
	 * because stc_put_sync is just write() and close(). But here we
	 * may get them re-enabled as a side effect of callbacks triggered
	 * by runcurl. So, kill events after we're done draining.
	 */
	list_for_each_entry(evt, &cep->evt_list, link) {
		if (evt->armed) {
			event_del(&evt->evt);
			evt->armed = false;
		}
	}

	return true;
}

static ssize_t cf_get_buf(struct open_chunk *cep, void *data, size_t req_len)
{
	ssize_t req_done;
	struct open_event *evt;

	/*
	 * Step 1: fulfill the request from outstanding buffers.
	 */
	req_done = swift_fulfill(cep, data, req_len);

	/*
	 * Step 2: update counts and auto-close the back-end if finished.
	 */
	cep->done += req_done;
	if (cep->done >= cep->size) {
		cep->done = 0;
		cep->size = 0;
		curl_multi_remove_handle(cep->cmh, cep->c1h);
		curl_easy_cleanup(cep->c1h);
		cep->c1h = NULL;
		swift_dispose(cep);
		return req_done;
	}

	/*
	 * Step 3: re-enable the back-end if low water (for now, 0).
	 * We re-arm events indiscriminately in case we suppressed them.
	 */
	if (req_done != req_len) {
		list_for_each_entry(evt, &cep->evt_list, link) {
			if (evt->mask && !evt->armed) {
				event_add(&evt->evt, NULL);
				evt->armed = true;
			}
		}
	}

	return req_done;
}

static int cf_obj_del(struct storage_node *stn, uint64_t key)
{
	char stckey[STOR_KEY_SLEN+1];
	struct curl_slist *req_hdrs, *h;
	char		*url, *tok;
	CURL		*curl;
	int		rc;

	req_hdrs = NULL;

	sprintf(stckey, stor_key_fmt, (unsigned long long) key);
	rc = asprintf(&url, "%s/%s/%s",
		      stn->auth_url, SWIFT_CONTAINER, stckey);
	if (rc < 0)
		goto err_url;
	rc = asprintf(&tok, "X-Auth-Token: %s", stn->auth_token);
	if (rc < 0)
		goto err_tok;

	curl = curl_easy_init();
	if (!curl)
		goto err_curl;

	h = curl_slist_append(req_hdrs, tok);
	if (!h)
		goto err_hdr_1;
	req_hdrs = h;
	h = curl_slist_append(req_hdrs, "Content-Type: binary/octet-stream");
	if (!h)
		goto err_hdr_all;
	req_hdrs = h;

	// curl_easy_reset(curl);  /* not needed after curl_easy_init */
	curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, swift_dbcb);
	if (debugging) /* if (verbose) */
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_hdrs);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_NOBODY, 1);

	rc = curl_easy_perform(curl);
/* P3 */ applog(LOG_INFO, "swift obj_del rc %d", rc);

	curl_easy_cleanup(curl);
	curl_slist_free_all(req_hdrs);
	free(tok);
	free(url);
	return rc == 0;

 err_hdr_all:
	curl_slist_free_all(req_hdrs);
 err_hdr_1:
	curl_easy_cleanup(curl);
 err_curl:
	free(tok);
 err_tok:
	free(url);
 err_url:
	return false;
}

/*
 * XXX This is basically the same thing cf_open_read, only does HEAD instead
 * of GET, and executes with curl_easy_perform. Needs refactoring.
 */
static bool cf_obj_test(struct open_chunk *cep, uint64_t key)
{
	char stckey[STOR_KEY_SLEN+1];
	struct curl_slist *req_hdrs, *h;
	char		*url, *tok;
	CURL		*curl;
	int		rc;

	req_hdrs = NULL;

	sprintf(stckey, stor_key_fmt, (unsigned long long) key);
	rc = asprintf(&url, "%s/%s/%s",
		      cep->node->auth_url, SWIFT_CONTAINER, stckey);
	if (rc < 0)
		goto err_url;
	rc = asprintf(&tok, "X-Auth-Token: %s", cep->node->auth_token);
	if (rc < 0)
		goto err_tok;

	curl = curl_easy_init();
	if (!curl)
		goto err_curl;

	h = curl_slist_append(req_hdrs, tok);
	if (!h)
		goto err_hdr_1;
	req_hdrs = h;
	h = curl_slist_append(req_hdrs, "Content-Type: binary/octet-stream");
	if (!h)
		goto err_hdr_all;
	req_hdrs = h;

	// curl_easy_reset(curl);  /* not needed after curl_easy_init */
	curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, swift_dbcb);
	if (debugging) /* if (verbose) */
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_hdrs);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_NOBODY, 1);

	rc = curl_easy_perform(curl);
/* P3 */ applog(LOG_INFO, "swift obj_test rc %d", rc);

	curl_easy_cleanup(curl);
	curl_slist_free_all(req_hdrs);
	free(tok);
	free(url);
	return rc == 0;

 err_hdr_all:
	curl_slist_free_all(req_hdrs);
 err_hdr_1:
	curl_easy_cleanup(curl);
 err_curl:
	free(tok);
 err_tok:
	free(url);
 err_url:
	return false;
}

/*
 * XXX temporary side effect as result - stored auth & url in storage_node
 */
static int swift_auth(struct storage_node *stn)
{
	struct curl_slist *req_hdrs, *h;
	struct swift_auth_ctx rsp_hdrs;
	CURL		*curl;
	char		*url, *user, *pass;
	unsigned short	port;
	int		rc;

	req_hdrs = NULL;
	memset(&rsp_hdrs, 0, sizeof(struct swift_auth_ctx));

	port = ntohs(stn->addr.sin6_port);	/* union match for IPv4 too */
	rc = asprintf(&url, "http://%s:%u/v1.0", stn->hostname, port);
	if (rc < 0)
		goto err_url;
	rc = asprintf(&user, "X-Storage-User: " SWIFT_ACCOUNT ":%s",
		      tabled_srv.chunk_user);
	if (rc < 0)
		goto err_user;
	rc = asprintf(&pass, "X-Storage-Pass: %s", tabled_srv.chunk_key);
	if (rc < 0)
		goto err_pass;

	curl = curl_easy_init();
	if (!curl)
		goto err_curl;

	h = curl_slist_append(req_hdrs, user);
	if (!h)
		goto err_hdr_1;
	req_hdrs = h;
	h = curl_slist_append(req_hdrs, pass);
	if (!h)
		goto err_hdr_all;
	req_hdrs = h;

	// curl_easy_reset(curl);  /* not needed after curl_easy_init */
	curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, swift_dbcb);
	if (debugging) /* if (verbose) */
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_hdrs);
	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, swift_wcb_discard);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, swift_hcb_auth);
	curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &rsp_hdrs);

	// curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);  /* telnet only */

	rc = curl_easy_perform(curl);

	curl_easy_cleanup(curl);
	curl_slist_free_all(req_hdrs);
	free(pass);
	free(user);
	free(url);

	if (rc) {
		applog(LOG_WARNING, "nid %u: auth error", stn->id);
		return -1;
	}

	if (!rsp_hdrs.token) {
		applog(LOG_WARNING, "nid %u: auth ok but no token", stn->id);
	} else if (!rsp_hdrs.url) {
		applog(LOG_WARNING, "nid %u: auth ok but no url", stn->id);
	} else {
		if (debugging)
			applog(LOG_INFO, "auth ok token <%s> url <%s>",
			   rsp_hdrs.token, rsp_hdrs.url);
	}

	free(stn->auth_url);
	stn->auth_url = rsp_hdrs.url;
	free(stn->auth_token);
	stn->auth_token = rsp_hdrs.token;
	return 0;

 err_hdr_all:
	curl_slist_free_all(req_hdrs);
 err_hdr_1:
	curl_easy_cleanup(curl);
 err_curl:
	free(pass);
 err_pass:
	free(user);
 err_user:
	free(url);
 err_url:
	return -1;
}

static int swift_mkbin(struct storage_node *stn, char *bin)
{
	struct curl_slist *req_hdrs, *h;
	CURL		*curl;
	char		*url, *tok;
	int		rc;

	req_hdrs = NULL;

	rc = asprintf(&url, "%s/%s", stn->auth_url, bin);
	if (rc < 0)
		goto err_url;
	rc = asprintf(&tok, "X-Auth-Token: %s", stn->auth_token);
	if (rc < 0)
		goto err_tok;

	curl = curl_easy_init();
	if (!curl)
		goto err_curl;

	h = curl_slist_append(req_hdrs, tok);
	if (!h)
		goto err_hdr_1;
	req_hdrs = h;

	// curl_easy_reset(curl);  /* not needed after curl_easy_init */
	curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, swift_dbcb);
	if (debugging) /* if (verbose) */
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_hdrs);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0);
	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, swift_rcb_null);
	curl_easy_setopt(curl, CURLOPT_READDATA, NULL);
	// curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);  /* telnet only */

	rc = curl_easy_perform(curl);

	curl_easy_cleanup(curl);
	curl_slist_free_all(req_hdrs);
	free(tok);
	free(url);

	if (rc) {
		applog(LOG_WARNING, "nid %u: container %s creation error",
		       stn->id, bin);
		return -1;
	}
	return 0;

// err_hdr_all:
//	curl_slist_free_all(req_hdrs);
 err_hdr_1:
	curl_easy_cleanup(curl);
 err_curl:
	free(tok);
 err_tok:
	free(url);
 err_url:
	return -1;
}

static int swift_tstbin(struct storage_node *stn, char *bin)
{
	struct curl_slist *req_hdrs, *h;
	CURL		*curl;
	char		*url, *tok;
	int		rc;

	req_hdrs = NULL;

	rc = asprintf(&url, "%s/%s", stn->auth_url, bin);
	if (rc < 0)
		goto err_url;
	rc = asprintf(&tok, "X-Auth-Token: %s", stn->auth_token);
	if (rc < 0)
		goto err_tok;

	curl = curl_easy_init();
	if (!curl)
		goto err_curl;

	h = curl_slist_append(req_hdrs, tok);
	if (!h)
		goto err_hdr_1;
	req_hdrs = h;

	// curl_easy_reset(curl);  /* not needed after curl_easy_init */
	curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, swift_dbcb);
	if (debugging) /* if (verbose) */
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_hdrs);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_NOBODY, 1);

	rc = curl_easy_perform(curl);

	curl_easy_cleanup(curl);
	curl_slist_free_all(req_hdrs);
	free(tok);
	free(url);

	if (rc) {
		applog(LOG_WARNING, "nid %u: container %s test error",
		       stn->id, bin);
		return -1;
	}
	return 0;

// err_hdr_all:
//	curl_slist_free_all(req_hdrs);
 err_hdr_1:
	curl_easy_cleanup(curl);
 err_curl:
	free(tok);
 err_tok:
	free(url);
 err_url:
	return -1;
}

static int cf_node_check(struct storage_node *stn)
{
	if (stn->auth_token) {
		if (swift_tstbin(stn, SWIFT_CONTAINER))
			return -1;
	} else {
		/*
		 * XXX Temporarily locating auth in node-check while debugging.
		 * Or maybe not so temporarily, if we make container here.
		 * --- also, we need auth to be active in case of deletes
		 */
		if (swift_auth(stn))
			return -1;
		if (swift_mkbin(stn, SWIFT_CONTAINER))
			return -1;
	}
	return 0;
}

struct st_node_ops stor_ops_swift = {
	.open =		cf_open,
	.open_read =	cf_open_read,
	.close =	cf_close,
	.abort =	cf_abort,
	.put_start =	cf_put_start,
	.put_buf =	cf_put_buf,
	.put_end =	cf_put_end,
	.get_buf =	cf_get_buf,
	.obj_del =	cf_obj_del,
	.obj_test =	cf_obj_test,
	.node_check =	cf_node_check,
};

