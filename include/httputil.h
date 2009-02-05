#ifndef __HTTPUTIL_H__
#define __HTTPUTIL_H__

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

#include <stdbool.h>
#include <glib.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define PATH_ESCAPE_MASK        0x02
#define QUERY_ESCAPE_MASK       0x04

enum {
	REQ_MAX_HDR		= 128,		/* max hdrs per req */
};

struct uri {
	char		*scheme;
	unsigned int	scheme_len;
	char		*userinfo;
	unsigned int	userinfo_len;
	char		*hostname;
	unsigned int	hostname_len;

	unsigned int	port;

	char		*path;
	unsigned int	path_len;
	char		*query;
	unsigned int	query_len;
	char		*fragment;
	unsigned int	fragment_len;	/* see FIXME in uri.c */
};

struct http_hdr {
	char			*key;
	char			*val;
};

struct http_req {
	char			*method;	/* GET, POST, etc. */
	struct uri		uri;		/* URI */
	int			major;		/* HTTP version */
	int			minor;

	char			*orig_path;

	unsigned int		n_hdr;		/* list of headers */
	struct http_hdr		hdr[REQ_MAX_HDR];
};

/* httputil.c */
extern char *time2str(char *strbuf, time_t time);
extern time_t str2time(const char *timestr);
extern int req_hdr_push(struct http_req *req, char *key, char *val);
extern char *req_hdr(struct http_req *req, const char *key);
extern void req_sign(struct http_req *req, const char *bucket, const char *key,
	      char *b64hmac_out);
extern GHashTable *req_query(struct http_req *req);
extern void req_free(struct http_req *req);

/* uri.c */
extern struct uri *uri_parse(struct uri *uri_dest, char *uri_src_text);
extern int field_unescape(char *s, int s_len);
extern char* field_escape (char *signed_str, unsigned char mask);

static inline bool http11(struct http_req *req)
{
	if (req->major > 1)
		return true;
	if (req->major == 1 && req->minor > 0)
		return true;
	return false;
}

#endif /* __HTTPUTIL_H__ */
