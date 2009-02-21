
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
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <glib.h>
#include <openssl/hmac.h>
#include <httputil.h>

time_t str2time(const char *timestr)
{
	struct tm tm;

	memset(&tm, 0, sizeof(tm));

	if (!strptime(timestr, "%a, %d %b %Y %H:%M:%S %z", &tm))
		return 0;

	return mktime(&tm);
}

char *time2str(char *strbuf, time_t time)
{
	struct tm *tm = gmtime(&time);
	strftime(strbuf, 64, "%a, %d %b %Y %H:%M:%S %z", tm);
	return strbuf;
}

int req_hdr_push(struct http_req *req, char *key, char *val)
{
	struct http_hdr *hdr;

	if (req->n_hdr == REQ_MAX_HDR)
		return -ENOSPC;

	while (isspace(*val))
		val++;

	hdr = &req->hdr[req->n_hdr++];
	hdr->key = key;
	hdr->val = val;

	return 0;
}

char *req_hdr(struct http_req *req, const char *key)
{
	int i;

	for (i = 0; i < req->n_hdr; i++)
		if (!strcasecmp(key, req->hdr[i].key))
			return req->hdr[i].val;

	return NULL;
}

static inline void _HMAC_Update(HMAC_CTX *ctx, const void *data, int len)
{
	HMAC_Update(ctx, data, len);
}

static void req_sign_hdr(struct http_req *req, HMAC_CTX *ctx, const char *_hdr)
{
	char *hdr = req_hdr(req, _hdr);
	if (hdr)
		_HMAC_Update(ctx, hdr, strlen(hdr));
	_HMAC_Update(ctx, "\n", 1);
}

static const char *req_query_sign[] = {
	"acl",
	"location",
	"logging",
	"torrent",
};

void req_sign(struct http_req *req, const char *bucket, const char *key,
	      char *b64hmac_out)
{
	HMAC_CTX ctx;
	unsigned int len = 0, i;
	unsigned char md[EVP_MAX_MD_SIZE];
	int save = 0, state = 0, b64_len;

	HMAC_CTX_init(&ctx);
	HMAC_Init(&ctx, key, strlen(key), EVP_sha1());

	_HMAC_Update(&ctx, req->method, strlen(req->method));
	_HMAC_Update(&ctx, "\n", 1);

	req_sign_hdr(req, &ctx, "content-md5");
	req_sign_hdr(req, &ctx, "content-type");
	if (req_hdr(req, "x-amz-date"))
		_HMAC_Update(&ctx, "\n", 1);
	else
		req_sign_hdr(req, &ctx, "date");

	/* FIXME: canonicalize x-amz-* headers */

	if (bucket) {
		_HMAC_Update(&ctx, "/", 1);
		_HMAC_Update(&ctx, bucket, strlen(bucket));
	}

	_HMAC_Update(&ctx, req->orig_path, strlen(req->orig_path));

	for (i = 0; i < ARRAY_SIZE(req_query_sign); i++)
		if (!strncasecmp(req->uri.query, req_query_sign[i],
				 req->uri.query_len))
			_HMAC_Update(&ctx, req->uri.query, req->uri.query_len);

	HMAC_Final(&ctx, md, &len);
	HMAC_CTX_cleanup(&ctx);

	b64_len = g_base64_encode_step(md, len, FALSE, b64hmac_out,
				       &state, &save);
	b64_len += g_base64_encode_close(FALSE, b64hmac_out + b64_len,
					 &state, &save);
	b64hmac_out[b64_len] = 0;
}

void req_free(struct http_req *req)
{
	free(req->orig_path);
	req->orig_path = NULL;
}

GHashTable *req_query(struct http_req *req)
{
	char *qtmp, *q, *tmp, *end;
	int qlen, qtmplen;
	GHashTable *ht;

	ht = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
	if (!ht)
		return NULL;

	qtmp = alloca(req->uri.query_len + 1);

	q = req->uri.query;
	qlen = req->uri.query_len;

	while (qlen > 0) {
		char *key, *val;
		int keylen, vallen, valskip;

		tmp = memchr(q, '=', qlen);
		if (!tmp || (tmp == q))
			break;

		keylen = tmp - q;
		end = memchr(tmp, '&', qlen - keylen);

		memcpy(qtmp, q, keylen);
		qtmp[keylen] = 0;
		qtmplen = field_unescape(qtmp, strlen(qtmp));

		key = g_ascii_strdown(qtmp, qtmplen);

		qlen -= (keylen + 1);
		q += (keylen + 1);
		tmp++;

		if (end)
			vallen = end - tmp;
		else
			vallen = qlen;

		memcpy(qtmp, tmp, vallen);
		qtmplen = field_unescape(qtmp, vallen);

		val = g_strndup(qtmp, qtmplen);

		valskip = vallen;
		if (end)
			valskip++;

		qlen -= valskip;
		q += valskip;

		g_hash_table_insert(ht, key, val);
	}

	return ht;
}

