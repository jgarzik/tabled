
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
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <glib.h>
#include <openssl/md5.h>
#include "tabled.h"

/*
 * If successful, return the object (in DB representation).
 * N.B.: returned object is truncated, which is ok for unlink.
 */
static int object_find(DB_TXN *txn, const char *bucket, const char *key,
		       struct db_obj_ent *pobj)
{
	DB *objs = tdb.objs;
	struct db_obj_key *okey;
	size_t alloc_len;
	DBT pkey, pval;
	int rc;

	alloc_len = sizeof(*okey) + strlen(key) + 1;
	okey = alloca(alloc_len);
	strncpy(okey->bucket, bucket, sizeof(okey->bucket));
	strcpy(okey->key, key);

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = okey;
	pkey.size = alloc_len;

	memset(&pval, 0, sizeof(pval));
	pval.flags = DB_DBT_MALLOC;

	/* read existing object info, if any */
	rc = objs->get(objs, txn, &pkey, &pval, DB_RMW);
	if (rc == DB_NOTFOUND)
		return 1;
	if (rc)
		return -1;

	if (pobj)
		memcpy(pobj, pval.data, sizeof(struct db_obj_ent));
	free(pval.data);
	return 0;
}

static bool __object_del(DB_TXN *txn, const char *bucket, const char *key)
{
	DB *objs = tdb.objs;
	struct db_obj_key *okey;
	size_t okey_len;
	DBT pkey;
	int rc;

	/* delete object metadata */
	okey_len = sizeof(*okey) + strlen(key) + 1;
	okey = alloca(okey_len);
	strncpy(okey->bucket, bucket, sizeof(okey->bucket));
	strcpy(okey->key, key);

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = okey;
	pkey.size = okey_len;

	rc = objs->del(objs, txn, &pkey, 0);
	if (rc && rc != DB_NOTFOUND) {
		objs->err(objs, rc, "objs->del");
		return false;
	}

	/* delete object ACLs */
	return object_del_acls(txn, bucket, key);
}

bool object_del_acls(DB_TXN *txn, const char *bucket, const char *key)
{
	DB *acls = tdb.acls;
	struct db_acl_key *akey;
	size_t alloc_len;
	DBT pkey;
	int rc;

	alloc_len = sizeof(*akey) + strlen(key) + 1;
	akey = alloca(alloc_len);
	memset(akey, 0, alloc_len);
	strncpy(akey->bucket, bucket, sizeof(akey->bucket));
	strcpy(akey->key, key);

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = akey;
	pkey.size = alloc_len;

	rc = acls->del(acls, txn, &pkey, 0);
	if (rc && rc != DB_NOTFOUND) {
		acls->err(acls, rc, "acls->del");
		return false;
	}

	return true;
}

static void object_unlink(struct db_obj_ent *obj)
{
	struct db_obj_addr *addr;
	int i;
	struct storage_node *stnode;
	int rc;

	if (GUINT32_FROM_LE(obj->flags) & DB_OBJ_INLINE)
		return;
	addr = &obj->d.a;

	for (i = 0; i < MAXWAY; i++) {
		uint32_t nid;

		nid = GUINT32_FROM_LE(addr->nidv[i]);
		if (!nid)
			continue;
		stnode = stor_node_by_nid(nid);
		if (!stnode)
			continue;

		rc = stor_obj_del(stnode, GUINT64_FROM_LE(addr->oid));
		if (rc)
			applog(LOG_ERR,
			       "object data(%llX) unlink failed on nid %u",
			       (unsigned long long) GUINT64_FROM_LE(addr->oid),
			       nid);
	}
}

bool object_del(struct client *cli, const char *user,
		const char *bucket, const char *key)
{
	char timestr[64], *hdr;
	int rc;
	enum errcode err = InternalError;
	size_t alloc_len;
	DB_ENV *dbenv = tdb.env;
	DB *objs = tdb.objs;
	struct db_obj_key *okey;
	struct db_obj_ent obje;
	DBT pkey, pval;
	DB_TXN *txn = NULL;

	if (!user || !has_access(user, bucket, NULL, "WRITE")) {
		err = AccessDenied;
		return cli_err(cli, err);
	}

	/* begin trans */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		return cli_err(cli, InternalError);
	}

	alloc_len = sizeof(*okey) + strlen(key) + 1;
	okey = alloca(alloc_len);
	strncpy(okey->bucket, bucket, sizeof(okey->bucket));
	strcpy(okey->key, key);

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = okey;
	pkey.size = alloc_len;

	memset(&pval, 0, sizeof(pval));
	pval.flags = DB_DBT_MALLOC;

	/* read existing object info, if any */
	rc = objs->get(objs, txn, &pkey, &pval, DB_RMW);
	if (rc) {
		if (rc == DB_NOTFOUND)
			err = NoSuchKey;
                goto err_out;
	}

	/* save object addresses, for later use */
	memcpy(&obje, pval.data, sizeof(struct db_obj_ent));
	free(pval.data);

	if (!__object_del(txn, bucket, key))
		goto err_out;

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		return cli_err(cli, InternalError);
	}

	object_unlink(&obje);
	if (asprintf(&hdr,
"HTTP/%d.%d 204 x\r\n"
"Content-Length: 0\r\n"
"Date: %s\r\n"
"Server: " PACKAGE_STRING "\r\n"
"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     time2str(timestr, time(NULL))) < 0)
		return cli_err(cli, InternalError);

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc) {
		free(hdr);
		return true;
	}

	return cli_write_start(cli);

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	return cli_err(cli, err);
}

static void cli_ochunk_free(struct list_head *olist)
{
	struct open_chunk *ochunk;

	while (!list_empty(olist)) {
		ochunk = list_entry(olist->next, struct open_chunk, link);
		list_del(&ochunk->link);
		stor_abort(ochunk);
		stor_close(ochunk);
		free(ochunk);
	}
}

void cli_out_end(struct client *cli)
{
	if (!cli)
		return;

	cli_ochunk_free(&cli->out_ch);

	free(cli->out_bucket);
	free(cli->out_key);
	free(cli->out_user);

	cli->out_user =
	cli->out_bucket =
	cli->out_key = NULL;

	free(cli->out_buf);
	cli->out_buf = NULL;
}

static const char *copy_headers[] = {
	"cache-control",
	"expires",
	"content-disposition",
	"content-encoding",
	"content-type",
};

static bool should_copy_header(const struct http_hdr *hdr)
{
	int i;

	if (!strncasecmp(hdr->key, "x-amz-meta-", strlen("x-amz-meta-")))
		return true;

	for (i = 0; i < ARRAY_SIZE(copy_headers); i++)
		if (!strcasecmp(hdr->key, copy_headers[i]))
			return true;

	return false;
}

static void append_hdr_string(GArray *string_lens, GByteArray *string_data,
			      const struct http_hdr *hdr)
{
	char *s;
	uint16_t slen;

	s = g_strdup_printf("%s: %s\r\n", hdr->key, hdr->val);
	slen = strlen(s) + 1;

	g_array_append_val(string_lens, slen);
	g_byte_array_append(string_data, (uint8_t *) s, slen);

	free(s);
}

static bool object_put_end(struct client *cli)
{
	unsigned char md[MD5_DIGEST_LENGTH];
	char md5[33], timestr[64];
	char *type, *hdr;
	int rc, i;
	struct list_head *pos, *tmp;
	int nok;
	enum errcode err = InternalError;
	struct db_obj_addr obj_addr;
	struct db_obj_ent *obj;
	struct db_obj_key *obj_key;
	struct db_obj_ent oldobj;
	bool delobj;
	size_t alloc_len;
	DB_ENV *dbenv = tdb.env;
	DBT pkey, pval;
	DB *objs = tdb.objs;
	DB_TXN *txn = NULL;
	GByteArray *string_data;
	GArray *string_lens;
	uint16_t tmp16;
	uint32_t n_str;
	void *mem;

	if (http11(&cli->req))
		cli->state = evt_recycle;
	else
		cli->state = evt_dispose;

	memset(&obj_addr, 0, sizeof(struct db_obj_addr));
	obj_addr.oid = GUINT64_TO_LE(cli->out_objid);
	nok = 0;
	list_for_each_safe(pos, tmp, &cli->out_ch) {
		struct open_chunk *ochunk;

		ochunk = list_entry(pos, struct open_chunk, link);
		if (!stor_put_end(ochunk)) {
			applog(LOG_ERR, "Chunk sync failed");
			/* stor_abort(ochunk); */
		} else {
			if (debugging) {
				/* FIXME how do we test for inline objects here? */
				if (!stor_obj_test(ochunk, cli->out_objid))
					applog(LOG_ERR, "Stat (%llX) failed",
					       (unsigned long long) cli->out_objid);
				else
					applog(LOG_DEBUG, "STORED %llX, size -",
					       (unsigned long long) cli->out_objid);
			}
			obj_addr.nidv[nok] = GUINT32_TO_LE(ochunk->node->id);
			nok++;
		}
		stor_close(ochunk);
		list_del(&ochunk->link);
		free(ochunk);
	}
	if (!nok)
		goto err_out;

	MD5_Final(md, &cli->out_md5);

	md5str(md, md5);

	type = req_hdr(&cli->req, "content-type");
	if (!type)
		type = "binary/octet-stream";
	else
		type = NULL;

	/* begin trans */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto err_out;
	}

	delobj = false;
	rc = object_find(txn, cli->out_bucket, cli->out_key, &oldobj);
	if (rc < 0) {
		objs->err(objs, rc, "object_find");
		goto err_out_rb;
	}

	/* delete existing object, if it exists;
	 * remember existing object filename for later unlinking
	 */
	if (rc == 0) {
		delobj = true;

		/* delete object metadata, ACLs */
		if (!__object_del(txn, cli->out_bucket, cli->out_key))
			goto err_out_rb;
	}

	/* insert object ACL */
	rc = add_access_canned(txn, cli->out_bucket, cli->out_key,
			      cli->out_user, ACLC_PRIV);
	if (rc) {
		dbenv->err(dbenv, rc, "acls->put");
		goto err_out_rb;
	}

	/* alloc areas to collect string lengths, string data */
	string_data = g_byte_array_sized_new(4096);
	string_lens = g_array_new(FALSE, FALSE, sizeof(uint16_t));
	if (!string_data || !string_lens)
		goto err_out_rb;

	/* add special case first string: object key */
	tmp16 = strlen(cli->out_key) + 1;
	g_array_append_val(string_lens, tmp16);
	g_byte_array_append(string_data, (uint8_t *) cli->out_key, tmp16);

	/* copy select headers */
	for (i = 0; i < cli->req.n_hdr; i++)
		if (should_copy_header(&cli->req.hdr[i]))
			append_hdr_string(string_lens, string_data,
					  &cli->req.hdr[i]);

	if (type) {
		struct http_hdr ct_hdr = { "Content-Type", type };
		append_hdr_string(string_lens, string_data, &ct_hdr);
	}

	/* allocate and build object metadata for storage */
	n_str = string_lens->len;
	alloc_len = sizeof(*obj) +
		    (sizeof(uint16_t) * n_str) +
		    string_data->len;
	obj = calloc(1, alloc_len);
	if (!obj)
		goto err_out_rb;

	/* encode object header */
	obj->size = cli->out_size;
	obj->mtime = (uint64_t)time(NULL) * 1000000;
	memcpy(&obj->d.a, &obj_addr, sizeof(struct db_obj_addr));
	strncpy(obj->bucket, cli->out_bucket, sizeof(obj->bucket));
	strncpy(obj->owner, cli->out_user, sizeof(obj->owner));
	strncpy(obj->md5, md5, sizeof(obj->md5));
	obj->n_str = GUINT32_TO_LE(n_str);

	/* encode object string length table */
	mem = obj;
	mem += sizeof(struct db_obj_ent);
	memcpy(mem, string_lens->data, n_str * sizeof(uint16_t));
	mem += n_str * sizeof(uint16_t);

	/* encode object string data area */
	memcpy(mem, string_data->data, string_data->len);

	obj_key = alloca(sizeof(struct db_obj_key) + strlen(cli->out_key) + 1);
	strncpy(obj_key->bucket, cli->out_bucket, sizeof(obj_key->bucket));
	strcpy(obj_key->key, cli->out_key);

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));
	pkey.data = obj_key;
	pkey.size = sizeof(*obj_key) + strlen(obj_key->key) + 1;
	pval.data = obj;
	pval.size = alloc_len;

	/* store object metadata in database */
	rc = objs->put(objs, txn, &pkey, &pval, 0);
	free(obj);
	if (rc) {
		dbenv->err(dbenv, rc, "objs->put");
		goto err_out_rb;
	}

	/* commit all these changes (deletions + additions) to database */
	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		goto err_out;
	}

	/* now that all database manipulation has been a success,
	 * we can remove the old object (overwritten) data.
	 */
	if (delobj)
		object_unlink(&oldobj);

	free(cli->out_bucket);
	free(cli->out_key);
	free(cli->out_user);

	cli->out_user =
	cli->out_bucket =
	cli->out_key = NULL;

	if (asprintf(&hdr,
"HTTP/%d.%d 200 x\r\n"
"Content-Length: 0\r\n"
"ETag: \"%s\"\r\n"
"Date: %s\r\n"
"Server: " PACKAGE_STRING "\r\n"
"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     md5,
		     time2str(timestr, time(NULL))) < 0) {
		/* FIXME: cleanup failure */
		applog(LOG_ERR, "OOM in object_put_end");
		return cli_err(cli, InternalError);
	}

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc) {
		free(hdr);
		return true;
	}

	return cli_write_start(cli);

err_out_rb:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
err_out:
	cli_out_end(cli);
	return cli_err(cli, err);
}

static void object_put_event(struct open_chunk *ochunk)
{
	struct client *cli = ochunk->cli;
	ssize_t bytes;

	if (ochunk->wcnt == 0) {
		if (debugging)
			applog(LOG_DEBUG, "spurious write notify");
		return;
	}

	bytes = stor_put_buf(ochunk, cli->out_buf, cli->out_bcnt);
	if (bytes < 0) {
		if (debugging)
			applog(LOG_DEBUG, "write(2) error: %s",
			       strerror(-bytes));
		if (!cli->out_nput) {
			applog(LOG_INFO, "out_nput imbalance on error");
		} else {
			--cli->out_nput;
		}
		if (!cli->out_nput) {
			if (!cli->ev_active) {
				event_add(&cli->ev, NULL);
				cli->ev_active = true;
			}
		}
		list_del(&ochunk->link);
		stor_abort(ochunk);
		stor_close(ochunk);
		free(ochunk);
		return;
	}
	ochunk->wcnt -= bytes;

	if (ochunk->wcnt == 0) {
		if (!cli->out_nput) {
			applog(LOG_INFO, "out_nput imbalance");
		} else {
			--cli->out_nput;
		}

		if (!cli->out_nput) {
			if (!cli->ev_active) {
				event_add(&cli->ev, NULL);
				cli->ev_active = true;
			}
		}
	}
}

static int object_put_buf(struct client *cli, struct open_chunk *ochunk,
			  char *buf, size_t len)
{
	ssize_t bytes;

	ochunk->wcnt = len;

	bytes = stor_put_buf(ochunk, buf, len);
	if (bytes < 0) {
		if (debugging) {
			applog(LOG_ERR, "write(2) error in HTTP data-in: %s",
			       strerror(-bytes));
		}
		return -EIO;
	}
	ochunk->wcnt -= bytes;

	if (ochunk->wcnt != 0)
		cli->out_nput++;
	return 0;
}

bool cli_evt_http_data_in(struct client *cli, unsigned int events)
{
	ssize_t avail;
	struct open_chunk *ochunk;
	struct list_head *pos, *tmp;
	int nok;

	if (!cli->out_len)
		return object_put_end(cli);

	if (cli->out_nput) {
		if (cli->ev_active) {
			event_del(&cli->ev);
			cli->ev_active = false;
		} else {
			/* P3 temporary */ applog(LOG_INFO, "spurious ev");
		}
		return false;
	}

	avail = read(cli->fd, cli->out_buf, MIN(cli->out_len, CLI_DATA_BUF_SZ));
	if (avail <= 0) {
		if ((avail < 0) && (errno == EAGAIN))
			return false;

		cli_out_end(cli);
		if (avail < 0)
			applog(LOG_ERR, "object read(2) error: %s",
				strerror(errno));
		else
			applog(LOG_ERR, "object read(2) unexpected EOF");
		return cli_err(cli, InternalError);
	}
	cli->out_bcnt = avail;

	MD5_Update(&cli->out_md5, cli->out_buf, avail);

	nok = 0;
	list_for_each_safe(pos, tmp, &cli->out_ch) {
		ochunk = list_entry(pos, struct open_chunk, link);
		if (object_put_buf(cli, ochunk, cli->out_buf, avail) < 0) {
			list_del(&ochunk->link);
			stor_abort(ochunk);
			stor_close(ochunk);
			free(ochunk);
		} else {
			nok++;
		}
	}
	if (!nok) {
		cli_out_end(cli);
		/* if (debugging) */ /* P3 temporary */
			applog(LOG_ERR, "data write-out error");
		return cli_err(cli, InternalError);
	}

	if (!cli->out_nput) {
		cli->out_len -= avail;
		if (!cli->out_len)
			return object_put_end(cli);
	} else {
		if (cli->ev_active) {
			event_del(&cli->ev);
			cli->ev_active = false;
		}
	}

	return false;
}

static struct open_chunk *open_chunk1(struct storage_node *stnode,
				     uint64_t objid, long content_len)
{
	struct open_chunk *ochunk;
	int rc;

	ochunk = calloc(1, sizeof(struct open_chunk));
	if (!ochunk) {
		applog(LOG_ERR, "OOM");
		goto err_alloc;
	}

	rc = stor_open(ochunk, stnode);
	if (rc != 0) {
		applog(LOG_WARNING, "Cannot open output chunk, nid %u (%d)",
		       stnode->id, rc);
		goto err_open;
	}

	rc = stor_put_start(ochunk, object_put_event, objid, content_len);
	if (rc != 0) {
		applog(LOG_WARNING, "Cannot start putting for %llX (%d)",
		       (unsigned long long) objid, rc);
		goto err_start;
	}

	return ochunk;

 err_start:
	stor_close(ochunk);
 err_open:
	free(ochunk);
 err_alloc:
	return NULL;
}

/*
 * Open up to MAXWAY chunks from slist, pre-start writing on all of them,
 * and put them on the olist.
 *
 * This is a very limited implementation for now (FIXME).
 *  - we do not do any kind of sensible selection, like the least full node,
 *    just first-forward
 *  - we ignore all redundancy issues and only return an error if no nodes
 *    were opened
 */
static int open_chunks(struct list_head *olist, struct list_head *slist,
		       struct client *cli, uint64_t objid, long content_len)
{
	struct storage_node *stnode;
	struct open_chunk *ochunk;
	int n;

	n = 0;
	list_for_each_entry(stnode, slist, all_link) {
		if (n >= MAXWAY)
			break;
		if (!stnode->up)
			continue;
		ochunk = open_chunk1(stnode, objid, content_len);
		if (!ochunk)
			continue;
		ochunk->cli = cli;
		list_add(&ochunk->link, olist);
		n++;
	}
	if (n == 0) {
		applog(LOG_ERR, "No chunk nodes");
		goto err;
	}
	return 0;

err:
	/*
	 * cli_free does the same cleanup for us, but let's be good for KISS
	 * and possible client reuse.
	 */
	cli_ochunk_free(olist);
	return -1;
}

bool object_put_body(struct client *cli, const char *user, const char *bucket,
		const char *key, long content_len, bool expect_cont)
{
	long avail;
	uint64_t objid;
	int rc;

	if (!user || !has_access(user, bucket, NULL, "WRITE"))
		return cli_err(cli, AccessDenied);

	if (!cli->out_buf && !(cli->out_buf = malloc(CLI_DATA_BUF_SZ))) {
		applog(LOG_ERR, "OOM (%ld)", (long)CLI_DATA_BUF_SZ);
		return cli_err(cli, InternalError);
	}

	objid = objid_next(&tabled_srv.object_count, &tdb);

	rc = open_chunks(&cli->out_ch, &tabled_srv.all_stor,
			 cli, objid, content_len);
	if (rc)
		return cli_err(cli, InternalError);

	cli->out_bucket = strdup(bucket);
	cli->out_key = strdup(key);
	MD5_Init(&cli->out_md5);
	cli->out_len = content_len;
	cli->out_size = content_len;
	cli->out_objid = objid;
	cli->out_user = strdup(user);

	/* handle Expect: 100-continue header, by unconditionally
	 * requesting that they continue.
	 */
	if (expect_cont) {
		char *cont;

		if (asprintf(&cont, "HTTP/%d.%d 100 Continue\r\n\r\n",
			     cli->req.major, cli->req.minor) == -1) {
			cli_out_end(cli);
			return cli_err(cli, InternalError);
		}
		cli_writeq(cli, cont, strlen(cont), cli_cb_free, cont);
		cli_write_start(cli);
	}

	avail = MIN(cli_req_avail(cli), content_len);
	if (avail) {
		struct list_head *pos, *tmp;
		struct open_chunk *ochunk;
		int nok;

		cli->out_bcnt = avail;

		MD5_Update(&cli->out_md5, cli->req_ptr, avail);

		nok = 0;
		list_for_each_safe(pos, tmp, &cli->out_ch) {
			ochunk = list_entry(pos, struct open_chunk, link);
			if (object_put_buf(cli, ochunk, cli->req_ptr, avail) < 0) {
				list_del(&ochunk->link);
				stor_abort(ochunk);
				stor_close(ochunk);
				free(ochunk);
			} else {
				nok++;
			}
		}
		if (!nok) {
			cli_out_end(cli);
			if (debugging)
				applog(LOG_ERR, "data pig-out error");
			return cli_err(cli, InternalError);
		}
	}

	if (!cli->out_nput) {
		cli->out_len -= avail;
		if (!cli->out_len)
			return object_put_end(cli);
	} else {
		if (cli->ev_active) {
			event_del(&cli->ev);
			cli->ev_active = false;
		}
	}
	cli->state = evt_http_data_in;
	return true;
}

static bool object_put_acls(struct client *cli, const char *user,
    const char *bucket, const char *key, long content_len, bool expect_cont)
{
	enum errcode err = InternalError;
	enum ReqACLC canacl;
	DB_ENV *dbenv = tdb.env;
	DB_TXN *txn = NULL;
	DB *objs = tdb.objs;
	char *hdr;
	char timestr[64];
	int rc;

	if (content_len) {
		/*
		 * FIXME We should support this, but parsing XML is a pain.
		 * We only do canned ACPs for now.
		 */
		return cli_err(cli, InvalidArgument);
	}

	if (!user || !has_access(user, bucket, key, "WRITE_ACP"))
		return cli_err(cli, AccessDenied);

	if ((rc = req_acl_canned(&cli->req)) == ACLCNUM) {
		err = InvalidArgument;
		goto err_out_parm;
	}
	canacl = (rc == -1)? ACLC_PRIV: rc;

	if (http11(&cli->req))
		cli->state = evt_recycle;
	else
		cli->state = evt_dispose;

	/* begin trans */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto err_out;
	}

	rc = object_find(txn, bucket, key, NULL);
	if (rc < 0) {
		objs->err(objs, rc, "object_find");
		goto err_out_rb;
	}
	if (rc != 0) {
		err = NoSuchKey;
		goto err_out_rb;
	}

	if (!object_del_acls(txn, bucket, key))
		goto err_out_rb;

	rc = add_access_canned(txn, bucket, key, user, canacl);
	if (rc) {
		dbenv->err(dbenv, rc, "add_access_canned");
		goto err_out_rb;
	}

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		goto err_out;
	}

	if (asprintf(&hdr,
"HTTP/%d.%d 200 x\r\n"
"Content-Length: 0\r\n"
"Date: %s\r\n"
"Server: " PACKAGE_STRING "\r\n"
"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     time2str(timestr, time(NULL))) < 0) {
		/* FIXME: cleanup failure */
		applog(LOG_ERR, "OOM in object_put_end");
		return cli_err(cli, InternalError);
	}

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc) {
		free(hdr);
		return true;
	}

	return cli_write_start(cli);

err_out_rb:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
err_out:
err_out_parm:
	return cli_err(cli, err);
}

bool object_put(struct client *cli, const char *user, const char *bucket,
		const char *key, long content_len, bool expect_cont)
{
	bool setacl;

	setacl = false;
	if (cli->req.uri.query_len) {
		switch (req_is_query(&cli->req)) {
		case URIQ_ACL:
			setacl = true;
			break;
		default:
			return cli_err(cli, InvalidURI);
		}
	}

	if (setacl)
		return object_put_acls(cli, user, bucket, key,
				       content_len, expect_cont);
	else
		return object_put_body(cli, user, bucket, key,
				       content_len, expect_cont);
}

void cli_in_end(struct client *cli)
{
	if (!cli)
		return;

	stor_close(&cli->in_ce);
}

static bool object_get_more(struct client *cli, struct client_write *wr,
			    bool done);

/*
 * Return true iff cli_writeq was called. This is compatible with the
 * convention for cli continuation callbacks, so object_get_more can call us.
 */
static bool object_get_poke(struct client *cli)
{
	char *buf;
	ssize_t bytes;

	buf = malloc(CLI_DATA_BUF_SZ);
	if (!buf)
		return false;

	bytes = stor_get_buf(&cli->in_ce, buf,
			     MIN(cli->in_len, CLI_DATA_BUF_SZ));
	if (bytes < 0) {
		applog(LOG_ERR, "read obj(%llX) failed",
		       (unsigned long long) cli->in_objid);
		goto err_out;
	}
	if (bytes == 0) {
		if (!cli->in_len) {
			cli_in_end(cli);
			cli_write_start(cli);
		}
		free(buf);
		return false;
	}

	cli->in_len -= bytes;
	if (!cli->in_len) {
		if (cli_writeq(cli, buf, bytes, cli_cb_free, buf))
			goto err_out;
		cli_in_end(cli);
		cli_write_start(cli);
	} else {
		if (cli_writeq(cli, buf, bytes, object_get_more, buf))
			goto err_out;
		if (cli_wqueued(cli) >= 4000)
			cli_write_start(cli);
	}
	return true;

err_out:
	cli_in_end(cli);
	free(buf);
	return false;
}

/* callback from the client side: a queued write is being disposed */
static bool object_get_more(struct client *cli, struct client_write *wr,
			    bool done)
{

	/* free now-written buffer */
	free(wr->cb_data);

	/* do not queue more, if !completion or fd was closed early */
	if (!done)	/* FIXME We used to test for input errors here. */
		return false;

	return object_get_poke(cli);		/* won't hurt to try */
}

/* callback from the chunkd side: some data is available */
static void object_get_event(struct open_chunk *ochunk)
{
	object_get_poke(ochunk->cli);
}

bool object_get_body(struct client *cli, const char *user, const char *bucket,
		       const char *key, bool want_body)
{
	char *md5;
	char timestr[64], modstr[64], *hdr, *tmp;
	int rc, i;
	enum errcode err = InternalError;
	char buf[4096];
	ssize_t bytes;
	bool access_ok, modified = true;
	GString *extra_hdr;
	size_t alloc_len;
	DB *objs = tdb.objs;
	struct db_obj_key *okey;
	struct db_obj_ent *obj = NULL;
	DBT pkey, pval;
	void *p;
	uint64_t objsize;	/* As reported by Chunk. Not used. */
	struct storage_node *stnode;
	uint32_t n_str;
	uint16_t *slenp;

#if 0 /* FIXME look it up in the docs if we need access to bucket */
	access_ok = has_access(user, bucket, key, "READ");
	if (!access_ok) {
		err = AccessDenied;
		goto err_out_acc;
	}
#endif

	alloc_len = sizeof(*okey) + strlen(key) + 1;
	okey = alloca(alloc_len);
	strncpy(okey->bucket, bucket, sizeof(okey->bucket));
	strcpy(okey->key, key);

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = okey;
	pkey.size = alloc_len;

	memset(&pval, 0, sizeof(pval));
	pval.flags = DB_DBT_MALLOC;

	rc = objs->get(objs, NULL, &pkey, &pval, 0);
	if (rc) {
		if (rc == DB_NOTFOUND)
			err = NoSuchKey;
		goto err_out_get;
	}

	obj = p = pval.data;

	/* Now that we know that the object exists, let's look up access */
	access_ok = has_access(user, bucket, key, "READ");
	if (!access_ok) {
		err = AccessDenied;
		goto err_out_reset;
	}

	md5 = obj->md5;

	hdr = req_hdr(&cli->req, "if-match");
	if (hdr && strcmp(md5, hdr)) {
		err = PreconditionFailed;
		goto err_out_reset;
	}

	extra_hdr = g_string_sized_new(1024);
	if (!extra_hdr)
		goto err_out_reset;

	/* get pointer to start of uint16_t array */
	p += sizeof(struct db_obj_ent);
	slenp = p;

	/* set pointer to start of packed string area */
	n_str = GUINT32_FROM_LE(obj->n_str);
	p += n_str * sizeof(uint16_t);

	for (i = 0; i < n_str; i++) {
		char *dbhdr;

		dbhdr = p;
		p += GUINT16_FROM_LE(*slenp);
		slenp++;

		/* first string is object key; skip */
		if (i == 0)
			continue;

		extra_hdr = g_string_append(extra_hdr, dbhdr);
	}

	if (GUINT32_FROM_LE(obj->flags) & DB_OBJ_INLINE)
{
 /* FIXME: Not implemented yet */
 /* P3 */ applog(LOG_ERR, "Inline object %s", key);
		goto err_out_str;
}

	cli->in_objid = GUINT64_FROM_LE(obj->d.a.oid);

	for (i = 0; i < MAXWAY; i++ ) {
		uint32_t nid;

		nid = GUINT32_FROM_LE(obj->d.a.nidv[0]);
		if (!nid)
			continue;
		stnode = stor_node_by_nid(nid);
		if (stnode)		/* FIXME temporarily 1-way */
			break;

		applog(LOG_ERR, "No chunk node nid %u for oid %llX",
		       nid, cli->in_objid);
	}
	if (!stnode)
		goto err_out_str;

	rc = stor_open(&cli->in_ce, stnode);
	if (rc < 0) {
		applog(LOG_WARNING, "Cannot open input chunk, nid %u (%d)",
		       stnode->id, rc);
		goto err_out_str;
	}

	rc = stor_open_read(&cli->in_ce, object_get_event, cli->in_objid,
			    &objsize);
	if (rc < 0) {
		applog(LOG_ERR, "open oid %llX failed, nid %u (%d)",
		       (unsigned long long) cli->in_objid, stnode->id, rc);
		goto err_out_str;
	}
	cli->in_ce.cli = cli;

	hdr = req_hdr(&cli->req, "if-unmodified-since");
	if (hdr) {
		time_t t;

		t = str2time(hdr);
		if (!t) {
			err = InvalidArgument;
			goto err_out_in_end;
		}

		if (obj->mtime / 1000000 > t) {
			err = PreconditionFailed;
			goto err_out_in_end;
		}
	}

	hdr = req_hdr(&cli->req, "if-modified-since");
	if (hdr) {
		time_t t;

		t = str2time(hdr);
		if (!t) {
			err = InvalidArgument;
			goto err_out_in_end;
		}

		if (obj->mtime / 1000000 <= t) {
			modified = false;
			want_body = false;
		}
	}

	hdr = req_hdr(&cli->req, "if-none-match");
	if (hdr && (!strcmp(md5, hdr))) {
		modified = false;
		want_body = false;
	}

	if (asprintf(&hdr,
"HTTP/%d.%d %d x\r\n"
"Content-Length: %llu\r\n"
"ETag: \"%s\"\r\n"
"Date: %s\r\n"
"Last-Modified: %s\r\n"
"Server: " PACKAGE_STRING "\r\n"
"%s"
"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     modified ? 200 : 304,
		     (unsigned long long) obj->size,
		     md5,
		     time2str(timestr, time(NULL)),
		     time2str(modstr, obj->mtime / 1000000),
		     extra_hdr->str) < 0)
		goto err_out_in_end;

	if (!want_body) {
		cli_in_end(cli);

		rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
		if (rc) {
			free(hdr);
			return true;
		}
		goto start_write;
	}

	cli->in_len = obj->size;

	bytes = stor_get_buf(&cli->in_ce, buf, MIN(cli->in_len, sizeof(buf)));
	if (bytes < 0) {
		applog(LOG_ERR, "read obj(%llX) failed",
		       (unsigned long long) cli->in_objid);
		goto err_out_in_end;
	}
	if (bytes == 0) {
		if (!cli->in_len)
			cli_in_end(cli);

		rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
		if (rc) {
			free(hdr);
			goto err_out_in_end;
		}
		goto start_write;
	}

	cli->in_len -= bytes;

	if (!cli->in_len)
		cli_in_end(cli);

	tmp = malloc(bytes);
	if (!tmp)
		goto err_out_in_end;
	memcpy(tmp, buf, bytes);

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc) {
		free(hdr);
		free(tmp);
		return true;
	}

	if (cli_writeq(cli, tmp, bytes,
		       cli->in_len ? object_get_more : cli_cb_free, tmp))
		goto err_out_in_end;

start_write:
	free(obj);
	g_string_free(extra_hdr, TRUE);
	return cli_write_start(cli);

err_out_in_end:
	cli_in_end(cli);
err_out_str:
	g_string_free(extra_hdr, TRUE);
err_out_reset:
	free(obj);
err_out_get:
	return cli_err(cli, err);
}

static bool object_get_acls(struct client *cli, const char *user,
    const char *bucket, const char *key, bool want_body)
{

	if (!want_body) {
		/*
		 * We don't do HEAD for ACLs (yet?)
		 */
		return cli_err(cli, InvalidArgument);
	}

	return access_list(cli, bucket, key, user);
}

bool object_get(struct client *cli, const char *user, const char *bucket,
		       const char *key, bool want_body)
{
	bool getacl;

	getacl = false;
	if (cli->req.uri.query_len) {
		switch (req_is_query(&cli->req)) {
		case URIQ_ACL:
			getacl = true;
			break;
		default:
			/* Don't bomb, fall to object_get_body */
			break;
		}
	}

	if (getacl)
		return object_get_acls(cli, user, bucket, key, want_body);
	else
		return object_get_body(cli, user, bucket, key, want_body);
}
