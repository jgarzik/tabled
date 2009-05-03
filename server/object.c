
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
	memset(&pval, 0, sizeof(pval));
	pkey.data = okey;
	pkey.size = alloc_len;

	/* read existing object info, if any */
	rc = objs->get(objs, txn, &pkey, &pval, DB_RMW);
	if (rc == DB_NOTFOUND)
		return 1;
	if (rc)
		return -1;

	if (pobj)
		memcpy(pobj, pval.data, sizeof(struct db_obj_ent));
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

static int object_unlink(struct db_obj_ent *obj)
{
	struct db_obj_addr *addr;
	struct storage_node *stnode;

	if (GUINT32_FROM_LE(obj->flags) & DB_OBJ_INLINE)
		return 0;
	/*
	 * FIXME Iterate over all of avec[] when redundancy is added;
	 * use nid to locate node in all_stor.
	 */
	addr = &obj->d.avec[0];

	if (list_empty(&tabled_srv.all_stor))
		return -EIO;
	stnode = list_entry(tabled_srv.all_stor.next,
			    struct storage_node, all_link);

	return stor_obj_del(stnode, addr->oid);
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
	memset(&pval, 0, sizeof(pval));
	pkey.data = okey;
	pkey.size = alloc_len;

	/* read existing object info, if any */
	rc = objs->get(objs, txn, &pkey, &pval, DB_RMW);
	if (rc) {
		if (rc == DB_NOTFOUND)
			err = NoSuchKey;
                goto err_out;
	}

	/* save object addresses, for later use */
	memcpy(&obje, pval.data, sizeof(struct db_obj_ent));

	if (!__object_del(txn, bucket, key))
		goto err_out;

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		return cli_err(cli, InternalError);
	}

	if (object_unlink(&obje) < 0)
		syslog(LOG_ERR, "object data(%llX) unlink failed",
		       (unsigned long long) cli->in_objid);
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

void cli_out_end(struct client *cli)
{
	if (!cli)
		return;

	stor_abort(&cli->out_ce);
	stor_close(&cli->out_ce);

	free(cli->out_bucket);
	free(cli->out_key);
	free(cli->out_user);

	cli->out_user =
	cli->out_bucket =
	cli->out_key = NULL;
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
	enum errcode err = InternalError;
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

	if (!stor_put_end(&cli->out_ce)) {
		syslog(LOG_ERR, "Chunk sync failed");
		goto err_out;
	}

	if (debugging) {
		/* FIXME how do we test for inline objects here? */
		if (!stor_obj_test(&cli->out_ce, cli->out_objid))
			syslog(LOG_ERR, "Stat (%llX) failed",
			       (unsigned long long) cli->out_objid);
		else
			syslog(LOG_DEBUG, "STORED %llX, size -",
			       (unsigned long long) cli->out_objid);
	}

	stor_close(&cli->out_ce);

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
		struct http_hdr hdr = { "Content-Type", type };
		append_hdr_string(string_lens, string_data, &hdr);
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
	obj->d.avec[0].nid = 1;		/* FIXME */
	obj->d.avec[0].oid = cli->out_objid;
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
	if (delobj && object_unlink(&oldobj) < 0) {
		syslog(LOG_ERR, "object data(%llX) orphaned",
		       (unsigned long long) oldobj.d.avec[0].oid);
	}

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
		syslog(LOG_ERR, "OOM in object_put_end");
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

bool cli_evt_http_data_in(struct client *cli, unsigned int events)
{
	char buf[4096];
	char *p = buf;
	ssize_t avail, bytes;

	if (!cli->out_len)
		return object_put_end(cli);

	avail = read(cli->fd, buf, MIN(cli->out_len, sizeof(buf)));
	if (avail <= 0) {
		if ((avail < 0) && (errno == EAGAIN))
			return false;

		cli_out_end(cli);
		if (avail < 0)
			syslog(LOG_ERR, "object read(2) error: %s",
				strerror(errno));
		else
			syslog(LOG_ERR, "object read(2) unexpected EOF");
		return cli_err(cli, InternalError);
	}

	while (avail > 0) {
		bytes = stor_put_buf(&cli->out_ce, p, avail);
		if (bytes < 0) {
			cli_out_end(cli);
			syslog(LOG_ERR, "write(2) error in HTTP data-in: %s",
				strerror(errno));
			return cli_err(cli, InternalError);
		}

		MD5_Update(&cli->out_md5, p, bytes);

		cli->out_len -= bytes;
		p += bytes;
		avail -= bytes;
	}

	if (!cli->out_len)
		return object_put_end(cli);

	return (avail == sizeof(buf)) ? true : false;
}

bool object_put_body(struct client *cli, const char *user, const char *bucket,
		const char *key, long content_len, bool expect_cont)
{
	long avail;
	uint64_t objid;
	struct storage_node *stnode;
	int rc;

	if (!user || !has_access(user, bucket, NULL, "WRITE"))
		return cli_err(cli, AccessDenied);

	objid = objid_next();

	/* FIXME picking the first node until the redundancy is implemented */
	if (list_empty(&tabled_srv.all_stor)) {
		syslog(LOG_ERR, "No chunk nodes");
		return cli_err(cli, InternalError);
	}
	stnode = list_entry(tabled_srv.all_stor.next,
			    struct storage_node, all_link);

	rc = stor_open(&cli->out_ce, stnode);
	if (rc != 0) {
		syslog(LOG_WARNING, "Cannot open chunk (%d)", rc);
		return cli_err(cli, InternalError);
	}

	rc = stor_put_start(&cli->out_ce, objid, content_len);
	if (rc != 0) {
		syslog(LOG_WARNING, "Cannot start putting for %llX (%d)",
		       (unsigned long long) objid, rc);
		return cli_err(cli, InternalError);
	}

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

		/* FIXME check for err */
		asprintf(&cont, "HTTP/%d.%d 100 Continue\r\n\r\n",
			 cli->req.major, cli->req.minor);
		cli_writeq(cli, cont, strlen(cont), cli_cb_free, cont);
		cli_write_start(cli);
	}

	avail = MIN(cli_req_avail(cli), content_len);
	if (avail) {
		ssize_t bytes;

		while (avail > 0) {
			bytes = stor_put_buf(&cli->out_ce, cli->req_ptr, avail);
			if (bytes < 0) {
				cli_out_end(cli);
				syslog(LOG_ERR, "write(2) error in object_put: %s",
					strerror(errno));
				return cli_err(cli, InternalError);
			}

			MD5_Update(&cli->out_md5, cli->req_ptr, bytes);

			cli->out_len -= bytes;
			cli->req_ptr += bytes;
			avail -= bytes;
		}
	}

	if (!cli->out_len)
		return object_put_end(cli);

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
		syslog(LOG_ERR, "OOM in object_put_end");
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
		syslog(LOG_ERR, "read obj(%llX) failed",
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
static void object_get_event(struct open_chunk *cep)
{
	struct client *cli;
	unsigned char *p;

	/* FIXME what's the name of this ideom? parentof()? */
	p = (unsigned char *)cep;
	p -= ((unsigned long) &((struct client *)0)->in_ce);  /* offsetof */
	cli = (struct client *) p;

	object_get_poke(cli);
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
	bool access, modified = true;
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
	access = has_access(user, bucket, key, "READ");
	if (!access) {
		err = AccessDenied;
		goto err_out_acc;
	}
#endif

	alloc_len = sizeof(*okey) + strlen(key) + 1;
	okey = alloca(alloc_len);
	strncpy(okey->bucket, bucket, sizeof(okey->bucket));
	strcpy(okey->key, key);

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));
	pkey.data = okey;
	pkey.size = alloc_len;

	pval.flags = DB_DBT_MALLOC;

	rc = objs->get(objs, NULL, &pkey, &pval, 0);
	if (rc) {
		if (rc == DB_NOTFOUND)
			err = NoSuchKey;
		goto err_out_get;
	}

	obj = p = pval.data;

	/* Now that we know that the object exists, let's look up access */
	access = has_access(user, bucket, key, "READ");
	if (!access) {
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
 /* P3 */ syslog(LOG_ERR, "Inline object %s", key);
		goto err_out_str;
}

	cli->in_objid = obj->d.avec[0].oid;

	if (list_empty(&tabled_srv.all_stor)) {
		syslog(LOG_ERR, "No chunk nodes");
		goto err_out_str;
	}
	stnode = list_entry(tabled_srv.all_stor.next,
			    struct storage_node, all_link);

	rc = stor_open(&cli->in_ce, stnode);
	if (rc < 0) {
		syslog(LOG_WARNING, "Cannot open chunk (%d)", rc);
		goto err_out_str;
	}

	rc = stor_open_read(&cli->in_ce, object_get_event, cli->in_objid,
			    &objsize);
	if (rc < 0) {
		syslog(LOG_ERR, "open oid %llX failed (%d)",
		       (unsigned long long) cli->in_objid, rc);
		goto err_out_str;
	}

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
		syslog(LOG_ERR, "read obj(%llX) failed",
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
