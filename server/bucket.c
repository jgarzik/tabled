
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
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <glib.h>
#include <pcre.h>
#include <alloca.h>
#include <ctype.h>
#include "tabled.h"

bool has_access(const char *user, const char *bucket, const char *key,
		const char *perm_in)
{
	int rc;
	char perm[16];
	bool match = false;
	size_t alloc_len, key_len = 0;
	struct db_acl_key *acl_key;
	struct db_acl_ent *acl;
	DB_ENV *dbenv = tdb.env;
	DB_TXN *txn = NULL;
	DBT pkey, pval;
	DBC *cur = NULL;
	DB *acls = tdb.acls;

	/* alloc ACL key on stack, sized to fit 'key' function arg */
	alloc_len = sizeof(struct db_acl_key) + 1;
	if (key) {
		key_len = strlen(key);
		alloc_len += key_len;
	}
	acl_key = alloca(alloc_len);

	/* fill in search key struct */
	memset(acl_key, 0, alloc_len);
	strncpy(acl_key->bucket, bucket, sizeof(acl_key->bucket));
	memcpy(acl_key->key, key, key_len);
	acl_key->key[key_len] = 0;

	sprintf(perm, "%s,", perm_in);

	/* open transaction, search cursor */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		return false;
	}

	rc = acls->cursor(acls, txn, &cur, 0);
	if (rc) {
		acls->err(acls, rc, "acls->cursor");
		goto err_out;
	}

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	pkey.data = acl_key;
	pkey.size = alloc_len;

	/* loop through matching records (if any) */
	while (!match) {
		rc = cur->get(cur, &pkey, &pval, DB_NEXT);
		if (rc)
			break;

		acl = pval.data;

		if (strncmp(acl->grantee, user, sizeof(acl->grantee)))
			continue;

		match = (strstr(acl->perm, perm) == NULL) ? false : true;
	}

	/* close cursor, transaction */
	rc = cur->close(cur);
	if (rc)
		acls->err(acls, rc, "acls->cursor close");

	rc = txn->commit(txn, 0);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");

	return match;

err_out:
	if (txn->abort(txn))
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	return false;
}

bool service_list(struct client *cli, const char *user)
{
	GList *files = NULL, *content = NULL;
	char *s;
	enum errcode err = InternalError;
	int rc;
	bool rcb;
	DB_TXN *txn = NULL;
	DBC *cur = NULL;
	DB_ENV *dbenv = tdb.env;
	DB *bidx = tdb.buckets_idx;
	DBT skey, pkey, pval;

	if (asprintf(&s,
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<ListAllMyBucketsResult xmlns=\"http://indy.yyz.us/doc/2006-03-01/\">\r\n"
"  <Owner>\r\n"
"    <ID>%s</ID>\r\n"
"    <DisplayName>%s</DisplayName>\r\n"
"  </Owner>\r\n"
"  <Buckets>\r\n",

		     user,
		     user) < 0)
		goto err_out;

	content = g_list_append(content, s);

	/* open transaction, search cursor */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto err_out_content;
	}

	rc = bidx->cursor(bidx, txn, &cur, 0);
	if (rc) {
		bidx->err(bidx, rc, "bidx->cursor");
		goto err_out_content;
	}

	memset(&skey, 0, sizeof(skey));
	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	skey.data = (char *) user;
	skey.size = strlen(user) + 1;

	/* loop through matching buckets, if any */
	while (1) {
		char timestr[64];
		struct db_bucket_ent *ent;

		rc = cur->pget(cur, &skey, &pkey, &pval, DB_NEXT);
		if (rc)
			break;

		ent = pval.data;

		if (asprintf(&s,
                        "    <Bucket>\r\n"
                        "      <Name>%s</Name>\r\n"
                        "      <CreationDate>%s</CreationDate>\r\n"
                        "    </Bucket>\r\n",

			     ent->name,
			     time2str(timestr,
			     	      GUINT64_FROM_LE(ent->time_create))) < 0)
			goto err_out_content;

		content = g_list_append(content, s);
	}

	/* close cursor, transaction */
	rc = cur->close(cur);
	if (rc)
		bidx->err(bidx, rc, "bidx->cursor close");

	rc = txn->commit(txn, 0);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");

	if (asprintf(&s,
"  </Buckets>\r\n"
"</ListAllMyBucketsResult>\r\n") < 0)
		goto err_out_content;

	content = g_list_append(content, s);

	rcb = cli_resp_xml(cli, 200, content);

	strlist_free(files);
	g_list_free(content);

	return rcb;

err_out_content:
	strlist_free(content);
err_out:
	strlist_free(files);
	return cli_err(cli, err);
}

/*
 * This only implements more general checks and not fanciers restrictions
 * caused by hostname access, although we limit the size to hostname
 * compatible 63 just in case. Specifically, dot, underscore, and minus
 * are allowed (applications use them).
 *
 * We also reject IPv4-like names, at least for now. It's unclear if it's
 * a reasonable restriction. The syntax of hostname access seems to allow it.
 */
bool bucket_valid(const char *bucket)
{
	int captured[12];
	size_t len;
	size_t i;

	if (!bucket)
		return false;

	len = strlen(bucket);
	if (len < 1 || len > 63)
		return false;

	if (!islower(bucket[0]) && !isdigit(bucket[0]))
		return false;

	for (i = 1; i < len; i++) {
		char c = bucket[i];
		if (!(islower(c) || isdigit(c) ||
		    c == '.' || c == '_' || c == '-'))
			return false;
	}

	if (pcre_exec(patterns[pat_ipv4_addr].re, NULL,
			 bucket, len, 0, 0, captured, 12) >= 1)
		return false;

	return true;
}

/*
 * Parse the uri_path and return bucket and path, strndup-ed.
 * Returns true iff succeeded. Else, bucket and path are unchanged.
 */
bool bucket_base(const char *uri_path, char **pbucket, char **ppath)
{
	const char *p;
	char *bucket, *path;

	if (*uri_path != '/')
		return false;
	uri_path++;

	if (uri_path[0] == '\0') {
		bucket = NULL;
		if ((path = strdup("/")) == NULL)
			return false;
	} else if ((p = strchr(uri_path, '/')) == NULL) {
		if ((bucket = strdup(uri_path)) == NULL)
			return false;
		if ((path = strdup("/")) == NULL) {	/* fake slash */
			free(bucket);
			return false;
		}
	} else {
		if ((bucket = strndup(uri_path, p - uri_path)) == NULL)
			return false;
		if ((path = strdup(p)) == NULL) {	/* include slash */
			free(bucket);
			return false;
		}
	}
	*pbucket = bucket;
	*ppath = path;
	return true;
}

bool bucket_add(struct client *cli, const char *user, const char *bucket)
{
	char *hdr, timestr[64];
	char aclbuf[sizeof(struct db_acl_ent) + 32];
	enum errcode err = InternalError;
	int rc;
	struct db_bucket_ent ent;
	struct db_acl_ent *acl = (struct db_acl_ent *) &aclbuf;
	struct db_acl_key *acl_key = (struct db_acl_key *) &acl->bucket;
	DB *buckets = tdb.buckets;
	DB *acls = tdb.acls;
	DB_ENV *dbenv = tdb.env;
	DB_TXN *txn = NULL;
	DBT key, val;

	/* begin trans */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		return cli_err(cli, InternalError);
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));
	memset(&ent, 0, sizeof(ent));
	strncpy(ent.name, bucket, sizeof(ent.name));
	strncpy(ent.owner, user, sizeof(ent.owner));
	ent.time_create = GUINT64_TO_LE(time(NULL));

	key.data = &ent.name;
	key.size = strlen(ent.name) + 1;

	val.data = &ent;
	val.size = sizeof(ent);

	/* attempt to insert new bucket; will fail if it already exists */
	rc = buckets->put(buckets, txn, &key, &val, DB_NOOVERWRITE);
	if (rc) {
		if (rc == DB_KEYEXIST)
			err = BucketAlreadyExists;
		else
			buckets->err(buckets, rc, "buckets->put");
		goto err_out;
	}

	/* insert bucket ACL */
	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));
	memset(&aclbuf, 0, sizeof(aclbuf));
	strcpy(acl->bucket, bucket);
	strcpy(acl->grantee, user);
	strcpy(acl->perm, "READ,WRITE,READ_ACL,WRITE_ACL,");
	strcpy(acl->key, "");

	key.data = acl_key;
	key.size = sizeof(struct db_acl_key) + strlen(acl_key->key) + 1;

	val.data = acl;
	val.size = sizeof(struct db_acl_ent) + strlen(acl->key) + 1;

	rc = acls->put(acls, txn, &key, &val, 0);
	if (rc) {
		acls->err(acls, rc, "acls->put");
		goto err_out;
	}

	/* commit */
	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		return cli_err(cli, InternalError);
	}

	if (asprintf(&hdr,
"HTTP/%d.%d 200 x\r\n"
"Content-Length: 0\r\n"
"Date: %s\r\n"
"Location: /%s\r\n"
"Server: " PACKAGE_STRING "\r\n"
"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     time2str(timestr, time(NULL)),
		     bucket) < 0)
		return cli_err(cli, InternalError);

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc) {
		free(hdr);
		return true;
	}

	return cli_write_start(cli);

err_out:
	if (txn->abort(txn))
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	return cli_err(cli, err);
}

bool bucket_del(struct client *cli, const char *user, const char *bucket)
{
	char *hdr, timestr[64];
	enum errcode err = InternalError;
	int rc;
	struct db_bucket_ent *ent;
	DB_ENV *dbenv = tdb.env;
	DB_TXN *txn = NULL;
	DB *buckets = tdb.buckets;
	DB *acls = tdb.acls;
	DB *objs = tdb.objs;
	DBC *cur = NULL;
	DBT key, val;
	char structbuf[sizeof(struct db_acl_key) + 32];
	struct db_acl_key *acl_key = (struct db_acl_key *) &structbuf;
	struct db_obj_key *obj_key = (struct db_obj_key *) &structbuf;

	if (!user)
		return cli_err(cli, AccessDenied);

	/* open transaction */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto err_out;
	}

	/* search for (bucket, *) in object database, to see if
	 * any objects associated with this bucket exist
	 */
	rc = objs->cursor(objs, txn, &cur, 0);
	if (rc) {
		objs->err(objs, rc, "objs->cursor");
		goto err_out;
	}

	memset(&structbuf, 0, sizeof(structbuf));
	strncpy(obj_key->bucket, bucket, sizeof(obj_key->bucket));
	obj_key->key[0] = 0;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	key.data = obj_key;
	key.size = sizeof(*obj_key) + strlen(obj_key->key) + 1;

	rc = cur->get(cur, &key, &val, DB_SET_RANGE);

	if (rc == 0) {
		struct db_obj_key *newkey = key.data;

		if (!strcmp(newkey->bucket, bucket)) {
			cur->close(cur);
			err = BucketNotEmpty;
			goto err_out;
		}
	}

	rc = cur->close(cur);
	if (rc) {
		objs->err(objs, rc, "objs->cursor_close");
		goto err_out;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));
	key.data = (char *) bucket;
	key.size = strlen(bucket) + 1;

	/* verify the bucket exists */
	rc = buckets->get(buckets, txn, &key, &val, 0);
	if (rc) {
		if (rc == DB_NOTFOUND)
			err = NoSuchBucket;
		else
			buckets->err(buckets, rc, "buckets->get");
		goto err_out;
	}

	ent = val.data;

	/* verify that it is the owner who wishes to delete bucket */
	if (strncmp(user, ent->owner, sizeof(ent->owner))) {
		err = AccessDenied;
		goto err_out;
	}

	/* delete bucket */
	rc = buckets->del(buckets, txn, &key, 0);
	if (rc)
		goto err_out;

	/* delete bucket ACLs */
	memset(&structbuf, 0, sizeof(structbuf));
	strncpy(acl_key->bucket, bucket, sizeof(acl_key->bucket));
	acl_key->key[0] = 0;

	memset(&key, 0, sizeof(key));
	key.data = acl_key;
	key.size = sizeof(*acl_key) + strlen(acl_key->key) + 1;

	rc = acls->del(acls, txn, &key, 0);
	if (rc && rc != DB_NOTFOUND)
		goto err_out;

	/* commit */
	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		return cli_err(cli, InternalError);
	}

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
	if (txn->abort(txn))
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	return cli_err(cli, err);
}

static void bucket_list_pfx(GList *content, GHashTable *common_pfx)
{
	GList *pfx_list, *tmpl;
	int cpfx_len;
	char *s;

	pfx_list = g_hash_table_get_keys(common_pfx);
	if (!pfx_list)
		return;

	cpfx_len = 40;
	tmpl = pfx_list;
	while (tmpl) {
		cpfx_len += strlen((char *) tmpl->data) + 30;
		tmpl = tmpl->next;
	}

	s = malloc(cpfx_len);

	strcpy(s, "  <CommonPrefixes>\r\n");

	tmpl = pfx_list;
	while (tmpl) {
		strcat(s, "    <Prefix>");
		strcat(s, (char *) tmpl->data);
		strcat(s, "</Prefix>\r\n");
		tmpl = tmpl->next;
	}

	g_list_free(pfx_list);

	strcat(s, "  </CommonPrefixes>\r\n");

	content = g_list_append(content, s);

}

struct bucket_list_info {
	char *prefix;
	size_t pfx_len;
	char *delim;
	char *last_comp;
	size_t last_comp_len;
	GList *res;
	GHashTable *common_pfx;
	int maxkeys;
	int n_keys;
	const char *next_key;
	bool trunc;
};

static bool bucket_list_iter(const char *key, const char *name,
			     const char *md5, struct bucket_list_info *bli)
{
	if (bli->delim) {
		const char *post, *end;
		char *cpfx;
		int comp_len;

		post = key + bli->pfx_len;
		end = strstr(post, bli->delim);
		comp_len = end ? end - post : 0;
		if (!comp_len)
			goto no_component;

		cpfx = strndup(key, bli->pfx_len + comp_len);
		if (!cpfx)
			return true;		/* stop traversal */

		if (g_hash_table_lookup(bli->common_pfx, cpfx)) {
			free(cpfx);
			return false;		/* continue traversal */
		}

		if (bli->last_comp && (bli->last_comp_len == comp_len) &&
		    !memcmp(post, bli->last_comp, comp_len)) {
			GList *ltmp;

			ltmp = g_list_last(bli->res);
			free(ltmp->data);
			bli->res = g_list_delete_link(bli->res, ltmp);

			g_hash_table_insert(bli->common_pfx, cpfx, NULL);

			free(bli->last_comp);
			bli->last_comp = NULL;

			return false;		/* continue traversal */
		}

		free(cpfx);
		bli->last_comp = strndup(post, comp_len);

no_component:
		do { ; } while(0);

	} else if (bli->last_comp) {
		free(bli->last_comp);
		bli->last_comp = NULL;
	}

	if (bli->n_keys == bli->maxkeys) {
		bli->next_key = key;
		bli->trunc = true;
		return true;		/* stop traversal */
	}

	bli->res = g_list_append(bli->res, strdup(key));
	bli->res = g_list_append(bli->res, strdup(name));
	bli->res = g_list_append(bli->res, strdup(md5));

	return false;		/* continue traversal */
}

bool bucket_list(struct client *cli, const char *user, const char *bucket)
{
	GHashTable *param;
	enum errcode err = InternalError;
	char *prefix, *marker, *maxkeys_str, *delim, *s;
	int maxkeys = 100, i, rc;
	GList *content, *tmpl;
	size_t pfx_len;
	struct bucket_list_info bli;
	bool rcb;
	DB_ENV *dbenv = tdb.env;
	DB_TXN *txn = NULL;
	DB *objs = tdb.objs;
	DBC *cur = NULL;
	DBT pkey, pval;
	struct db_obj_key *obj_key;
	size_t alloc_len;
	bool first_loop = true;
	bool seen_prefix = false;

	/* verify READ access */
	if (!user || !has_access(user, bucket, NULL, "READ")) {
		err = AccessDenied;
		goto err_out;
	}

	/* parse URI query string */
	param = req_query(&cli->req);
	if (!param)
		goto err_out;

	/* read useful params from query string */
	prefix = g_hash_table_lookup(param, "prefix");
	pfx_len = prefix ? strlen(prefix) : 0;

	marker = g_hash_table_lookup(param, "marker");
	delim = g_hash_table_lookup(param, "delim");
	maxkeys_str = g_hash_table_lookup(param, "maxkeys_str");
	if (maxkeys_str) {
		i = atoi(maxkeys_str);
		if (i > 0 && i < maxkeys)
			maxkeys = i;
	}

	/* open transaction */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto err_out;
	}

	/* search for (bucket, *) in object database, to see if
	 * any objects associated with this bucket exist
	 */
	rc = objs->cursor(objs, txn, &cur, 0);
	if (rc) {
		objs->err(objs, rc, "objs->cursor");
		goto err_out;
	}

	alloc_len = sizeof(*obj_key) +
		    (marker ? strlen(marker) :
		     prefix ? strlen(prefix) : 0) + 1;
	obj_key = alloca(alloc_len);

	memset(obj_key, 0, alloc_len);
	strncpy(obj_key->bucket, bucket, sizeof(obj_key->bucket));
	strcpy(obj_key->key, marker ? marker : prefix ? prefix : "");

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	pkey.data = obj_key;
	pkey.size = alloc_len;

	memset(&bli, 0, sizeof(bli));
	bli.prefix = prefix;
	bli.pfx_len = pfx_len;
	bli.delim = delim;
	bli.common_pfx = g_hash_table_new_full(g_str_hash, g_str_equal,
					       free, NULL);
	bli.maxkeys = maxkeys;

	/* iterate through each returned data row */
	while (1) {
		char *key, *name, *md5;
		int get_flags;
		struct db_obj_key *tmpkey;
		struct db_obj_ent *obj;
		bool have_prefix;

		if (first_loop) {
			get_flags = DB_SET_RANGE;
			first_loop = false;
		} else
			get_flags = DB_NEXT;

		rc = cur->get(cur, &pkey, &pval, get_flags);
		if (rc)
			break;

		tmpkey = pkey.data;
		obj = pval.data;

		if (strcmp(tmpkey->bucket, bucket))
			break;
		if (prefix) {
			have_prefix = (strncmp(tmpkey->key, prefix,
					       strlen(prefix)) == 0);
			if (!have_prefix) {
				if (!seen_prefix)
					/* continue searching for
					 * a record that begins with this
					 * prefix
					 */
					continue;
				else
					/* no more records with our prefix */
					break;
			}

			seen_prefix = true;
		}

		key = tmpkey->key;
		name = obj->name;
		md5 = obj->md5;

		if (bucket_list_iter(key, name, md5, &bli))
			break;
	}

	/* close cursor, transaction */
	rc = cur->close(cur);
	if (rc) {
		objs->err(objs, rc, "objs->cursor close");
		goto err_out_rb;
	}

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		goto err_out_param;
	}

	asprintf(&s,
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<ListBucketResult xmlns=\"http://indy.yyz.us/doc/2006-03-01/\">\r\n"
"  <Name>%s</Name>\r\n"
"  <MaxKeys>%d</MaxKeys>\r\n"
"  <IsTruncated>%s</IsTruncated>\r\n",

		 bucket,
		 maxkeys,
		 bli.trunc ? "true" : "false");

	content = g_list_append(NULL, s);

	if (prefix) {
		asprintf(&s, "  <Prefix>%s</Prefix>\n", prefix);
		content = g_list_append(content, s);
	}
	if (marker) {
		asprintf(&s, "  <Marker>%s</Marker>\n", marker);
		content = g_list_append(content, s);
	}

	tmpl = bli.res;
	while (tmpl) {
		char *key, *md5;
		char *fn, *name, timestr[64];
		struct stat st;

		key = tmpl->data;
		tmpl = tmpl->next;

		name = tmpl->data;
		tmpl = tmpl->next;

		md5 = tmpl->data;
		tmpl = tmpl->next;

		if (asprintf(&fn, "%s/%s", tabled_srv.data_dir, name) < 0)
			goto do_next;

		if (stat(fn, &st) < 0) {
			syslog(LOG_ERR, "blist stat(%s) failed: %s",
				fn, strerror(errno));
			st.st_mtime = 0;
			st.st_size = 0;
		}

		asprintf(&s,
                         "  <Contents>\r\n"
                         "    <Key>%s</Key>\r\n"
                         "    <LastModified>%s</LastModified>\r\n"
                         "    <ETag>%s</ETag>\r\n"
                         "    <Size>%llu</Size>\r\n"
                         "    <StorageClass>STANDARD</StorageClass>\r\n"
                         "    <Owner>\r\n"
                         "      <ID>%s</ID>\r\n"
                         "      <DisplayName>%s</DisplayName>\r\n"
                         "    </Owner>\r\n"
                         "  </Contents>\r\n",

			 key,
			 time2str(timestr, st.st_mtime),
			 md5,
			 (unsigned long long) st.st_size,
			 user,
			 user);

		content = g_list_append(content, s);

do_next:
		free(key);
		free(name);
		free(md5);
		free(fn);
	}

	g_list_free(bli.res);

	bucket_list_pfx(content, bli.common_pfx);

	s = strdup("</ListBucketResult>\r\n");
	content = g_list_append(content, s);

	free(bli.last_comp);
	g_hash_table_destroy(bli.common_pfx);
	g_hash_table_destroy(param);

	rcb = cli_resp_xml(cli, 200, content);

	g_list_free(content);

	return rcb;

err_out_rb:
	if (txn->abort(txn))
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
err_out_param:
	g_hash_table_destroy(param);
err_out:
	return cli_err(cli, err);
}

