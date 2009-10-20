
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

	if (user == NULL)
		user = DB_ACL_ANON;
	if (key == NULL)
		key = "";

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

	snprintf(perm, sizeof(perm), "%s,", perm_in);

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
	pkey.data = acl_key;
	pkey.size = alloc_len;

	memset(&pval, 0, sizeof(pval));
	pval.flags = DB_DBT_MALLOC;

	/* loop through matching records (if any) */
	rc = cur->get(cur, &pkey, &pval, DB_SET);
	while (rc == 0) {
		acl = pval.data;

		if (!strncmp(acl->grantee, user, sizeof(acl->grantee))) {
			match = (strstr(acl->perm, perm) != NULL);
			free(acl);
			break;
		}
		free(acl);

		memset(&pval, 0, sizeof(pval));
		pval.flags = DB_DBT_MALLOC;

		rc = cur->get(cur, &pkey, &pval, DB_NEXT_DUP);
	}

	if (rc && rc != DB_NOTFOUND)
		acls->err(acls, rc, "has_access iteration");

	/* close cursor, transaction */
	rc = cur->close(cur);
	if (rc)
		acls->err(acls, rc, "acls->cursor close");

	rc = txn->commit(txn, 0);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");

	return match;

err_out:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	return false;
}

static int add_access_user(DB_TXN *txn, const char *bucket, const char *key,
			   const char *user, const char *perms)
{
	DB *acls = tdb.acls;
	int key_len;
	int acl_len;
	struct db_acl_ent *acl;
	struct db_acl_key *acl_key;
	DBT pkey, pval;

	key_len = strlen(key);
	acl_len = sizeof(struct db_acl_ent) + key_len + 1;

	acl = alloca(acl_len);
	memset(acl, 0, acl_len);

	acl_key = (struct db_acl_key *) &acl->bucket;	/* trick */

	strncpy(acl->bucket, bucket, sizeof(acl->bucket));
	strncpy(acl->grantee, user, sizeof(acl->grantee));
	strncpy(acl->perm, perms, sizeof(acl->perm));
	strcpy(acl->key, key);

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	pkey.data = acl_key;
	pkey.size = sizeof(struct db_acl_key) + key_len + 1;

	pval.data = acl;
	pval.size = acl_len;

	return acls->put(acls, txn, &pkey, &pval, 0);
}

int add_access_canned(DB_TXN *txn, const char *bucket, const char *key,
		      const char *user, enum ReqACLC canacl)
{
	int rc;

	/* All 4 canned modes include FULL_CONTROL, so add that. */
	rc = add_access_user(txn, bucket, key,
			     user, "READ,WRITE,READ_ACP,WRITE_ACP,");
	if (rc)
		return rc;

	switch (canacl) {
	default: /* case ACLC_PRIV: */
		rc = 0;
		break;
	case ACLC_PUB_R:
		rc = add_access_user(txn, bucket, key, DB_ACL_ANON, "READ,");
		break;
	case ACLC_PUB_RW:
		rc = add_access_user(txn, bucket, key,
				     DB_ACL_ANON, "READ,WRITE,");
		break;
	case ACLC_AUTH_R:
		/* We do not implement this yet */
		rc = 0;
		break;
	}
	return rc;
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

	/* FIXME: Use of DB_NEXT rather than DB_SET to begin search
	 * means we iterate through entire db, rather than
	 * starting at the first matching key.
	 */

	/* loop through matching buckets, if any */
	while (1) {
		char timestr[64];
		struct db_bucket_ent *ent;

		rc = cur->pget(cur, &skey, &pkey, &pval, DB_NEXT);
		if (rc)
			break;

		ent = pval.data;

		s = g_markup_printf_escaped(
                        "    <Bucket>\r\n"
                        "      <Name>%s</Name>\r\n"
                        "      <CreationDate>%s</CreationDate>\r\n"
                        "    </Bucket>\r\n",

			     ent->name,
			     time2str(timestr,
			     	      GUINT64_FROM_LE(ent->time_create)));
		if (!s)
			goto err_out_content;

		content = g_list_append(content, s);
	}

	if (rc != DB_NOTFOUND)
		bidx->err(bidx, rc, "service_list iter");

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

static int bucket_find(DB_TXN *txn, const char *bucket, char *owner,
		       int owner_len)
{
	DB *buckets = tdb.buckets;
	DBT key, val;
	struct db_bucket_ent ent;
	int rc;

	memset(&key, 0, sizeof(key));
	key.data = (char *) bucket;
	key.size = strlen(bucket) + 1;

	memset(&val, 0, sizeof(val));
	val.data = &ent;
	val.ulen = sizeof(struct db_bucket_ent);
	val.flags = DB_DBT_USERMEM;

	rc = buckets->get(buckets, txn, &key, &val, 0);

	if (rc == 0 && owner != NULL && owner_len > 0) {
		strncpy(owner, ent.owner, owner_len);
		owner[owner_len-1] = 0;
	}

	return rc;
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
		if ((bucket = g_strndup(uri_path, p - uri_path)) == NULL)
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

/*
 * Match host against ourhost and return the bucket, if any.
 * This used to be handled with a regexp "^\\s*(\\w+)\\.(\\w.*)$",
 * but that failed due to hostnames having a dash in them.
 */
char *bucket_host(const char *host, const char *ourhost)
{
	size_t ourhlen = strlen(ourhost);
	size_t hlen = strlen(host);
	size_t bucklen;

	if (ourhlen >= hlen)
		return NULL;
	bucklen = hlen-ourhlen;		/* at least one */
	if (strcasecmp(host + bucklen, ourhost))
		return NULL;
	if (host[--bucklen] != '.')
		return NULL;
	if (bucklen == 0)
		return NULL;
	return g_strndup(host, bucklen);
}

bool bucket_add(struct client *cli, const char *user, const char *bucket)
{
	char *hdr, timestr[64];
	enum errcode err = InternalError;
	int rc;
	struct db_bucket_ent ent;
	bool setacl;			/* is ok to put pre-existing bucket */
	enum ReqACLC canacl;
	DB *buckets = tdb.buckets;
	DB *acls = tdb.acls;
	DB_ENV *dbenv = tdb.env;
	DB_TXN *txn = NULL;
	DBT key, val;

	if (!user)
		return cli_err(cli, AccessDenied);

	/* prepare parameters */
	setacl = false;
	if (cli->req.uri.query_len) {
		switch (req_is_query(&cli->req)) {
		case URIQ_ACL:
			setacl = true;
			break;
		default:
			err = InvalidURI;
			goto err_par;
		}
	}

	if ((rc = req_acl_canned(&cli->req)) == ACLCNUM) {
		err = InvalidArgument;
		goto err_par;
	}
	canacl = (rc == -1)? ACLC_PRIV: rc;

	/* begin trans */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto err_db;
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

	if (setacl) {
		/* check if the bucket exists, else insert it */
		rc = bucket_find(txn, bucket, NULL, 0);
		if (rc) {
			if (rc != DB_NOTFOUND) {
				buckets->err(buckets, rc, "buckets->find");
				goto err_out;
			}

			rc = buckets->put(buckets, txn, &key, &val,
							DB_NOOVERWRITE);
			if (rc) {
				buckets->err(buckets, rc, "buckets->put");
				goto err_out;
			}
		} else {
			if (!has_access(user, bucket, NULL, "WRITE_ACP")) {
				err = AccessDenied;
				goto err_out;
			}
			if (!object_del_acls(txn, bucket, ""))
				goto err_out;
		}

	} else {
		/* attempt to insert new bucket */
		rc = buckets->put(buckets, txn, &key, &val, DB_NOOVERWRITE);
		if (rc) {
			if (rc == DB_KEYEXIST)
				err = BucketAlreadyExists;
			else
				buckets->err(buckets, rc, "buckets->put");
			goto err_out;
		}
	}

	/* insert bucket ACL */
	rc = add_access_canned(txn, bucket, "", user, canacl);
	if (rc) {
		acls->err(acls, rc, "acls->put");
		goto err_out;
	}

	/* commit -- no more exception emulation with goto. */
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
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
err_db:
err_par:
	return cli_err(cli, err);
}

bool bucket_del(struct client *cli, const char *user, const char *bucket)
{
	char *hdr, timestr[64];
	enum errcode err = InternalError;
	int rc;
	struct db_bucket_ent ent;
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

	val.flags = DB_DBT_MALLOC;

	rc = cur->get(cur, &key, &val, DB_SET_RANGE);

	if (rc == 0) {
		struct db_obj_key *newkey = key.data;

		if (!strcmp(newkey->bucket, bucket)) {
			free(newkey);
			cur->close(cur);
			err = BucketNotEmpty;
			goto err_out;
		}

		free(newkey);
	} else if (rc != DB_NOTFOUND)
		objs->err(objs, rc, "bucket_del empty check");

	rc = cur->close(cur);
	if (rc) {
		objs->err(objs, rc, "objs->cursor_close");
		goto err_out;
	}

	memset(&key, 0, sizeof(key));
	key.data = (char *) bucket;
	key.size = strlen(bucket) + 1;

	memset(&val, 0, sizeof(val));
	val.data = &ent;
	val.ulen = sizeof(struct db_bucket_ent);
	val.flags = DB_DBT_USERMEM;

	/* verify the bucket exists */
	rc = buckets->get(buckets, txn, &key, &val, 0);
	if (rc) {
		if (rc == DB_NOTFOUND)
			err = NoSuchBucket;
		else
			buckets->err(buckets, rc, "buckets->get");
		goto err_out;
	}

	/* verify that it is the owner who wishes to delete bucket */
	if (strncmp(user, ent.owner, sizeof(ent.owner))) {
		err = AccessDenied;
		goto err_out;
	}

	/* delete bucket */
	rc = buckets->del(buckets, txn, &key, 0);
	if (rc) {
		buckets->err(buckets, rc, "bucket del");
		goto err_out;
	}

	/* delete bucket ACLs */
	memset(&structbuf, 0, sizeof(structbuf));
	strncpy(acl_key->bucket, bucket, sizeof(acl_key->bucket));
	acl_key->key[0] = 0;

	memset(&key, 0, sizeof(key));
	key.data = acl_key;
	key.size = sizeof(*acl_key) + strlen(acl_key->key) + 1;

	rc = acls->del(acls, txn, &key, 0);
	if (rc && rc != DB_NOTFOUND) {
		acls->err(acls, rc, "acl del");
		goto err_out;
	}

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
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	return cli_err(cli, err);
}

/*
 * It looks obvious that one CommonPrefixes collection includes many
 * Prefix elements. This is why it's in plural, right? Not so.
 * The reference implementation lists one key per collection and
 * by now some applications depend on it (well, Boto self-test does).
 */
static GList *bucket_list_pfx(GList *content, GHashTable *common_pfx,
			      const char *delim0)
{
	GList *pfx_list, *tmpl;
	int cpfx_len;
	int pfx_len;
	int delim_len;
	char *s, *p;
	char *prefix;
	char *delim;
	const static char optag[] = "  <CommonPrefixes>\r\n";
	const static char edtag[] = "  </CommonPrefixes>\r\n";
	const static char pfoptag[] = "    <Prefix>";
	const static char pfedtag[] = "</Prefix>\r\n";

	pfx_list = g_hash_table_get_keys(common_pfx);
	if (!pfx_list)
		return content;

	/* At this point delim0 cannot be NULL, since we have a list. */

	if ((delim = g_markup_escape_text(delim0, -1)) == NULL) {
		g_list_free(pfx_list);
		return content;
	}
	delim_len = strlen(delim);

	cpfx_len = 0;
	tmpl = pfx_list;
	while (tmpl) {
		prefix = g_markup_escape_text((char *) tmpl->data, -1);
		pfx_len = strlen(prefix);
		tmpl->data = prefix;

		cpfx_len += sizeof(optag)-1;
		cpfx_len += sizeof(pfoptag)-1;
		cpfx_len += pfx_len;
		cpfx_len += delim_len;
		cpfx_len += sizeof(pfedtag)-1;
		cpfx_len += sizeof(edtag)-1;

		tmpl = tmpl->next;
	}
	cpfx_len += 1;

	s = malloc(cpfx_len);
	p = s;

	tmpl = pfx_list;
	while (tmpl) {
		prefix = (char *) tmpl->data;
		pfx_len = strlen(prefix);

		memcpy(p, optag, sizeof(optag)-1);  p += sizeof(optag)-1;
		memcpy(p, pfoptag, sizeof(pfoptag)-1);  p += sizeof(pfoptag)-1;
		memcpy(p, prefix, pfx_len);  p += pfx_len;
		memcpy(p, delim, delim_len);  p += delim_len;
		memcpy(p, pfedtag, sizeof(pfedtag)-1);  p += sizeof(pfedtag)-1;
		memcpy(p, edtag, sizeof(edtag)-1);  p += sizeof(edtag)-1;

		free(prefix);

		tmpl = tmpl->next;
	}
	*p = 0;

	free(delim);
	g_list_free(pfx_list);

	return g_list_append(content, s);
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

struct obj_vitals {
	char			*key;
	uint64_t		size;
	uint64_t		mtime;
	struct db_obj_addr	addr;
	char			md5[40];
};

static bool bucket_list_iter(const char *key, struct obj_vitals *v,
			     struct bucket_list_info *bli)
{
	struct obj_vitals *vitals;

	if (bli->delim) {
		const char *post, *end;
		char *cpfx;
		int comp_len;
		gpointer orig_key, orig_val;

		post = key + bli->pfx_len;
		end = strstr(post, bli->delim);
		comp_len = end ? end - post : 0;
		if (!comp_len)
			goto no_component;

		cpfx = g_strndup(key, bli->pfx_len + comp_len);
		if (!cpfx)
			return true;		/* stop traversal */

		if (g_hash_table_lookup_extended(bli->common_pfx, cpfx,
		    &orig_key, &orig_val)) {
			free(cpfx);
			return false;		/* continue traversal */
		}

		if (bli->last_comp && (bli->last_comp_len == comp_len) &&
		    !memcmp(post, bli->last_comp, comp_len)) {
			GList *ltmp;
			struct obj_vitals *vp;

			--bli->n_keys;
			ltmp = g_list_last(bli->res);
			vp = ltmp->data;
			free(vp->key);
			free(vp);
			bli->res = g_list_delete_link(bli->res, ltmp);

			g_hash_table_insert(bli->common_pfx, cpfx, NULL);

			free(bli->last_comp);
			bli->last_comp = NULL;

			return false;		/* continue traversal */
		}

		free(cpfx);
		bli->last_comp = g_strndup(post, comp_len);
		bli->last_comp_len = comp_len;

no_component:
		do { ; } while(0);

	}

	if (bli->n_keys == bli->maxkeys) {
		bli->next_key = key;
		bli->trunc = true;
		return true;		/* stop traversal */
	}

	if (!(vitals = malloc(sizeof(struct obj_vitals))))
		return false;
	memcpy(vitals, v, sizeof(struct obj_vitals));
	if (!(vitals->key = strdup(key))) {
		free(vitals);
		return false;
	}

	bli->res = g_list_append(bli->res, vitals);
	bli->n_keys++;

	return false;		/* continue traversal */
}

static bool bucket_list_keys(struct client *cli, const char *user,
			     const char *bucket)
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
	bool seen_prefix = false;
	int get_flags;

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
	delim = g_hash_table_lookup(param, "delimiter");
	maxkeys_str = g_hash_table_lookup(param, "max-keys");
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
		    (marker ? strlen(marker) : pfx_len) + 1;
	obj_key = alloca(alloc_len);

	memset(obj_key, 0, alloc_len);
	strncpy(obj_key->bucket, bucket, sizeof(obj_key->bucket));
	strcpy(obj_key->key, marker ? marker : prefix ? prefix : "");

	memset(&pkey, 0, sizeof(pkey));
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
	get_flags = DB_SET_RANGE;
	while (1) {
		struct obj_vitals v;
		struct db_obj_key *tmpkey;
		struct db_obj_ent *obj;

		memset(&pval, 0, sizeof(pval));
		pval.flags = DB_DBT_MALLOC;

		rc = cur->get(cur, &pkey, &pval, get_flags);
		if (rc) {
			if (rc != DB_NOTFOUND)
				objs->err(objs, rc, "bucket_list_keys iter");
			break;
		}

		get_flags = DB_NEXT;

		tmpkey = pkey.data;
		obj = pval.data;

		if (strcmp(tmpkey->bucket, bucket)) {
			free(obj);
			break;
		}
		if (prefix) {
			if (strncmp(tmpkey->key, prefix, pfx_len) != 0) {
				free(obj);
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

		memset(&v, 0, sizeof(v));
		strcpy(v.md5, obj->md5);
		if (!(GUINT32_FROM_LE(obj->flags) & DB_OBJ_INLINE))
			memcpy(&v.addr, &obj->d.a, sizeof(v.addr));
		v.mtime = obj->mtime;
		v.size = obj->size;
		free(obj);

		if (bucket_list_iter(tmpkey->key, &v, &bli))
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

	s = g_markup_printf_escaped(
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
		s = g_markup_printf_escaped("  <Prefix>%s</Prefix>\n", prefix);
		content = g_list_append(content, s);
	}
	if (marker) {
		s = g_markup_printf_escaped("  <Marker>%s</Marker>\n", marker);
		content = g_list_append(content, s);
	}

	tmpl = bli.res;
	while (tmpl) {
		char timestr[64];
		struct obj_vitals *vp;

		vp = tmpl->data;
		tmpl = tmpl->next;

		/*
		 * FIXME Use the vp->addr to verify that key still exists.
		 * And if it doesn't, then what? (addr.nid can be 0 for inline)
		 */

		s = g_markup_printf_escaped(
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

			 vp->key,
			 time2str(timestr, vp->mtime / 1000000),
			 vp->md5,
			 (unsigned long long) vp->size,
			 user,
			 user);

		content = g_list_append(content, s);

		free(vp->key);
		free(vp);
	}

	g_list_free(bli.res);

	content = bucket_list_pfx(content, bli.common_pfx, bli.delim);

	s = strdup("</ListBucketResult>\r\n");
	content = g_list_append(content, s);

	free(bli.last_comp);
	g_hash_table_destroy(bli.common_pfx);
	g_hash_table_destroy(param);

	rcb = cli_resp_xml(cli, 200, content);

	g_list_free(content);

	return rcb;

err_out_rb:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
err_out_param:
	g_hash_table_destroy(param);
err_out:
	return cli_err(cli, err);
}

bool access_list(struct client *cli, const char *bucket, const char *key,
		 const char *user)
{
	struct macl {
		char		perm[128];		/* perm(s) granted */
		char		grantee[64];		/* grantee user */
	};

	GHashTable *param;
	enum errcode err = InternalError;
	DB_ENV *dbenv = tdb.env;
	DB *acls = tdb.acls;
	int alloc_len;
	char owner[64];
	GList *res;
	struct db_acl_key *acl_key;
	struct db_acl_ent *acl;
	DB_TXN *txn = NULL;
	DBC *cur = NULL;
	GList *content;
	DBT pkey, pval;
	struct macl *mp;
	char guser[64];
	GList *p;
	char *s;
	int str_len;
	int rc;
	bool rcb;

	/* verify READ access for ACL */
	if (!user || !has_access(user, bucket, key, "READ_ACP")) {
		err = AccessDenied;
		goto err_out;
	}

	/* parse URI query string */
	param = req_query(&cli->req);
	if (!param)
		goto err_out;

	res = NULL;

	alloc_len = sizeof(struct db_acl_key) + strlen(key) + 1;
	acl_key = alloca(alloc_len);
	memset(acl_key, 0, alloc_len);

	strncpy(acl_key->bucket, bucket, sizeof(acl_key->bucket));
	strcpy(acl_key->key, key);

	/* open transaction, search cursor */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto err_out_param;
	}

	rc = bucket_find(txn, bucket, &owner[0], sizeof(owner));
	if (rc) {
		if (rc == DB_NOTFOUND)
			err = InvalidBucketName;
		else
			dbenv->err(dbenv, rc, "bucket_find");
		goto err_out_rb;
	}

	rc = acls->cursor(acls, txn, &cur, 0);
	if (rc) {
		acls->err(acls, rc, "acls->cursor");
		goto err_out_rb;
	}

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = acl_key;
	pkey.size = alloc_len;

	for (;; free(acl)) {

		memset(&pval, 0, sizeof(pval));
		pval.flags = DB_DBT_MALLOC;

		rc = cur->get(cur, &pkey, &pval, DB_NEXT);
		if (rc)
			break;

		acl = pval.data;

		/* This is a workaround, see FIXME about DB_NEXT. */
		if (strncmp(acl->bucket, bucket, sizeof(acl->bucket)))
			continue;
		if (strcmp(acl->key, key))
			continue;

		if ((mp = malloc(sizeof(struct macl))) == NULL) {
			free(acl);
			cur->close(cur);
			goto err_out_rb;
		}

		memcpy(mp->grantee, acl->grantee, sizeof(mp->grantee));
		mp->grantee[sizeof(mp->grantee)-1] = 0;

		memcpy(mp->perm, acl->perm, sizeof(mp->perm));

		/* lop off the trailing comma */
		mp->perm[sizeof(mp->perm)-1] = 0;
		str_len = strlen(mp->perm);
		if (str_len && mp->perm[str_len-1] == ',')
			mp->perm[--str_len] = 0;

		res = g_list_append(res, mp);
	}

	if (rc != DB_NOTFOUND)
		acls->err(acls, rc, "access_list iteration");

	/* close cursor, transaction */
	rc = cur->close(cur);
	if (rc)
		acls->err(acls, rc, "acls->cursor close");
	rc = txn->commit(txn, 0);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");

	/* dump collected acls -- no more exception handling */

	s = g_markup_printf_escaped(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		"<AccessControlPolicy "
		     "xmlns=\"http://indy.yyz.us/doc/2006-03-01/\">\r\n"
		"  <Owner>\r\n"
		"    <ID>%s</ID>\r\n"
		"    <DisplayName>%s</DisplayName>\r\n"
		"  </Owner>\r\n",
		owner, owner);
	content = g_list_append(NULL, s);

	s = g_markup_printf_escaped(
		"  <AccessControlList>\r\n");
	content = g_list_append(content, s);

	for (p = res; p != NULL; p = p->next) {
		mp = p->data;

		if (!strcmp(DB_ACL_ANON, mp->grantee)) {
			strcpy(guser, "anonymous");
		} else {
			strncpy(guser, mp->grantee, sizeof(guser));
			guser[sizeof(guser)-1] = 0;
		}

		s = g_markup_printf_escaped(
			"    <Grant>\r\n"
			"      <Grantee xmlns:xsi=\"http://www.w3.org/2001/"
			"XMLSchema-instance\" xsi:type=\"CanonicalUser\">\r\n"
			"        <ID>%s</ID>\r\n"
			"        <DisplayName>%s</DisplayName>\r\n"
			"      </Grantee>\r\n",
			guser, guser);
		content = g_list_append(content, s);

		/*
		 * FIXME This parsing is totally lame, we should replace
		 * strings with a bit mask once we make sure this works.
		 */
		if (!strcmp(mp->perm, "READ,WRITE,READ_ACP,WRITE_ACP")) {
			s = g_markup_printf_escaped(
			   "      <Permission>FULL_CONTROL</Permission>\r\n");
		} else {
			s = g_markup_printf_escaped(
			   "      <Permission>%s</Permission>\r\n",
			   mp->perm);
		}
		content = g_list_append(content, s);

		s = g_markup_printf_escaped("    </Grant>\r\n");
		content = g_list_append(content, s);

		free(mp);
	}

	s = g_markup_printf_escaped("  </AccessControlList>\r\n");
	content = g_list_append(content, s);

	s = g_markup_printf_escaped("</AccessControlPolicy>\r\n");
	content = g_list_append(content, s);

	g_list_free(res);

	rcb = cli_resp_xml(cli, 200, content);
	g_list_free(content);
	return rcb;

err_out_rb:
	rc = txn->abort(txn);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	for (p = res; p != NULL; p = p->next)
		free(p->data);
	g_list_free(res);
err_out_param:
	g_hash_table_destroy(param);
err_out:
	return cli_err(cli, err);
}

bool bucket_list(struct client *cli, const char *user, const char *bucket)
{
	bool getacl;

	getacl = false;
	if (cli->req.uri.query_len) {
		switch (req_is_query(&cli->req)) {
		case URIQ_ACL:
			getacl = true;
			break;
		default:
			/* Don't bomb, fall to bucket_list_keys */
			break;
		}
	}

	if (getacl)
		return access_list(cli, bucket, "", user);
	else
		return bucket_list_keys(cli, user, bucket);
}
