
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
#include <sqlite3.h>
#include <alloca.h>
#include "tabled.h"

bool has_access(const char *user, const char *bucket, const char *key,
		const char *perm_in)
{
	sqlite3_stmt *stmt;
	int rc;
	char perm[16];
	const char *perm_db;
	bool match;

	sprintf(perm, "%s,", perm_in);

	if (key)
		stmt = prep_stmts[st_acl_object];
	else
		stmt = prep_stmts[st_acl_bucket];

	sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, bucket, -1, SQLITE_STATIC);
	if (key)
		sqlite3_bind_text(stmt, 3, key, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);

	if (rc != SQLITE_ROW) {
		sqlite3_reset(stmt);
		return false;
	}

	perm_db = (const char *) sqlite3_column_text(stmt, 0);
	match = (strstr(perm_db, perm) == NULL) ? false : true;
	sqlite3_reset(stmt);

	return match;
}

bool service_list(struct client *cli, const char *user)
{
	GList *files = NULL, *content = NULL;
	char *s;
	enum errcode err = InternalError;
	int rc;
	bool rcb;
	sqlite3_stmt *stmt = prep_stmts[st_service_list];

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

	sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);

	while (1) {
		char timestr[64];

		rc = sqlite3_step(stmt);
		if (rc == SQLITE_DONE || rc == SQLITE_BUSY)
			break;
		g_assert(rc == SQLITE_ROW);

		if (asprintf(&s,
                        "    <Bucket>\r\n"
                        "      <Name>%s</Name>\r\n"
                        "      <CreationDate>%s</CreationDate>\r\n"
                        "    </Bucket>\r\n",

			     sqlite3_column_text(stmt, 0),
			     time2str(timestr,
			     	      sqlite3_column_int64(stmt, 1))) < 0)
			goto err_out_content;

		content = g_list_append(content, s);
	}

	rc = sqlite3_reset(stmt);
	g_assert(rc == SQLITE_OK);

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

bool bucket_valid(const char *bucket)
{
	int captured[4];
	size_t len;

	if (!bucket)
		return false;

	len = strlen(bucket);
	if (len < 1 || len > 63)
		return false;

	return pcre_exec(patterns[pat_bucket_name].re, NULL,
			 bucket, len, 0, 0, captured, 4) == 1 ? true : false;
}

bool bucket_add(struct client *cli, const char *user, const char *bucket)
{
	char *hdr, timestr[64];
	enum errcode err = InternalError;
	sqlite3_stmt *stmt;
	int rc;

	/* begin trans */
	if (!sql_begin())
		return cli_err(cli, InternalError);

	/* check bucket existence */
	stmt = prep_stmts[st_bucket];
	sqlite3_bind_text(stmt, 1, bucket, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);
	if (rc == SQLITE_ROW) {
		err = BucketAlreadyExists;
		goto err_out;
	}

	/* insert bucket */
	stmt = prep_stmts[st_add_bucket];
	sqlite3_bind_text(stmt, 1, bucket, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, user, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, time(NULL));

	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	if (rc != SQLITE_DONE)
		goto err_out;

	/* insert bucket ACL */
	stmt = prep_stmts[st_add_acl];
	sqlite3_bind_text(stmt, 1, bucket, -1, SQLITE_STATIC);
	sqlite3_bind_null(stmt, 2);
	sqlite3_bind_text(stmt, 3, user, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, "READ,WRITE,READ_ACL,WRITE_ACL,", -1,
			  SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	if (rc != SQLITE_DONE)
		goto err_out;

	/* commit */
	if (!sql_commit())
		return cli_err(cli, InternalError);

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
	sql_rollback();
	return cli_err(cli, err);
}

bool bucket_del(struct client *cli, const char *user, const char *bucket)
{
	const char *owner;
	char *hdr, timestr[64];
	enum errcode err = InternalError;
	sqlite3_stmt *stmt;
	int rc;

	if (!user)
		return cli_err(cli, AccessDenied);

	/* begin trans */
	if (!sql_begin())
		return cli_err(cli, InternalError);

	/* verify that bucket is empty */
	stmt = prep_stmts[st_bucket_objects];
	sqlite3_bind_text(stmt, 1, bucket, -1, SQLITE_STATIC);
	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	if (rc == SQLITE_ROW) {
		err = BucketNotEmpty;
		goto err_out;
	}

	/* verify that bucket exists */
	stmt = prep_stmts[st_bucket];
	sqlite3_bind_text(stmt, 1, bucket, -1, SQLITE_STATIC);
	rc = sqlite3_step(stmt);

	if (rc != SQLITE_ROW) {
		sqlite3_reset(stmt);
		err = NoSuchBucket;
		goto err_out;
	}

	/* verify that it is the owner who wishes to delete bucket */
	owner = (const char *) sqlite3_column_text(stmt, 1);
	rc = strcmp(owner, user);
	sqlite3_reset(stmt);

	if (rc) {
		err = AccessDenied;
		goto err_out;
	}

	/* delete bucket */
	stmt = prep_stmts[st_del_bucket];
	sqlite3_bind_text(stmt, 1, bucket, -1, SQLITE_STATIC);
	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	if (rc != SQLITE_DONE)
		goto err_out;

	/* delete bucket ACLs */
	stmt = prep_stmts[st_del_bucket_acl];
	sqlite3_bind_text(stmt, 1, bucket, -1, SQLITE_STATIC);
	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	if (rc != SQLITE_DONE)
		goto err_out;

	/* commit */
	if (!sql_commit())
		return cli_err(cli, InternalError);

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
	sql_rollback();
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
	char *zsql;
	const char *dummy;
	bool rcb;
	sqlite3_stmt *select;

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

	/* build SQL SELECT statement */
	zsql = alloca(80 +
		      (prefix ? strlen(prefix) : 0) +
		      (marker ? strlen(marker) : 0));

	strcpy(zsql, "select key, name, md5 from objects where bucket = ?");
	if (marker)
		strcat(zsql, " and key >= ?");
	if (prefix)
		strcat(zsql, " and key glob ?");
	strcat(zsql, " order by key asc");

	rc = sqlite3_prepare_v2(sqldb, zsql, -1, &select, &dummy);
	if (rc != SQLITE_OK)
		goto err_out_param;

	/* exec SQL query */
	i = 1;
	sqlite3_bind_text(select, i++, bucket, -1, SQLITE_STATIC);
	if (marker)
		sqlite3_bind_text(select, i++, marker, -1, SQLITE_STATIC);
	if (prefix) {
		s = alloca(strlen(prefix) + 2);
		sprintf(s, "%s*", prefix);
		sqlite3_bind_text(select, i++, s, -1, SQLITE_STATIC);
	}

	memset(&bli, 0, sizeof(bli));
	bli.prefix = prefix;
	bli.pfx_len = pfx_len;
	bli.delim = delim;
	bli.common_pfx = g_hash_table_new_full(g_str_hash, g_str_equal,
					       free, NULL);
	bli.maxkeys = maxkeys;

	/* iterate through each returned SQL data row */
	while (1) {
		const char *key, *name, *md5;

		rc = sqlite3_step(select);
		if (rc != SQLITE_ROW)
			break;

		key = (const char *) sqlite3_column_text(select, 0);
		name = (const char *) sqlite3_column_text(select, 1);
		md5 = (const char *) sqlite3_column_text(select, 2);

		if (!bucket_list_iter(key, name, md5, &bli))
			break;
	}

	sqlite3_finalize(select);

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

err_out_param:
	g_hash_table_destroy(param);
err_out:
	return cli_err(cli, err);
}

