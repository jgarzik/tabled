#define _GNU_SOURCE
#include "tabled-config.h"
#include <sys/types.h>
#include <sys/stat.h>
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

static bool __object_del(const char *bucket, const char *key)
{
	int rc;
	sqlite3_stmt *stmt;

	/* delete object metadata */
	stmt = prep_stmts[st_del_obj];
	sqlite3_bind_text(stmt, 1, bucket, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, key, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	if (rc != SQLITE_DONE) {
		syslog(LOG_ERR, "SQL st_del_obj failed: %d", rc);
		return false;
	}

	/* delete object ACLs */
	stmt = prep_stmts[st_del_obj_acl];
	sqlite3_bind_text(stmt, 1, bucket, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, key, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	if (rc != SQLITE_DONE) {
		syslog(LOG_ERR, "SQL st_del_obj_acl failed: %d", rc);
		return false;
	}

	/* delete object headers */
	stmt = prep_stmts[st_del_headers];
	sqlite3_bind_text(stmt, 1, bucket, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, key, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	if (rc != SQLITE_DONE) {
		syslog(LOG_ERR, "SQL st_del_headers failed: %d", rc);
		return false;
	}

	return true;
}

bool object_del(struct client *cli, const char *user,
		const char *bucket, const char *key)
{
	char timestr[64], *hdr, *fn;
	int rc;
	enum errcode err = InternalError;
	const char *basename;
	sqlite3_stmt *stmt;

	/* begin trans */
	if (!sql_begin()) {
		syslog(LOG_ERR, "SQL BEGIN failed in obj-del");
		return cli_err(cli, InternalError);
	}

	if (!user || !has_access(user, bucket, NULL, "WRITE")) {
		err = AccessDenied;
		goto err_out;
	}

	/* read existing object info, if any */
	stmt = prep_stmts[st_object];
	sqlite3_bind_text(stmt, 1, bucket, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, key, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		sqlite3_reset(stmt);
		err = NoSuchKey;
		goto err_out;
	}

	/* build data filename, for later use */
	basename = (const char *) sqlite3_column_text(stmt, 3);
	fn = alloca(strlen(tabled_srv.data_dir) + strlen(basename) + 2);
	sprintf(fn, "%s/%s", tabled_srv.data_dir, basename);

	sqlite3_reset(stmt);

	if (!__object_del(bucket, key))
		goto err_out;

	if (!sql_commit()) {
		syslog(LOG_ERR, "SQL COMMIT failed in obj-del");
		return cli_err(cli, InternalError);
	}

	if (unlink(fn) < 0)
		syslog(LOG_ERR, "object data(%s) unlink failed: %s",
		       fn, strerror(errno));
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

void cli_out_end(struct client *cli)
{
	if (!cli)
		return;

	if (cli->out_fn) {
		unlink(cli->out_fn);
		free(cli->out_fn);
		cli->out_fn = NULL;
	}

	free(cli->out_bucket);
	free(cli->out_key);
	free(cli->out_user);

	cli->out_user =
	cli->out_bucket =
	cli->out_key = NULL;

	if (cli->out_fd >= 0) {
		close(cli->out_fd);
		cli->out_fd = -1;
	}
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

static bool try_copy_header(const char *bucket, const char *key,
			    struct http_hdr *hdr)
{
	sqlite3_stmt *stmt;
	int rc;

	if (!should_copy_header(hdr))
		return true;

	stmt = prep_stmts[st_add_header];
	sqlite3_bind_text(stmt, 1, bucket, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, key, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, hdr->key, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, hdr->val, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	return (rc == SQLITE_DONE) ? true : false;
}

static bool object_put_end(struct client *cli)
{
	unsigned char md[MD5_DIGEST_LENGTH];
	char counter[64], md5[33], timestr[64];
	char *type, *hdr, *fn = NULL;
	int rc, i;
	enum errcode err = InternalError;
	sqlite3_stmt *stmt;

	if (http11(&cli->req))
		cli->state = evt_recycle;
	else
		cli->state = evt_dispose;

	if (fsync(cli->out_fd) < 0) {
		syslog(LOG_ERR, "fsync(%s) failed: %s",
		       cli->out_fn, strerror(errno));
		goto err_out;
	}

	if (debugging) {
		struct stat sst;
		if (fstat(cli->out_fd, &sst) < 0)
			syslog(LOG_ERR, "fstat(%s) failed: %s",
			       cli->out_fn, strerror(errno));
		else
			syslog(LOG_DEBUG, "STORED %s, size %llu",
			       cli->out_fn,
			       (unsigned long long) sst.st_size);
	}

	close(cli->out_fd);
	cli->out_fd = -1;

	MD5_Final(md, &cli->out_md5);

	sprintf(counter, "%016llX", (unsigned long long) cli->out_counter);
	md5str(md, md5);

	type = req_hdr(&cli->req, "content-type");
	if (!type)
		type = "binary/octet-stream";
	else
		type = NULL;

	/* begin trans */
	if (!sql_begin()) {
		syslog(LOG_ERR, "SQL BEGIN failed in put-end");
		goto err_out;
	}

	/* read existing object info, if any */
	stmt = prep_stmts[st_object];
	sqlite3_bind_text(stmt, 1, cli->out_bucket, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, cli->out_key, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);

	if (rc == SQLITE_ROW) {
		/* build data filename, for later use */
		const char *basename = (const char *)
			sqlite3_column_text(stmt, 3);
		fn = alloca(strlen(tabled_srv.data_dir) + strlen(basename) + 2);
		sprintf(fn, "%s/%s", tabled_srv.data_dir, basename);

		sqlite3_reset(stmt);

		/* delete object metadata, ACLs */
		if (!__object_del(cli->out_bucket, cli->out_key)) {
			syslog(LOG_ERR, "old-obj(%s) delete failed", fn);
			goto err_out_rb;
		}
	} else
		sqlite3_reset(stmt);

	/* insert object */
	stmt = prep_stmts[st_add_obj];
	sqlite3_bind_text(stmt, 1, cli->out_bucket, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, cli->out_key, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, md5, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, counter, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 5, cli->out_user, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	if (rc != SQLITE_DONE) {
		syslog(LOG_ERR, "SQL INSERT(obj) failed");
		goto err_out_rb;
	}

	/* insert object ACL */
	stmt = prep_stmts[st_add_acl];
	sqlite3_bind_text(stmt, 1, cli->out_bucket, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, cli->out_key, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, cli->out_user, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, "READ,WRITE,READ_ACL,WRITE_ACL,", -1,
			  SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	if (rc != SQLITE_DONE) {
		syslog(LOG_ERR, "SQL INSERT(obj acl) failed");
		goto err_out_rb;
	}

	/* copy select headers */
	for (i = 0; i < cli->req.n_hdr; i++)
		if (!try_copy_header(cli->out_bucket, cli->out_key,
				     &cli->req.hdr[i])) {
			syslog(LOG_ERR, "SQL INSERT(obj header) failed");
			goto err_out_rb;
		}

	if (type) {
		struct http_hdr hdr = { "Content-Type", type };
		if (!try_copy_header(cli->out_bucket, cli->out_key, &hdr))
			goto err_out_rb;
	}

	/* commit */
	if (!sql_commit()) {
		syslog(LOG_ERR, "SQL COMMIT");
		goto err_out;
	}

	if (fn && (unlink(fn) < 0))
		syslog(LOG_ERR, "object data(%s) unlink failed: %s",
		       fn, strerror(errno));

	free(cli->out_fn);
	free(cli->out_bucket);
	free(cli->out_key);
	free(cli->out_user);

	cli->out_user =
	cli->out_fn =
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
	sql_rollback();
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
		bytes = write(cli->out_fd, p, avail);
		if (bytes < 0) {
			cli_out_end(cli);
			syslog(LOG_ERR, "write(2) error in HTTP data-in: %s",
				strerror(errno));
			return cli_err(cli, InternalError);
		}

		MD5_Update(&cli->out_md5, cli->req_ptr, bytes);

		cli->out_len -= bytes;
		p += bytes;
		avail -= bytes;
	}

	if (!cli->out_len)
		return object_put_end(cli);

	return (avail == sizeof(buf)) ? true : false;
}

bool object_put(struct client *cli, const char *user, const char *bucket,
		const char *key, long content_len, bool expect_cont)
{
	char *fn = NULL;
	long avail;

	if (!user || !has_access(user, bucket, NULL, "WRITE"))
		return cli_err(cli, AccessDenied);

	while (cli->out_fd < 0) {
		counter++;

		free(fn);

		if (asprintf(&fn, "%s/%016llX", tabled_srv.data_dir,
			     (unsigned long long) counter) < 0) {
			syslog(LOG_ERR, "OOM in object_put");
			return cli_err(cli, InternalError);
		}

		cli->out_fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
	}

	cli->out_fn = fn;
	cli->out_bucket = strdup(bucket);
	cli->out_key = strdup(key);
	MD5_Init(&cli->out_md5);
	cli->out_len = content_len;
	cli->out_counter = counter;
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
			bytes = write(cli->out_fd, cli->req_ptr, avail);
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

void cli_in_end(struct client *cli)
{
	if (!cli)
		return;

	if (cli->in_fd >= 0) {
		close(cli->in_fd);
		cli->in_fd = -1;
	}

	free(cli->in_fn);
	cli->in_fn = NULL;
}

static bool object_get_more(struct client *cli, struct client_write *wr,
			    bool done)
{
	char *buf;
	ssize_t bytes;

	/* free now-written buffer */
	free(wr->cb_data);

	buf = malloc(CLI_DATA_BUF_SZ);
	if (!buf)
		return false;

	/* do not queue more, if !completion or fd was closed early */
	if (!done || cli->in_fd < 0)
		goto err_out_buf;

	bytes = read(cli->in_fd, buf, MIN(cli->in_len, CLI_DATA_BUF_SZ));
	if (bytes < 0) {
		syslog(LOG_ERR, "read obj(%s) failed: %s", cli->in_fn,
			strerror(errno));
		goto err_out;
	}
	if (bytes == 0 && cli->in_len != 0)
		goto err_out;

	cli->in_len -= bytes;

	if (!cli->in_len)
		cli_in_end(cli);

	if (cli_writeq(cli, buf, bytes,
		       cli->in_len ? object_get_more : cli_cb_free, buf))
		goto err_out;

	return true;

err_out:
	cli_in_end(cli);
err_out_buf:
	free(buf);
	return false;
}

bool object_get(struct client *cli, const char *user, const char *bucket,
		       const char *key, bool want_body)
{
	const char *md5, *type, *name;
	char timestr[64], modstr[64], *hdr, *fn, *tmp;
	int rc;
	enum errcode err = InternalError;
	struct stat st;
	char buf[4096];
	ssize_t bytes;
	sqlite3_stmt *stmt, *hdr_stmt;
	bool access, modified = true;
	GString *extra_hdr;

	if (!sql_begin())
		return cli_err(cli, InternalError);

	if (user)
		access = has_access(user, bucket, key, "READ");
	else
		access = has_access("ANONYMOUS", bucket, key, "READ");
	if (!access) {
		err = AccessDenied;
		goto err_out_rb;
	}

	stmt = prep_stmts[st_object];
	sqlite3_bind_text(stmt, 1, bucket, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, key, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		err = NoSuchKey;
		goto err_out_reset;
	}

	md5 = (const char *) sqlite3_column_text(stmt, 2);
	name = (const char *) sqlite3_column_text(stmt, 3);
	type = (const char *) sqlite3_column_text(stmt, 5);

	hdr = req_hdr(&cli->req, "if-match");
	if (hdr && strcmp(md5, hdr)) {
		err = PreconditionFailed;
		goto err_out_reset;
	}

	extra_hdr = g_string_sized_new(1024);
	if (!extra_hdr)
		goto err_out_reset;

	hdr_stmt = prep_stmts[st_headers];
	sqlite3_bind_text(hdr_stmt, 1, bucket, -1, SQLITE_STATIC);
	sqlite3_bind_text(hdr_stmt, 2, key, -1, SQLITE_STATIC);

	while (1) {
		const char *dbhdr, *dbval;

		rc = sqlite3_step(hdr_stmt);
		if (rc != SQLITE_ROW)
			break;

		dbhdr = (const char *) sqlite3_column_text(hdr_stmt, 0);
		dbval = (const char *) sqlite3_column_text(hdr_stmt, 1);

		extra_hdr = g_string_append(extra_hdr, dbhdr);
		extra_hdr = g_string_append(extra_hdr, ": ");
		extra_hdr = g_string_append(extra_hdr, dbval);
		extra_hdr = g_string_append(extra_hdr, "\r\n");
	}

	sqlite3_reset(hdr_stmt);

	if (asprintf(&fn, "%s/%s", tabled_srv.data_dir, name) < 0)
		goto err_out_str;

	cli->in_fd = open(fn, O_RDONLY);
	if (cli->in_fd < 0) {
		free(fn);
		syslog(LOG_ERR, "open obj(%s) failed: %s", fn,
			strerror(errno));
		goto err_out_str;
	}

	cli->in_fn = fn;

	if (fstat(cli->in_fd, &st) < 0) {
		syslog(LOG_ERR, "fstat obj(%s) failed: %s", fn,
			strerror(errno));
		goto err_out_in_end;
	}

	hdr = req_hdr(&cli->req, "if-unmodified-since");
	if (hdr) {
		time_t t;

		t = str2time(hdr);
		if (!t) {
			err = InvalidArgument;
			goto err_out_in_end;
		}

		if (st.st_mtime > t) {
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

		if (st.st_mtime <= t) {
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
		     (unsigned long long) st.st_size,
		     md5,
		     time2str(timestr, time(NULL)),
		     time2str(modstr, st.st_mtime),
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

	cli->in_len = st.st_size;

	bytes = read(cli->in_fd, buf, MIN(st.st_size, sizeof(buf)));
	if (bytes < 0) {
		syslog(LOG_ERR, "read obj(%s) failed: %s", fn,
			strerror(errno));
		goto err_out_in_end;
	}
	if (bytes == 0 && cli->in_len != 0)
		goto err_out_in_end;

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
	g_string_free(extra_hdr, TRUE);
	sqlite3_reset(prep_stmts[st_object]);
	sql_commit();
	return cli_write_start(cli);

err_out_in_end:
	cli_in_end(cli);
err_out_str:
	g_string_free(extra_hdr, TRUE);
err_out_reset:
	sqlite3_reset(prep_stmts[st_object]);
err_out_rb:
	sql_rollback();
	return cli_err(cli, err);
}

