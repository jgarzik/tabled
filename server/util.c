
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <glib.h>
#include <sqlite3.h>

#include "tabled.h"

static const char *sql_stmt_text[] = {
	[st_begin] =
	"begin transaction",

	[st_commit] =
	"commit transaction",

	[st_rollback] =
	"rollback transaction",

	[st_service_list] =
	"select name, time_create from buckets where owner = ?",

	[st_add_bucket] =
	"insert into buckets values (?, ?, ?)",

	[st_del_bucket] =
	"delete from buckets where name = ?",

	[st_del_bucket_acl] =
	"delete from acls where bucket = ?",

	[st_add_acl] =
	"insert into acls values (?, ?, ?, ?)",

	[st_bucket] =
	"select * from buckets where name = ?",

	[st_bucket_objects] =
	"select * from objects where bucket = ?",

	[st_add_obj] =
	"insert into objects values (?, ?, ?, ?, ?)",

	[st_del_obj] =
	"delete from objects where bucket = ? and key = ?",

	[st_del_obj_acl] =
	"delete from acls where bucket = ? and key = ?",

	[st_object] =
	"select * from objects where bucket = ? and key = ?",

	[st_acl_bucket] =
	"select perm from acls where grantee = ? and bucket = ? and key isnull",

	[st_acl_object] =
	"select perm from acls where grantee = ? and bucket = ? and key = ?",

	[st_add_header] =
	"insert into headers values (?, ?, ?, ?)",

	[st_del_headers] =
	"delete from headers where bucket = ? and key = ?",

	[st_headers] =
	"select header, header_val from headers where bucket = ? and key = ?",
};

sqlite3_stmt *prep_stmts[st_last + 1] = { NULL, };
sqlite3 *sqldb = NULL;
struct tabledb tdb;

size_t strlist_len(GList *l)
{
	GList *tmp = l;
	size_t sum = 0;

	while (tmp) {
		sum += strlen(tmp->data);
		tmp = tmp->next;
	}

	return sum;
}

void __strlist_free(GList *l)
{
	GList *tmp = l;

	while (tmp) {
		free(tmp->data);
		tmp->data = NULL;
		tmp = tmp->next;
	}
}

void strlist_free(GList *l)
{
	__strlist_free(l);
	g_list_free(l);
}

void syslogerr(const char *prefix)
{
	syslog(LOG_ERR, "%s: %s", prefix, strerror(errno));
}

void strup(char *s)
{
	while (*s) {
		*s = toupper(*s);
		s++;
	}
}

int write_pid_file(const char *pid_fn)
{
	char str[32], *s;
	size_t bytes;

	/* build file data */
	sprintf(str, "%u\n", getpid());
	s = str;
	bytes = strlen(s);

	/* exclusive open */
	int fd = open(pid_fn, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		syslogerr(pid_fn);
		return -errno;
	}

	/* write file data */
	while (bytes > 0) {
		ssize_t rc = write(fd, s, bytes);
		if (rc < 0) {
			syslogerr("pid data write failed");
			goto err_out;
		}

		bytes -= rc;
		s += rc;
	}

	/* make sure file data is written to disk */
	if ((fsync(fd) < 0) || (close(fd) < 0)) {
		syslogerr("pid file sync/close failed");
		goto err_out;
	}

	return 0;

err_out:
	close(fd);
	unlink(pid_fn);
	return -errno;
}

int fsetflags(const char *prefix, int fd, int or_flags)
{
	int flags, old_flags, rc;

	/* get current flags */
	old_flags = fcntl(fd, F_GETFL);
	if (old_flags < 0) {
		syslog(LOG_ERR, "%s F_GETFL: %s", prefix, strerror(errno));
		return -errno;
	}

	/* add or_flags */
	rc = 0;
	flags = old_flags | or_flags;

	/* set new flags */
	if (flags != old_flags)
		if (fcntl(fd, F_SETFL, flags) < 0) {
			syslog(LOG_ERR, "%s F_SETFL: %s", prefix, strerror(errno));
			rc = -errno;
		}

	return rc;
}

void md5str(const unsigned char *digest, char *outstr)
{
	static const char hex[] = "0123456789abcdef";
	int i;

	for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
		outstr[i * 2]       = hex[(digest[i] & 0xF0) >> 4];
		outstr[(i * 2) + 1] = hex[(digest[i] & 0x0F)     ];
	}

	outstr[MD5_DIGEST_LENGTH * 2] = 0;
}

bool sql_begin(void)
{
	int rc = sqlite3_step(prep_stmts[st_begin]);
	sqlite3_reset(prep_stmts[st_begin]);
	return (rc == SQLITE_DONE);
}

bool sql_commit(void)
{
	int rc = sqlite3_step(prep_stmts[st_commit]);
	sqlite3_reset(prep_stmts[st_commit]);
	return (rc == SQLITE_DONE);
}

bool sql_rollback(void)
{
	int rc = sqlite3_step(prep_stmts[st_rollback]);
	sqlite3_reset(prep_stmts[st_rollback]);
	return (rc == SQLITE_DONE);
}

void sql_init(void)
{
	char db_fn[PATH_MAX + 1];
	unsigned int i;
	int rc;

	sprintf(db_fn, "%s/master.db", tabled_srv.data_dir);

	rc = sqlite3_open(db_fn, &sqldb);
	if (rc != SQLITE_OK) {
		syslog(LOG_ERR, "sqlite3_open failed");
		exit(1);
	}

	for (i = 0; i <= st_last; i++) {
		const char *dummy;

		rc = sqlite3_prepare_v2(sqldb, sql_stmt_text[i], -1,
					&prep_stmts[i], &dummy);
		g_assert(rc == SQLITE_OK);
	}
}

void sql_done(void)
{
	sqlite3_close(sqldb);
}

void tdb_init(void)
{
	memset(&tdb, 0, sizeof(tdb));

	tdb.home = tabled_srv.tdb_dir;

	if (tdb_open(&tdb, DB_RECOVER | DB_CREATE, DB_CREATE,
		     "tabled", true))
		exit(1);
}

void tdb_done(void)
{
	tdb_close(&tdb);
}

