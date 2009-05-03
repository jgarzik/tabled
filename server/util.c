
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
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <glib.h>

#include "tabled.h"

#define OBJID_STEP   500

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

uint64_t objid_next(void)
{
	DB_ENV *dbenv = tdb.env;
	DB *oids = tdb.oids;
	DB_TXN *txn = NULL;
	DBT pkey, pval;
	int recno;
	uint64_t datum;		/* LE */
	uint64_t objcount;	/* Host order */
	int rc;

	recno = 1;

	objcount = ++tabled_srv.object_count;
	if (objcount % OBJID_STEP != 0)
		return objcount;

	datum = GUINT64_TO_LE(objcount);

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));
	pkey.data = &recno;
	pkey.size = sizeof(recno);
	pval.data = &datum;
	pval.size = sizeof(uint64_t);

	/* begin trans */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto err_out_begin;
	}

	/* write the counter */
	rc = oids->put(oids, txn, &pkey, &pval, 0);
	if (rc) {
		syslog(LOG_INFO, "objid_next DB put error %d", rc);
		goto err_out_put;
	}

	/* end trans */
	rc = txn->commit(txn, 0);
	if (rc)
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
	return objcount;

err_out_put:
	rc = txn->abort(txn);
	if (rc)
		syslog(LOG_INFO, "objid_new abort error %d", rc);
err_out_begin:
	return objcount;
}

/*
 * We could auto-init, but the explicit initialization makes aborts
 * more debuggable and less unexpected, as they happen before requests come.
 */
void objid_init(void)
{
	DB_ENV *dbenv = tdb.env;
	DB *oids = tdb.oids;
	DB_TXN *txn = NULL;
	DBT pkey, pval;
	int recno;
	uint64_t objcount;	/* Host order */
	int rc;

	recno = 1;

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));
	pkey.data = &recno;
	pkey.size = sizeof(recno);

	/* begin trans */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		exit(1);
	}

	/* read existing counter, if any */
	rc = oids->get(oids, txn, &pkey, &pval, DB_RMW);
	if (rc == DB_NOTFOUND) {
		objcount = 1;
	} else if (rc) {
		syslog(LOG_ERR, "objid_init get error %d", rc);
		exit(1);
	} else {
		if (pval.size != sizeof(uint64_t)) {
			syslog(LOG_ERR, "objid_init got size %d", pval.size);
			exit(1);
		}
		objcount = GUINT64_FROM_LE(*(uint64_t *)pval.data);
		if (debugging)
			syslog(LOG_INFO, "objid_init initial %llX",
			       (unsigned long long) objcount);
		objcount += OBJID_STEP;

		/*
		 * Commit new step block for two reasons:
		 *  - if we crash before next step commit
		 *  - better verify now that writing IDs works ok
		 */
		*(uint64_t *)pval.data = GUINT64_TO_LE(objcount);

		rc = oids->put(oids, txn, &pkey, &pval, 0);
		if (rc) {
			dbenv->err(dbenv, rc, "oids->put");
			rc = txn->abort(txn);
			if (rc)
				dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
			exit(1);
		}
	}

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		exit(1);	/* Quit before something unknown blows up. */
	}

	if (objcount & 0xff00000000000000) {
		syslog(LOG_ERR, "Dangerous objid %llX\n",
		       (unsigned long long) objcount);
		exit(1);
	}
	tabled_srv.object_count = objcount;
}

