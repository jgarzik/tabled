
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
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <glib.h>

#include "tabled.h"

#define OBJID_STEP   500

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

void applogerr(const char *prefix)
{
	applog(LOG_ERR, "%s: %s", prefix, strerror(errno));
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
	int fd;
	struct flock lock;
	int err;

	/* build file data */
	sprintf(str, "%u\n", getpid());

	/* open non-exclusively (works on NFS v2) */
	fd = open(pid_fn, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		err = errno;
		applog(LOG_ERR, "Cannot open PID file %s: %s",
		       pid_fn, strerror(err));
		return -err;
	}

	/* lock */
	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	if (fcntl(fd, F_SETLK, &lock) != 0) {
		err = errno;
		if (err == EAGAIN) {
			applog(LOG_ERR, "PID file %s is already locked",
			       pid_fn);
		} else {
			applog(LOG_ERR, "Cannot lock PID file %s: %s",
			       pid_fn, strerror(err));
		}
		close(fd);
		return -err;
	}

	/* write file data */
	bytes = strlen(str);
	s = str;
	while (bytes > 0) {
		ssize_t rc = write(fd, s, bytes);
		if (rc < 0) {
			err = errno;
			applog(LOG_ERR, "PID number write failed: %s",
			       strerror(err));
			goto err_out;
		}

		bytes -= rc;
		s += rc;
	}

	/* make sure file data is written to disk */
	if (fsync(fd) < 0) {
		err = errno;
		applog(LOG_ERR, "PID file fsync failed: %s", strerror(err));
		goto err_out;
	}

	return fd;

err_out:
	unlink(pid_fn);
	close(fd);
	return -err;
}

int fsetflags(const char *prefix, int fd, int or_flags)
{
	int flags, old_flags, rc;

	/* get current flags */
	old_flags = fcntl(fd, F_GETFL);
	if (old_flags < 0) {
		applog(LOG_ERR, "%s F_GETFL: %s", prefix, strerror(errno));
		return -errno;
	}

	/* add or_flags */
	rc = 0;
	flags = old_flags | or_flags;

	/* set new flags */
	if (flags != old_flags)
		if (fcntl(fd, F_SETFL, flags) < 0) {
			applog(LOG_ERR, "%s F_SETFL: %s", prefix, strerror(errno));
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

uint64_t objid_next(uint64_t *obj_count, struct tabledb *tdbp)
{
	DB_ENV *dbenv = tdbp->env;
	DB *oids = tdbp->oids;
	DB_TXN *txn = NULL;
	DBT pkey, pval;
	int recno;
	uint64_t datum;		/* LE */
	uint64_t objcount;	/* Host order */
	int rc;

	recno = 1;

	objcount = ++(*obj_count);
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
		applog(LOG_INFO, "objid_next DB put error %d", rc);
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
		applog(LOG_INFO, "objid_new abort error %d", rc);
err_out_begin:
	return objcount;
}

/*
 * We could auto-init, but the explicit initialization makes aborts
 * more debuggable and less unexpected, as they happen before requests come.
 */
int objid_init(uint64_t *obj_count, struct tabledb *tdbp)
{
	DB_ENV *dbenv = tdbp->env;
	DB *oids = tdbp->oids;
	DB_TXN *txn = NULL;
	DBT pkey, pval;
	int recno;
	uint64_t cntbuf;	/* LE */
	uint64_t objcount;	/* Host order */
	int rc;

	recno = 1;

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = &recno;
	pkey.size = sizeof(recno);

	memset(&pval, 0, sizeof(pval));
	pval.data = &cntbuf;
	pval.size = sizeof(uint64_t);
	pval.ulen = sizeof(uint64_t);
	pval.flags = DB_DBT_USERMEM;

	/* begin trans */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		return -1;
	}

	/* read existing counter, if any */
	rc = oids->get(oids, txn, &pkey, &pval, DB_RMW);
	if (rc) {
		if (rc != DB_NOTFOUND) {
			applog(LOG_ERR, "objid_init get error %d", rc);
			txn->abort(txn);
			return -1;
		}
		objcount = 1;
	} else {
		if (pval.size != sizeof(uint64_t)) {
			applog(LOG_ERR, "objid_init got size %d", pval.size);
			txn->abort(txn);
			return -1;
		}

		objcount = GUINT64_FROM_LE(cntbuf);
		if (debugging)
			applog(LOG_INFO, "objid_init initial %llX",
			       (unsigned long long) objcount);
		objcount += OBJID_STEP;
	}

	/*
	 * Commit new step block for two reasons:
	 *  - if we crash before next step commit
	 *  - better verify now that writing IDs works ok
	 */
	cntbuf = GUINT64_TO_LE(objcount);

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = &recno;
	pkey.size = sizeof(recno);

	memset(&pval, 0, sizeof(pval));
	pval.data = &cntbuf;
	pval.size = sizeof(uint64_t);

	rc = oids->put(oids, txn, &pkey, &pval, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "oids->put");
		rc = txn->abort(txn);
		if (rc)
			dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
		return -1;
	}

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		exit(1);	/* Quit before something unknown blows up. */
	}

	if (objcount & 0xff00000000000000) {
		applog(LOG_ERR, "Dangerous objid %llX\n",
		       (unsigned long long) objcount);
		return -1;
	}
	*obj_count = objcount;
	return 0;
}

