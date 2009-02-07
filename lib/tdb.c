
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

#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <glib.h>
#include <tdb.h>

enum {
	TDB_PGSZ_PASSWD		= 1024,	/* db4 passwd database page size */
	TDB_PGSZ_BUCKETS	= 1024,	/* db4 buckets database page size */
	TDB_PGSZ_BUCKETS_IDX	= 1024,	/* db4 buckets_idx database page size */
	TDB_PGSZ_ACLS		= 1024,	/* db4 acls database page size */
};

static void db4syslog(const DB_ENV *dbenv, const char *errpfx, const char *msg)
{
	syslog(LOG_WARNING, "%s: %s", errpfx, msg);
}

static int buckets_owner_idx(DB *secondary, const DBT *pkey, const DBT *pdata,
			     DBT *key_out)
{
	const struct db_bucket_ent *ent = pdata->data;

	memset(key_out, 0, sizeof(*key_out));

	key_out->data = (void *) ent->owner;
	key_out->size = strlen(ent->owner) + 1;

	return 0;
}

static int open_db(DB_ENV *env, DB **db_out, const char *name,
		   unsigned int page_size, unsigned int flags)
{
	int rc;
	DB *db;

	rc = db_create(db_out, env, 0);
	if (rc) {
		env->err(env, rc, "db_create");
		return -EIO;
	}

	db = *db_out;

	rc = db->set_pagesize(db, page_size);
	if (rc) {
		db->err(db, rc, "db->set_pagesize");
		rc = -EIO;
		goto err_out;
	}

	/* fix everything as little endian */
	rc = db->set_lorder(db, 1234);
	if (rc) {
		db->err(db, rc, "db->set_lorder");
		rc = -EIO;
		goto err_out;
	}

	rc = db->open(db, NULL, name, NULL, DB_HASH,
		      DB_AUTO_COMMIT | flags, S_IRUSR | S_IWUSR);
	if (rc) {
		db->err(db, rc, "db->open");
		rc = -EIO;
		goto err_out;
	}

	return 0;

err_out:
	db->close(db, 0);
	return rc;
}

int tdb_open(struct tabledb *tdb, unsigned int env_flags, unsigned int flags,
	     const char *errpfx, bool do_syslog)
{
	const char *db_home, *db_password;
	int rc;
	DB_ENV *dbenv;

	/*
	 * open DB environment
	 */

	db_home = tdb->home;
	g_assert(db_home != NULL);

	/* this isn't a very secure way to handle passwords */
	db_password = tdb->key;

	rc = db_env_create(&tdb->env, 0);
	if (rc) {
		fprintf(stderr, "tdb->env_create failed: %d\n", rc);
		return rc;
	}

	dbenv = tdb->env;

	dbenv->set_errpfx(dbenv, errpfx);

	if (do_syslog)
		dbenv->set_errcall(dbenv, db4syslog);
	else
		dbenv->set_errfile(dbenv, stderr);

	if (db_password) {
		flags |= DB_ENCRYPT;
		rc = dbenv->set_encrypt(dbenv, db_password, DB_ENCRYPT_AES);
		if (rc) {
			dbenv->err(dbenv, rc, "dbenv->set_encrypt");
			goto err_out;
		}

		memset(tdb->key, 0, strlen(tdb->key));
		free(tdb->key);
		tdb->key = NULL;
	}

	/* init DB transactional environment, stored in directory db_home */
	rc = dbenv->open(dbenv, db_home,
			 env_flags |
			 DB_INIT_LOG | DB_INIT_LOCK | DB_INIT_MPOOL |
			 DB_INIT_TXN, S_IRUSR | S_IWUSR);
	if (rc) {
		if (dbenv)
			dbenv->err(dbenv, rc, "dbenv->open");
		else
			fprintf(stderr, "dbenv->open failed: %d\n", rc);
		goto err_out;
	}

	/*
	 * Open databases
	 */

	rc = open_db(dbenv, &tdb->passwd, "passwd", TDB_PGSZ_PASSWD, flags);
	if (rc)
		goto err_out;

	rc = open_db(dbenv, &tdb->buckets, "buckets", TDB_PGSZ_BUCKETS, flags);
	if (rc)
		goto err_out_passwd;

	rc = open_db(dbenv, &tdb->buckets_idx, "buckets_idx",
		     TDB_PGSZ_BUCKETS_IDX, flags | DB_DUP);
	if (rc)
		goto err_out_buckets;

	/* associate this secondary index with 'buckets' primary db */
	rc = tdb->buckets->associate(tdb->buckets, NULL, tdb->buckets_idx,
				     buckets_owner_idx, DB_CREATE);
	if (rc) {
		dbenv->err(dbenv, rc, "buckets->associate");
		goto err_out_bidx;
	}

	rc = open_db(dbenv, &tdb->acls, "acls", TDB_PGSZ_ACLS, flags | DB_DUP);
	if (rc)
		goto err_out_bidx;

	return 0;

err_out_bidx:
	tdb->buckets_idx->close(tdb->buckets_idx, 0);
err_out_buckets:
	tdb->buckets->close(tdb->buckets, 0);
err_out_passwd:
	tdb->passwd->close(tdb->passwd, 0);
err_out:
	dbenv->close(dbenv, 0);
	return rc;
}

void tdb_close(struct tabledb *tdb)
{
	tdb->acls->close(tdb->acls, 0);
	tdb->buckets_idx->close(tdb->buckets_idx, 0);
	tdb->buckets->close(tdb->buckets, 0);
	tdb->passwd->close(tdb->passwd, 0);
	tdb->env->close(tdb->env, 0);

	tdb->env = NULL;
	tdb->passwd = NULL;
	tdb->buckets = NULL;
	tdb->buckets_idx = NULL;
	tdb->acls = NULL;
}

