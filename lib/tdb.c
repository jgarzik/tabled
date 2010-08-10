
/*
 * Copyright 2008-2010 Red Hat, Inc.
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
	TDB_PGSZ_OBJS		= 1024,	/* db4 objects database page size */
};

static void db4syslog(const DB_ENV *dbenv, const char *errpfx, const char *msg)
{
	/*
	 * Since we use syslog, we discard the prefix set in tdb_init,
	 * because syslog adds our own prefix too. The errpfx would be
	 * useful if we weren't dumping to syslog here.
	 */
	syslog(LOG_WARNING, "%s", msg);
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
		   unsigned int page_size, DBTYPE dbtype, unsigned int flags,
		   int (*bt_compare)(DB *db, const DBT *dbt1, const DBT *dbt2),
		   int (*dup_compare)(DB *db, const DBT *dbt1, const DBT *dbt2),
		   unsigned int fset)
{
	int rc;
	DB *db;
	int retries = 5;

retry:
	rc = db_create(db_out, env, 0);
	if (rc) {
		env->err(env, rc, "db_create");
		return -EIO;
	}
	db = *db_out;

	if (page_size) {
		rc = db->set_pagesize(db, page_size);
		if (rc) {
			db->err(db, rc, "db->set_pagesize");
			goto err_out;
		}
	}

	/* fix everything as little endian */
	rc = db->set_lorder(db, 1234);
	if (rc) {
		db->err(db, rc, "db->set_lorder");
		goto err_out;
	}

	if (bt_compare) {
		rc = db->set_bt_compare(db, bt_compare);
		if (rc) {
			db->err(db, rc, "db->set_bt_compare");
			goto err_out;
		}
	}

	if (fset) {
		rc = db->set_flags(db, fset);
		if (rc) {
			db->err(db, rc, "db->set_flags");
			goto err_out;
		}
	}

	if (dup_compare) {
		rc = db->set_dup_compare(db, dup_compare);
		if (rc) {
			db->err(db, rc, "db->set_dup_compare");
			goto err_out;
		}
	}

	rc = db->open(db, NULL, name, NULL, dbtype,
		      DB_AUTO_COMMIT | flags, S_IRUSR | S_IWUSR);
	if (rc) {
		if (rc == ENOENT || rc == DB_REP_HANDLE_DEAD ||
		    rc == DB_LOCK_DEADLOCK) {
			if (!retries) {
				db->err(db, rc, "db->open retried");
				goto err_out;
			}

			rc = db->close(db, rc == ENOENT ? 0 : DB_NOSYNC);
			if (rc) {
				db->err(db, rc, "db->close");
				goto err_out;
			}

			retries--;
			sleep(2);
			goto retry;
		}

		db->err(db, rc, "db->open");
		goto err_out;
	}

	return 0;

err_out:
	db->close(db, 0);
	return -EIO;
}

static void db4_event(DB_ENV *dbenv, u_int32_t event, void *event_info)
{
	struct tabledb *tdb = dbenv->app_private;

	switch (event) {
	case DB_EVENT_PANIC:
		dbenv->errx(dbenv, "PANIC event is reported, exiting");
		exit(2);
		break;
	case DB_EVENT_REP_CLIENT:
		tdb->is_master = false;
		if (tdb->state_cb)
			(*tdb->state_cb)(TDB_EV_CLIENT);
		break;
	case DB_EVENT_REP_MASTER:
		tdb->is_master = true;
		if (tdb->state_cb)
			(*tdb->state_cb)(TDB_EV_MASTER);
		break;
	case DB_EVENT_REP_ELECTED:
		if (tdb->state_cb)
			(*tdb->state_cb)(TDB_EV_ELECTED);
		break;
	case DB_EVENT_REP_NEWMASTER:
		dbenv->errx(dbenv, "New master is reported: %d",
			    *(int *)event_info);
		/* XXX Need to verify that it's the same master as before. */
		break;
	case DB_EVENT_REP_STARTUPDONE:
		dbenv->errx(dbenv, "Client start-up complete");
		break;
	default:
		/* do nothing */
		break;
	}
}

/*
 * Initialize the DB environment and kick off the replication.
 * db_password, cb can be NULL
 */
int tdb_init(struct tabledb *tdb, const char *db_home, const char *db_password,
	     const char *errpfx, bool do_syslog, int rep_ourid,
	     int (*rep_send)(DB_ENV *dbenv, const DBT *ctl, const DBT *rec,
			     const DB_LSN *lsnp, int envid, uint32_t flags),
	     bool we_are_master,
	     void (*cb)(enum db_event))
{
	unsigned int env_flags;
	unsigned int rep_flags;
	int rc;
	DB_ENV *dbenv;

	tdb->is_master = we_are_master;
	tdb->home = db_home;
	tdb->state_cb = cb;

	rc = db_env_create(&tdb->env, 0);
	if (rc) {
		if (do_syslog)
			syslog(LOG_WARNING, "db_env_create failed: %d", rc);
		else
			fprintf(stderr, "db_env_create failed: %d\n", rc);
		return rc;
	}

	dbenv = tdb->env;
	dbenv->app_private = tdb;

	dbenv->set_errpfx(dbenv, errpfx);
	if (do_syslog)
		dbenv->set_errcall(dbenv, db4syslog);
	else
		dbenv->set_errfile(dbenv, stderr);

	/* enable automatic deadlock detection */
	rc = dbenv->set_lk_detect(dbenv, DB_LOCK_DEFAULT);
	if (rc) {
		dbenv->err(dbenv, rc, "set_lk_detect");
		goto err_out;
	}

	/* enable automatic removal of unused logs.  should be re-examined
	 * once this project is more mature, as this makes catastrophic
	 * recovery more difficult.
	 */
	rc = dbenv->log_set_config(dbenv, DB_LOG_AUTO_REMOVE, 1);
	if (rc) {
		dbenv->err(dbenv, rc, "log_set_config(AUTO_REMOVE)");
		goto err_out;
	}

	if (db_password) {
		rc = dbenv->set_encrypt(dbenv, db_password, DB_ENCRYPT_AES);
		if (rc) {
			dbenv->err(dbenv, rc, "set_encrypt");
			goto err_out;
		}
		tdb->keyed = true;
	}

	rc = dbenv->set_event_notify(dbenv, db4_event);
	if (rc) {
		dbenv->err(dbenv, rc, "set_event_notify");
		goto err_out;
	}

	// rc = dbenv->rep_set_timeout(dbenv, DB_REP_LEASE_TIMEOUT, 17000000);
	// if (rc) {
	// 	dbenv->err(dbenv, rc, "rep_set_timeout(LEASE)");
	// 	goto err_out;
	// }

	// Comment this out due to "nsites must be zero if leases configured"
	// rc = dbenv->rep_set_config(dbenv, DB_REP_CONF_LEASE, 1);
	// if (rc) {
	// 	dbenv->err(dbenv, rc, "rep_set_config(LEASE)");
	// 	goto err_out;
	// }

	if (rep_send) {
		rc = dbenv->rep_set_transport(dbenv, rep_ourid, rep_send);
		if (rc) {
			dbenv->err(dbenv, rc, "rep_set_transport");
			goto err_out;
		}

		// /*
		//  * Fix the derbies. This is the only way, since passing of
		//  * DB_REP_MASTER to rep_start() after a failover will end in:
		//  * "DB_REP_UNAVAIL: Unable to elect a master" (and a hang).
		//  */
		// rc = dbenv->rep_set_priority(dbenv, we_are_master ? 100 : 10);
		// if (rc) {
		// 	dbenv->err(dbenv, rc, "rep_set_priority");
		// 	goto err_out;
		// }

		env_flags = DB_RECOVER | DB_CREATE | DB_THREAD;
		env_flags |= DB_INIT_LOG | DB_INIT_LOCK | DB_INIT_MPOOL;
		env_flags |= DB_INIT_TXN | DB_INIT_REP;
		rc = dbenv->open(dbenv, db_home, env_flags, S_IRUSR | S_IWUSR);
		if (rc) {
			dbenv->err(dbenv, rc, "open rep");
			goto err_out;
		}

		rep_flags = we_are_master ? DB_REP_MASTER : DB_REP_CLIENT;
		rc = dbenv->rep_start(dbenv, NULL, rep_flags);
		if (rc) {
			dbenv->err(dbenv, rc, "rep_start");
			goto err_out;
		}

	} else {
		env_flags = DB_RECOVER | DB_CREATE | DB_THREAD;
		env_flags |= DB_INIT_LOG | DB_INIT_LOCK | DB_INIT_MPOOL;
		env_flags |= DB_INIT_TXN;
		rc = dbenv->open(dbenv, db_home, env_flags, S_IRUSR | S_IWUSR);
		if (rc) {
			dbenv->err(dbenv, rc, "open norep");
			goto err_out;
		}

		/* XXX rip this out from tdbadm.c */
		/*
		 * The db4 only delivers callbacks if replication was ordered.
		 * Since we force-set master, we ought to deliver them here
		 * for the universal code to work as if a master was elected.
		 */
		if (cb)
			(*cb)(we_are_master ? TDB_EV_MASTER : TDB_EV_CLIENT);
	}

	return 0;

err_out:
	dbenv->close(dbenv, 0);
	return -1;
}

/*
 * Open databases
 */
int tdb_up(struct tabledb *tdb, unsigned int flags)
{
	DB_ENV *dbenv = tdb->env;
	int rc;

	if (!tdb->is_master)
		flags &= ~DB_CREATE;
	if (tdb->keyed)
		flags |= DB_ENCRYPT;

	rc = open_db(dbenv, &tdb->passwd, "passwd", TDB_PGSZ_PASSWD,
		     DB_HASH, flags, NULL, NULL, 0);
	if (rc)
		goto err_out;

	rc = open_db(dbenv, &tdb->buckets, "buckets", TDB_PGSZ_BUCKETS,
		     DB_HASH, flags, NULL, NULL, 0);
	if (rc)
		goto err_out_passwd;

	rc = open_db(dbenv, &tdb->buckets_idx, "buckets_idx",
		     TDB_PGSZ_BUCKETS_IDX, DB_HASH, flags, NULL, NULL, DB_DUP);
	if (rc)
		goto err_out_buckets;

	/* associate this secondary index with 'buckets' primary db */
	rc = tdb->buckets->associate(tdb->buckets, NULL, tdb->buckets_idx,
				     buckets_owner_idx, DB_CREATE);
	if (rc) {
		dbenv->err(dbenv, rc, "buckets->associate");
		goto err_out_bidx;
	}

	rc = open_db(dbenv, &tdb->acls, "acls", TDB_PGSZ_ACLS,
		     DB_HASH, flags, NULL, NULL, DB_DUP);
	if (rc)
		goto err_out_bidx;

	rc = open_db(dbenv, &tdb->objs, "objs", TDB_PGSZ_OBJS,
		     DB_BTREE, flags, NULL, NULL, 0);
	if (rc)
		goto err_out_acls;

	rc = open_db(dbenv, &tdb->oids, "oids", 0, DB_RECNO, flags, NULL,
		     NULL, 0);
	if (rc)
		goto err_out_obj;

	return 0;

err_out_obj:
	tdb->objs->close(tdb->objs, 0);
err_out_acls:
	tdb->acls->close(tdb->acls, 0);
err_out_bidx:
	tdb->buckets_idx->close(tdb->buckets_idx, 0);
err_out_buckets:
	tdb->buckets->close(tdb->buckets, 0);
err_out_passwd:
	tdb->passwd->close(tdb->passwd, 0);
err_out:
	return rc;
}

/*
 * This only closes databases, but we don't want to call it "tdb_close"
 * for historic reasons. Mind, replication remains up after this returns.
 */
void tdb_down(struct tabledb *tdb)
{
	tdb->oids->close(tdb->oids, 0);
	tdb->objs->close(tdb->objs, 0);
	tdb->acls->close(tdb->acls, 0);
	tdb->buckets_idx->close(tdb->buckets_idx, 0);
	tdb->buckets->close(tdb->buckets, 0);
	tdb->passwd->close(tdb->passwd, 0);

	tdb->passwd = NULL;
	tdb->buckets = NULL;
	tdb->buckets_idx = NULL;
	tdb->acls = NULL;
	tdb->objs = NULL;
	tdb->oids = NULL;
}

void tdb_fini(struct tabledb *tdb)
{
	tdb->env->close(tdb->env, 0);
	tdb->env = NULL;
}

