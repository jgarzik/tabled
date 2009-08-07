
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
	TDB_PGSZ_OBJS		= 1024,	/* db4 objects database page size */
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

static int add_remote_sites(DB_ENV *dbenv, GList *remotes, int *nsites)
{
	int rc;
	struct db_remote *rp;
	GList *tmp;

	*nsites = 0;
	for (tmp = remotes; tmp; tmp = tmp->next) {
		rp = tmp->data;

		rc = dbenv->repmgr_add_remote_site(dbenv, rp->host, rp->port,
						   NULL, 0);
		if (rc) {
			dbenv->err(dbenv, rc,
				   "dbenv->add.remote.site host %s port %u",
				   rp->host, rp->port);
			return rc;
		}
		(*nsites)++;
	}

	return 0;
}

static void db4_event(DB_ENV *dbenv, u_int32_t event, void *event_info)
{
	struct tabledb *tdb = dbenv->app_private;

	switch (event) {
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
	     unsigned int env_flags, const char *errpfx, bool do_syslog,
	     GList *remotes, char *rep_host, unsigned short rep_port,
	     void (*cb)(enum db_event))
{
	int nsites;
	int rc;
	DB_ENV *dbenv;

	tdb->is_master = false;
	tdb->home = db_home;
	tdb->state_cb = cb;

	rc = db_env_create(&tdb->env, 0);
	if (rc) {
		if (do_syslog)
			syslog(LOG_WARNING, "tdb->env_create failed: %d", rc);
		else
			fprintf(stderr, "tdb->env_create failed: %d\n", rc);
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
		dbenv->err(dbenv, rc, "log_set_config");
		goto err_out;
	}

	if (db_password) {
		rc = dbenv->set_encrypt(dbenv, db_password, DB_ENCRYPT_AES);
		if (rc) {
			dbenv->err(dbenv, rc, "dbenv->set_encrypt");
			goto err_out;
		}
		tdb->keyed = true;
	}

	rc = dbenv->repmgr_set_local_site(dbenv, rep_host, rep_port, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "dbenv->set_local_site");
		goto err_out;
	}

	rc = dbenv->set_event_notify(dbenv, db4_event);
	if (rc) {
		dbenv->err(dbenv, rc, "dbenv->set_event_notify");
		goto err_out;
	}

	// rc = dbenv->rep_set_timeout(dbenv, DB_REP_LEASE_TIMEOUT, 17000000);
	// if (rc) {
	// 	dbenv->err(dbenv, rc, "dbenv->rep_set_timeout(LEASE)");
	// 	goto err_out;
	// }

	// Comment this out due to "nsites must be zero if leases configured"
	// rc = dbenv->rep_set_config(dbenv, DB_REP_CONF_LEASE, 1);
	// if (rc) {
	// 	dbenv->err(dbenv, rc, "dbenv->rep_set_config");
	// 	goto err_out;
	// }

	rc = dbenv->rep_set_priority(dbenv, 100);
	if (rc) {
		dbenv->err(dbenv, rc, "dbenv->rep_set_priority");
		goto err_out;
	}

	/* init DB transactional environment, stored in directory db_home */
	env_flags |= DB_INIT_LOG | DB_INIT_LOCK | DB_INIT_MPOOL;
	env_flags |= DB_INIT_TXN | DB_INIT_REP;
	rc = dbenv->open(dbenv, db_home, env_flags, S_IRUSR | S_IWUSR);
	if (rc) {
		dbenv->err(dbenv, rc, "dbenv->open");
		goto err_out;
	}

	rc = add_remote_sites(dbenv, remotes, &nsites);
	if (rc)
		goto err_out;

	// rc = dbenv->rep_set_nsites(dbenv, nsites + 1);
	// if (rc) {
	// 	dbenv->err(dbenv, rc, "dbenv->repmgr_set_nsites");
	// 	goto err_out;
	// }

	rc = dbenv->repmgr_start(dbenv, 2, DB_REP_ELECTION);
	if (rc) {
		dbenv->err(dbenv, rc, "dbenv->repmgr_start");
		goto err_out;
	}

	return 0;

err_out:
	dbenv->close(dbenv, 0);
	return rc;
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
