
/*
 * Copyright 2009 Red Hat, Inc.
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
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <db.h>
#include <elist.h>
#include "tabled.h"

struct rep_arg {
	struct event_base *evbase;
};

/*
 * Replication Job
 */
struct rep_job {
	struct list_head jlink;
	struct rep_arg *arg;

	uint64_t oid;
	uint64_t size;		/* all of the object */
	time_t start_time;
	/* cannot look up by oid, keep key */
	size_t klen;
	struct db_obj_key *key;

	struct storage_node *src, *dst;
	struct open_chunk in_ce, out_ce;
	long in_len;		/* can MIN() take long long? */
	char *buf;
	char *bptr;		/* points into buf */
	ssize_t bcnt;		/* currently in buf */
};

struct rep_jobs {
	int njobs;
	struct list_head jlist;
};

static struct rep_jobs active = { 0, LIST_HEAD_INIT(active.jlist) };
static struct rep_jobs queue = { 0, LIST_HEAD_INIT(queue.jlist) };
static struct rep_jobs done = { 0, LIST_HEAD_INIT(done.jlist) };

/*
 * These should actually be thread-local, but we only have one thread.
 */
static struct event kscan_timer;	/* db4 key rescan timer */
static time_t kscan_last;
static bool kscan_running;
static unsigned long kscan_cnt;

/*
 * These are module-scope things: global locks and flags, thread list, etc.
 */
static bool kscan_enabled = false;
static GMutex *kscan_mutex;
static GThread *scan_thread;

static void job_dispatch(void);

/* should've called this job_alloc_and_fill actually */
static struct rep_job *job_alloc(size_t klen, struct db_obj_key *key)
{
	struct rep_job *job;
	size_t len;

	len = sizeof(struct rep_job) + klen;
	job = malloc(len);
	if (job) {
		memset(job, 0, sizeof(struct rep_job));
		memcpy(job+1, key, klen);
		job->klen = klen;
		job->key = (struct db_obj_key *)(job+1);
	}
	return job;
}

static void job_free(struct rep_job *job)
{
	if (job->src)
		stor_node_put(job->src);
	if (job->dst)
		stor_node_put(job->dst);
	free(job->buf);
	free(job);
}

/* N.B. the current calling convention is to wait for drain on the socket */
static void job_done(struct rep_job *job)
{
/* P3 */ applog(LOG_INFO, "job done oid %llX", (long long) job->oid);
	if (!stor_put_end(&job->out_ce)) {
		applog(LOG_ERR, "Chunk sync failed on nid %u", job->dst->id);
	}
	stor_close(&job->out_ce);
	stor_close(&job->in_ce);

	list_del(&job->jlink);
	--active.njobs;

	list_add(&job->jlink, &done.jlist);
	done.njobs++;
}

static void job_abend(struct rep_job *job)
{
/* P3 */ applog(LOG_INFO, "job abend from %u to %u oid %llX",
  job->src->id, job->dst->id, (long long) job->oid);
	stor_abort(&job->out_ce);
	stor_close(&job->out_ce);
	stor_close(&job->in_ce);

	list_del(&job->jlink);
	--active.njobs;
	job_free(job);
}

static int job_submit_buf(struct rep_job *job, char *buf, ssize_t len)
{
	ssize_t bytes;

	job->bptr = buf;
	job->bcnt = len;

	bytes = stor_put_buf(&job->out_ce, job->bptr, job->bcnt);
	if (bytes < 0) {
		job->bcnt = 0;
		if (debugging)
			applog(LOG_DEBUG, "stor_put_buf failed (%d)", bytes);
		return bytes;
	}
	job->bptr += bytes;
	job->bcnt -= bytes;
	return 0;
}

static void job_get_poke(struct rep_job *job)
{
	ssize_t bytes;

	for (;;) {
		if (job->bcnt != 0)
			break;
		if (!job->in_len)
			break;
		bytes = stor_get_buf(&job->in_ce, job->buf,
				     MIN(job->in_len, CLI_DATA_BUF_SZ));
		if (bytes < 0) {
			applog(LOG_ERR, "read failed oid %llX at nid %u",
			       (unsigned long long) job->oid, job->src->id);
			goto err_out;
		}
		if (bytes == 0)
			break;
		if (job_submit_buf(job, job->buf, bytes))
			goto err_out;
		job->in_len -= bytes;
	}

	if (job->bcnt == 0 && job->in_len == 0) {
		job_done(job);
		return;
	}

	/*
	 * Since storage events automatically arm and disarm themselves,
	 * we can just return to the main loop without a fear of looping.
	 */
	return;

err_out:
	job_abend(job);
	return;
}

static void job_get_event(struct open_chunk *stp)
{
	job_get_poke(stp->cli);

	job_dispatch();
}

static void job_put_poke(struct rep_job *job)
{
	ssize_t bytes;

	bytes = stor_put_buf(&job->out_ce, job->bptr, job->bcnt);
	if (bytes < 0) {
		job->bcnt = 0;
		applog(LOG_ERR, "write failed oid %llX at nid %u",
		       (unsigned long long) job->oid, job->src->id);
		job_abend(job);
		return;
	}
	job->bptr += bytes;
	job->bcnt -= bytes;

	if (!job->bcnt)
		job_get_poke(job);
}

static void job_put_event(struct open_chunk *stp)
{
	struct rep_job *job = stp->cli;

	if (job->bcnt) {
		job_put_poke(job);
	} else {
		job_get_poke(job);
	}

	job_dispatch();
}

/* well, not much scheduling for now, just throw to the tail of the queue. */
static int job_schedule(struct rep_job *job)
{

	job->start_time = time(NULL);

	/* P3 */ applog(LOG_INFO, "job oid %llX start %lu from %u to %u",
	    job->oid, (long)job->start_time, job->src->id, job->dst->id);

	list_add(&job->jlink, &queue.jlist);
	queue.njobs++;
	return 0;
}

/* FIXME needs to loop while active.njobs < max or something */
static void job_dispatch()
{
	struct rep_job *job;
	uint64_t objsize;	/* As reported by Chunk. Not used. */
	int rc;

	if (active.njobs >= 2)	/* FIXME: Bogus. Need to know current loads. */
		return;

	if (list_empty(&queue.jlist))
		return;
	job = list_entry(queue.jlist.next, struct rep_job, jlink);
	list_del(&job->jlink);
	--queue.njobs;

	job->buf = malloc(CLI_DATA_BUF_SZ);
	if (!job->buf)
		goto err_malloc;

	rc = stor_open(&job->in_ce, job->src, job->arg->evbase);
	if (rc) {
		applog(LOG_WARNING, "Cannot open input chunk, nid %u (%d)",
		       job->src->id, rc);
		goto err_inopen;
	}
	job->in_ce.cli = job;

	rc = stor_open(&job->out_ce, job->dst, job->arg->evbase);
	if (rc) {
		applog(LOG_WARNING, "Cannot open output chunk, nid %u (%d)",
		       job->dst->id, rc);
		goto err_outopen;
	}
	job->out_ce.cli = job;

	rc = stor_open_read(&job->in_ce, job_get_event, job->oid, &objsize);
	if (rc) {
		applog(LOG_ERR, "Cannot start nid %u for oid %llX (%d)",
		       job->src->id, (unsigned long long) job->oid, rc);
		goto err_read;
	}
	job->in_len = job->size;

	rc = stor_put_start(&job->out_ce, job_put_event, job->oid, job->size);
	if (rc) {
		applog(LOG_ERR, "Cannot start putting, nid %u (%d)",
		       job->dst->id, rc);
		goto err_put;
	}

	list_add(&job->jlink, &active.jlist);
	active.njobs++;

	job_get_poke(job);	/* required to start */

	return;

err_put:
err_read:
	stor_close(&job->out_ce);
err_outopen:
	stor_close(&job->in_ce);
err_inopen:
	/* no free(buf) since job_free does it */
err_malloc:
	job_free(job);
	return;
}

static struct storage_node *job_select_src(int nnum,
					   struct storage_node *nvec[])
{
	if (nnum == 0)
		return NULL;
	return stor_node_get(nvec[rand() % nnum]);
}

/* FIXME Need to select by capacity and load. Ditto in initial selection. */
static struct storage_node *job_select_dst(int nnum,
					   struct storage_node *nvec[])
{
	enum { NRAND = 20 };
	struct storage_node *tmp[NRAND];
	int n, i;
	struct storage_node *stn;
	time_t t1;

	g_mutex_lock(tabled_srv.bigmutex);
	t1 = time(NULL);
	n = 0;
	list_for_each_entry(stn, &tabled_srv.all_stor, all_link) {
		if (!stn->up)
			continue;
		if (t1 > stn->last_up + CHUNK_REBOOT_TIME)
			continue;

		/* de-dup with source */
		for (i = 0; i < nnum; i++) {
			if (nvec[i] == stn)
				break;
		}
		if (i < nnum)
			continue;

		tmp[n] = stn;
		n++;
	}
	if (n == 0) {
		g_mutex_unlock(tabled_srv.bigmutex);
		return NULL;
	}
	stn = stor_node_get(tmp[rand() % n]);
	g_mutex_unlock(tabled_srv.bigmutex);
	return stn;
}

static struct rep_job *job_find_by_oid(uint64_t oid)
{
	struct rep_job *pos;

	list_for_each_entry(pos, &queue.jlist, jlink) {
		if (pos->oid == oid)
			return pos;
	}
	list_for_each_entry(pos, &active.jlist, jlink) {
		if (pos->oid == oid)
			return pos;
	}
	return NULL;
}

/* start replicating the key somewhere */
static void rep_job_start(struct rep_arg *arg,
			  size_t klen, struct db_obj_key *key,
			  uint64_t oid, uint64_t objsize,
			  int nnum, struct storage_node *nvec[])
{
	struct rep_job *job;

	if (objsize == 0) {
		static int cnt = 10;
		if (cnt > 0) {	/* internal error; if it ever hits, it floods */
			--cnt;
			applog(LOG_ERR, "Submitting oid %llX with zero size",
			       (long long) oid);
		}
		return;
	}
	if (job_find_by_oid(oid) != NULL)
		return;
	job = job_alloc(klen, key);
	if (!job)
		goto err_alloc;
	job->arg = arg;
	job->oid = oid;
	job->size = objsize;
	job->src = job_select_src(nnum, nvec);
	if (!job->src)
		goto err_src;
	job->dst = job_select_dst(nnum, nvec);
	if (!job->dst)
		goto err_dst;
	if (job->src->id == job->dst->id) {
		/* Is this bad enough to invoke exit(1) right here? */
		applog(LOG_ERR, "Internal error, copy from/to nid %u",
		       job->src->id);
		return;
	}
	if (job_schedule(job) != 0)
		goto err_sched;
	job_dispatch();
	return;

err_sched:
err_dst:
err_src:
	job_free(job);
err_alloc:
	return;
}

/*
 * rep_scan() and friends
 * Read the whole db of keys, replicate those below redundancy.
 */

struct cursor {		/* our own "soft" cursor, works across transactions */
	size_t klen;	/* zero possible, means no key */
	struct db_obj_key *key;
	DB_ENV *db_env;
	DB     *db_objs;
	DB_TXN *db_txn;
	DBC    *db_cur;
};

static int rep_scan_open(struct cursor *cp)
{
	int rc;

	rc = cp->db_env->txn_begin(cp->db_env, NULL, &cp->db_txn, 0);
	if (rc) {
		cp->db_env->err(cp->db_env, rc, "DB_ENV->txn_begin");
		goto err_none;
	}

	// DB_WRITECURSOR ?  DB_BULK ?
	rc = cp->db_objs->cursor(cp->db_objs, cp->db_txn, &cp->db_cur, 0);
	if (rc) {
		cp->db_objs->err(cp->db_objs, rc, "objs->cursor");
		goto err_out;
	}

	return 0;

err_out:
	rc = cp->db_txn->abort(cp->db_txn);
	if (rc)
		cp->db_env->err(cp->db_env, rc, "DB_ENV->txn_abort");
err_none:
	return -1;
}

static void rep_scan_close(struct cursor *cp)
{
	int rc;

	rc = cp->db_cur->close(cp->db_cur);
	if (rc) {
		cp->db_objs->err(cp->db_objs, rc, "objs->cursor close");
		goto err_out;
	}
	cp->db_cur = NULL;

	rc = cp->db_txn->commit(cp->db_txn, 0);
	if (rc)
		cp->db_env->err(cp->db_env, rc, "DB_ENV->txn_commit");
	cp->db_txn = NULL;
	return;

err_out:
	rc = cp->db_txn->abort(cp->db_txn);
	if (rc)
		cp->db_env->err(cp->db_env, rc, "DB_ENV->txn_abort");
	return;
}

/* get next */
static int rep_scan_get(struct cursor *cp, struct db_obj_ent **pobj)
{
	unsigned int get_flags;
	DBT pkey, pval;
	int rc;

	if (cp->db_cur) {
		get_flags = DB_NEXT;
	} else {
		if (rep_scan_open(cp) != 0)
			return -1;
		get_flags = DB_SET_RANGE;
	}

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = cp->key;
	pkey.size = cp->klen;

	memset(&pval, 0, sizeof(pval));
	pval.flags = DB_DBT_MALLOC;

	rc = cp->db_cur->get(cp->db_cur, &pkey, &pval, get_flags);
	if (rc) {
		if (rc != DB_NOTFOUND)
			cp->db_objs->err(cp->db_objs, rc, "cur->get for keys");
		return -1;
	}

	*pobj = pval.data;
	return 0;
}

/* parse object into cursor state */
static int rep_scan_parse(struct cursor *cp, struct db_obj_ent *obj)
{
	unsigned int obj_koff, obj_klen;
	struct db_obj_key *okey;

	obj_klen = GUINT16_FROM_LE(*(uint16_t *)(obj+1));
	if (obj_klen >= 64*1024) {	/* byteswapped or corrupt */
		applog(LOG_ERR, "bad key length %d", obj_klen);
		return -1;
	}
	obj_koff = obj->n_str * sizeof(uint16_t);

	okey = malloc(64 + obj_klen);

	memcpy(okey->bucket, obj->bucket, 64);
	memcpy(okey->key, (char *)(obj+1) + obj_koff, obj_klen);

	free(cp->key);
	cp->key = okey;
	cp->klen = 64 + obj_klen;
	return 0;
}

/* meat of scan - check if replication is need on the key */
static void rep_scan_verify(struct rep_arg *arg,
			    struct cursor *cp, struct db_obj_ent *obj)
{
	char bucket_name[65];
	char object_name[1025];
	uint64_t oid;
	int i;
	struct storage_node *redvec[MAXWAY];
	int allcnt, redcnt;
	uint32_t nid;
	struct storage_node *stn;
	time_t t1;

	memcpy(bucket_name, cp->key->bucket, 64);
	bucket_name[64] = 0;
	memcpy(object_name, cp->key->key, cp->klen - 64);
	object_name[cp->klen - 64] = 0;

	t1 = time(NULL);

	allcnt = 0;
	redcnt = 0;
	for (i = 0; i < MAXWAY; i++) {
		nid = GUINT32_FROM_LE(obj->d.a.nidv[i]);
		if (!nid)
			continue;
		stn = stor_node_by_nid(nid);
		if (!stn)
			continue;
		allcnt++;
		if (!stn->up) {
			stor_node_put(stn);
			continue;
		}
		if (t1 > stn->last_up + CHUNK_REBOOT_TIME) {
			stor_node_put(stn);
			continue;
		}
		/*
		 * This is where we later ask chunks for checksums (TODO).
		 */

		redvec[redcnt] = stn;
		redcnt++;
	}

	oid = GUINT64_FROM_LE(obj->d.a.oid);

	applog(LOG_INFO, "bucket %s key %s oid %llX n(%u,%u,%u): all %d ok %d",
	       bucket_name, object_name, (long long) oid,
	       GUINT32_FROM_LE(obj->d.a.nidv[0]),
	       GUINT32_FROM_LE(obj->d.a.nidv[1]),
	       GUINT32_FROM_LE(obj->d.a.nidv[2]),
	       allcnt, redcnt);

	if (redcnt < MAXWAY) {		/* maybe have MINWAY too? */
		rep_job_start(arg, cp->klen, cp->key, oid,
			      GUINT64_FROM_LE(obj->size), redcnt, redvec);
	}

	for (i = 0; i < redcnt; i++)
		stor_node_put(redvec[i]);
}

static void rep_add_nid(unsigned int klen, struct db_obj_key *key, uint32_t nid)
{
	DB_ENV *db_env = tdb.env;
	DB *db_objs = tdb.objs;
	DB_TXN *db_txn;
	DBT pkey, pval;
	struct db_obj_ent *obj;
	ssize_t oelen;
	unsigned empty;
	uint32_t n;
	int i;
	int rc;

	rc = db_env->txn_begin(db_env, NULL, &db_txn, 0);
	if (rc) {
		db_env->err(db_env, rc, "DB_ENV->txn_begin");
		goto err_none;
	}

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = key;
	pkey.size = klen;

	memset(&pval, 0, sizeof(pval));
	pval.flags = DB_DBT_MALLOC;

	rc = db_objs->get(db_objs, db_txn, &pkey, &pval, DB_RMW);
	if (rc) {
		db_env->err(db_env, rc, "objs->get");
		goto err_get;
	}

	obj = pval.data;
	oelen = pval.size;

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = key;
	pkey.size = klen;

	rc = db_objs->del(db_objs, db_txn, &pkey, 0);
	if (rc) {
		db_objs->err(db_objs, rc, "objs->del");
		goto err_del;
	}

	empty = 0;
	for (i = 0; i < MAXWAY; i++) {
		n = GUINT32_FROM_LE(obj->d.a.nidv[i]);
		if (n && n == nid) {
			applog(LOG_WARNING,
			       "object %llX already has nid %u",
			       (long long) GUINT64_FROM_LE(obj->d.a.oid), nid);
			goto err_check;
		}
		if (!n)
			empty++;
	}
	if (!empty) {
		applog(LOG_WARNING,
		      "object %llX already fully redundant, dropping nid %u",
		       (long long) GUINT64_FROM_LE(obj->d.a.oid), nid);
		goto err_check;
	}

	for (i = 0; i < MAXWAY; i++) {
		if (!obj->d.a.nidv[i]) {
			obj->d.a.nidv[i] = GUINT32_TO_LE(nid);
			break;
		}
	}

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = key;
	pkey.size = klen;

	memset(&pval, 0, sizeof(pval));
	pval.data = obj;
	pval.size = oelen;

	rc = db_objs->put(db_objs, db_txn, &pkey, &pval, 0);
	if (rc) {
		db_env->err(db_env, rc, "objs->put");
		goto err_put;
	}

	free(obj);

	rc = db_txn->commit(db_txn, 0);
	if (rc) {
		db_env->err(db_env, rc, "DB_ENV->txn_commit");
	}
	return;

err_put:
err_check:
err_del:
	free(obj);
err_get:
	rc = db_txn->abort(db_txn);
	if (rc)
		db_env->err(db_env, rc, "DB_ENV->txn_abort");
err_none:
	return;
}

static void rep_retire(void)
{
	struct rep_job *job;

	while (!list_empty(&done.jlist)) {
		job = list_entry(done.jlist.next, struct rep_job, jlink);
		list_del(&job->jlink);
		--done.njobs;

		rep_add_nid(job->klen, job->key, job->dst->id);
		job_free(job);
	}
}

static void rep_scan(struct rep_arg *arg)
{
	struct cursor cur;
	struct db_obj_ent *obj;
	unsigned long kcnt;
	time_t start_time, t;

	rep_retire();
	job_dispatch();

	start_time = time(NULL);
	if (debugging)
		applog(LOG_DEBUG, "key scan start time %lu", (long)start_time);
	g_mutex_lock(kscan_mutex);
	kscan_running = 1;
	kscan_last = start_time;
	kscan_cnt = 0;
	g_mutex_unlock(kscan_mutex);

	memset(&cur, 0, sizeof(struct cursor));	/* enough to construct */
	cur.db_env = tdb.env;
	cur.db_objs = tdb.objs;

	kcnt = 0;
	for (;;) {
		/* FIXME: need to limit queing by some sane number like number of stn */
		if (queue.njobs >= 100) {
			/* P3 */ applog(LOG_INFO, "overload %u", queue.njobs);
			goto out;
		}
		if ((t = time(NULL)) >= start_time + 2) {
			if (debugging)
				applog(LOG_DEBUG,
				       "db release at keys %lu seconds %lu",
				       kcnt, (long)t);
			rep_scan_close(&cur);
		}

		if (rep_scan_get(&cur, &obj) != 0)
			break;

		/* not needed for db4 with DB_NEXT, but eases our logic */
		if (rep_scan_parse(&cur, obj) != 0) {
			free(obj);
			continue;
		}

		if (!GUINT32_FROM_LE(obj->flags) & DB_OBJ_INLINE)
			rep_scan_verify(arg, &cur, obj);

		free(obj);
		kcnt++;
	}

	rep_scan_close(&cur);
	free(cur.key);
	cur.key = NULL;

	if (debugging)
		applog(LOG_DEBUG, "key scan done keys %lu", kcnt);

out:
	g_mutex_lock(kscan_mutex);
	kscan_running = 0;
	kscan_cnt = kcnt;
	g_mutex_unlock(kscan_mutex);
	return;
}

static void add_kscan_timer(void)
{
	static const struct timeval tv = { TABLED_RESCAN_SEC, 0 };

	if (evtimer_add(&kscan_timer, &tv) < 0)
		applog(LOG_WARNING, "unable to add key scan timer");
}

static void tdb_keyscan(int fd, short events, void *userdata)
{
	struct rep_arg *arg = userdata;

	if (kscan_enabled)
		rep_scan(arg);
	add_kscan_timer();
}

static gpointer rep_thread_func(gpointer data)
{
	struct rep_arg *arg = data;
	int rc;

	evtimer_set(&kscan_timer, tdb_keyscan, arg);
	event_base_set(arg->evbase, &kscan_timer);

	/*
	 * We must add an event now, or else event_base_dispatch will
	 * exit right away with code 1.
	 */
	add_kscan_timer();

	for (;;) {
		rc = event_base_dispatch(arg->evbase);
		applog(LOG_ERR, "rep event_base_dispatch exits (%d)", rc);
		sleep(300);	/* Should not happen, so maybe exit(1)? */
	}
	return NULL;
}

void rep_init(struct event_base *ev_base)
{
	GError *error;
	struct rep_arg *arg;

	kscan_mutex = g_mutex_new();

	arg = malloc(sizeof(struct rep_arg));
	if (!arg) {
		applog(LOG_ERR, "No core");
		exit(1);
	}
	arg->evbase = ev_base;

	scan_thread = g_thread_create(rep_thread_func, arg, FALSE, &error);
	if (scan_thread == NULL) {
		applog(LOG_ERR, "Failed to start replication thread: %s",
		       error->message);
		exit(1);
	}
}

void rep_start()
{
	kscan_enabled = true;
}

void rep_stats()
{
	bool running;
	unsigned long kcnt;
	time_t last;

	applog(LOG_INFO, "REP: Jobs: queued %d active %d done %d",
	       queue.njobs, active.njobs, done.njobs);

	g_mutex_lock(kscan_mutex);
	running = kscan_running;
	last = kscan_last;
	kcnt = kscan_cnt;
	g_mutex_unlock(kscan_mutex);

	if (running) {
		applog(LOG_INFO, "REP: run Active started %lu scanned %lu",
		      (long) last, kcnt);
	} else {
		if (last)
			applog(LOG_INFO,
			       "REP: run Done started %lu scanned %lu",
			       (long) last, kcnt);
		else
			applog(LOG_INFO, "REP: run None");
	}
}

bool rep_status(struct client *cli, GList *content)
{
	time_t now;
	char *str;
	bool running;
	unsigned long kcnt;
	time_t last;

	now = time(NULL);

	if (asprintf(&str,
		     "<h2>Data replication</h2>\r\n"
		     "<p>Jobs: queued %d active %d done %d</p>\r\n",
		     queue.njobs, active.njobs, done.njobs) < 0)
		return false;
	content = g_list_append(content, str);

	g_mutex_lock(kscan_mutex);
	running = kscan_running;
	last = kscan_last;
	kcnt = kscan_cnt;
	g_mutex_unlock(kscan_mutex);

	if (running) {
		if (asprintf(&str,
			     "<p>Run started at %lu (%ld back),"
			     " previous keys scanned %lu</p>\r\n",
			     (long) last, (long) (now - last),
			     kcnt) < 0)
			return false;
	} else {
		if (last) {
			if (asprintf(&str,
				     "<p>Last run at %lu (%ld back),"
				     " keys scanned %lu</p>\r\n",
				     (long) last, (long) (now - last),
				     kcnt) < 0)
				return false;
		} else {
			if (asprintf(&str,
				     "<p>No run data</p>\r\n") < 0)
				return false;
		}
	}
	content = g_list_append(content, str);

	return true;
}
