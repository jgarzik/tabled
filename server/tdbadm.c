
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

#include "tabled-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <argp.h>
#include <glib.h>

#include <tdb.h>

enum various_modes {
	mode_user		= 1,
	mode_user_list,
	mode_bucket_list,
	mode_acl_list,
	mode_obj_list,
	mode_all_lists,
};

static int mode_adm;
static struct tabledb tdb;
static unsigned long invalid_lines;
static char *tdb_dir;

const char *argp_program_version = PACKAGE_VERSION;

static struct argp_option options[] = {
	{ "users", 'u', NULL, 0,
	  "User list input (from stdin, to database)" },
	{ "list-all", 'a', NULL, 0,
	  "Output all lists (from database, to stdout)" },
	{ "list-acls", 'A', NULL, 0,
	  "ACL list output (from database, to stdout)" },
	{ "list-buckets", 'B', NULL, 0,
	  "Bucket list output (from database, to stdout)" },
	{ "list-objects", 'O', NULL, 0,
	  "Object list output (from database, to stdout)" },
	{ "list-users", 'U', NULL, 0,
	  "User list output (from database, to stdout)" },
	{ "tdb", 't', "DIRECTORY", 0,
	  "Store TDB database environment in DIRECTORY" },
	{ }
};

static const char doc[] =
"tdbadm - TDB administration";


static error_t parse_opt (int key, char *arg, struct argp_state *state);


static const struct argp argp = { options, parse_opt, NULL, doc };


static void die(const char *msg)
{
	fprintf(stderr, "%s", msg);
	exit(1);
}

static void push_upw(DB_TXN *txn, char *user, char *pw)
{
	int rc;
	DBT key, val;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* store username + terminating null as key */
	key.data = user;
	key.size = strlen(user) + 1;

	/* store password + terminating null as value */
	val.data = pw;
	val.size = strlen(pw) + 1;

	rc = tdb.passwd->put(tdb.passwd, txn, &key, &val, DB_NOOVERWRITE);
	if (rc) {
		fprintf(stderr, "db put: %d\n", rc);
		exit(1);
	}
}

static void user_line(DB_TXN *txn, char *line)
{
	char *tab;
	char *user, *pw;
	size_t slen = strlen(line);

	/* ignore lines beginning with comment prefix */
	if (line[0] == '#')
		return;

	/* trim trailing whitespace */
	while (slen && (isspace(line[slen - 1]))) {
		slen--;
		line[slen] = 0;
	}

	/* ignore blank lines */
	if (!slen)
		return;

	/* find tab; make sure user & pw fields are non-zero length */
	tab = strchr(line, '\t');
	if (!tab || tab == line || (tab + 1) == 0) {
		invalid_lines++;
		return;
	}

	user = line;
	*tab = 0;
	pw = tab + 1;

	push_upw(txn, user, pw);
}

static void do_mode_user(void)
{
	char s[LINE_MAX + 1];
	DB_TXN *txn = NULL;
	int rc;

	rc = tdb.env->txn_begin(tdb.env, NULL, &txn, 0);
	if (rc) {
		fprintf(stderr, "txn_begin failed: %d\n", rc);
		exit(1);
	}

	while (fgets(s, sizeof(s), stdin) != NULL)
		user_line(txn, s);

	rc = txn->commit(txn, 0);
	if (rc) {
		fprintf(stderr, "txn_commit failed: %d\n", rc);
		exit(1);
	}
}

static void do_acl_list(void)
{
	int rc;
	DBC *cur = NULL;
	DBT key, val;
	unsigned long count = 0;
	struct db_acl_ent *ent;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	rc = tdb.acls->cursor(tdb.acls, NULL, &cur, 0);
	if (rc) {
		tdb.acls->err(tdb.acls, rc, "cursor create");
		exit(1);
	}

	printf("bucket\tgrantee\tperm\tkey\n");

	while (1) {
		rc = cur->get(cur, &key, &val, DB_NEXT);
		if (rc)
			break;

		ent = val.data;

		printf("%s\t%s\t%s\t%s\n",
		       ent->bucket,
		       ent->grantee,
		       ent->perm,
		       ent->key);

		count++;
	}

	fprintf(stderr, "%lu records\n", count);

	cur->close(cur);
}

static void do_bucket_list(void)
{
	int rc;
	DBC *cur = NULL;
	DBT key, val;
	unsigned long count = 0;
	struct db_bucket_ent *ent;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	rc = tdb.buckets->cursor(tdb.buckets, NULL, &cur, 0);
	if (rc) {
		tdb.buckets->err(tdb.buckets, rc, "cursor create");
		exit(1);
	}

	printf("name\towner\ttime_created\n");

	while (1) {
		rc = cur->get(cur, &key, &val, DB_NEXT);
		if (rc)
			break;

		ent = val.data;

		printf("%s\t%s\t%llu\n",
		       ent->name,
		       ent->owner,
		       (unsigned long long) GUINT64_FROM_LE(ent->time_create));

		count++;
	}

	fprintf(stderr, "%lu records\n", count);

	cur->close(cur);
}

static void do_user_list(void)
{
	int rc;
	DBC *cur = NULL;
	DBT key, val;
	unsigned long count = 0;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	rc = tdb.passwd->cursor(tdb.passwd, NULL, &cur, 0);
	if (rc) {
		tdb.passwd->err(tdb.passwd, rc, "cursor create");
		exit(1);
	}

	printf("username\tpassword\n");

	while (1) {
		rc = cur->get(cur, &key, &val, DB_NEXT);
		if (rc)
			break;

		printf("%s\t%s\n",
			(char *) key.data,
			(char *) val.data);
		count++;
	}

	fprintf(stderr, "%lu records\n", count);

	cur->close(cur);
}

static void print_obj(struct db_obj_ent *obj)
{
	uint32_t n_str = GUINT32_FROM_LE(obj->n_str);
	int i;
	void *p;
	uint16_t *slenp;
	char *dbstr;

	if (GUINT32_FROM_LE(obj->flags) & DB_OBJ_INLINE) {
		printf("%s\t%s\t%s\t[%d]\t%u\n",
			obj->bucket,
			obj->owner,
			obj->md5,
			GUINT16_FROM_LE(obj->size),
			n_str);
	} else {
		printf("%s\t%s\t%s",
			obj->bucket,
			obj->owner,
			obj->md5);
		for (i = 0; i < MAXWAY; i++) {
			if (i == 0) {
				printf("\t");
			} else {
				printf(",");
			}
			printf("\t%d:%lld",
			       GUINT32_FROM_LE(obj->d.avec[i].nid),
			       (long long) GUINT64_FROM_LE(obj->d.avec[i].oid));
			printf("%u\n", n_str);
		}
	}

	p = obj;
	p += sizeof(*obj);
	slenp = p;

	p += n_str * sizeof(uint16_t);

	for (i = 0; i < n_str; i++) {
		char pfx[16];

		dbstr = p;
		p += GUINT16_FROM_LE(*slenp);
		slenp++;

		if (i == 0)
			strcpy(pfx, "key: ");
		else
			sprintf(pfx, "str%d: ", i);

		printf("%s%s\n", pfx, dbstr);
	}

	printf("====\n");
}

static void do_obj_list(void)
{
	int rc;
	DBC *cur = NULL;
	DBT key, val;
	unsigned long count = 0;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	rc = tdb.objs->cursor(tdb.objs, NULL, &cur, 0);
	if (rc) {
		tdb.objs->err(tdb.objs, rc, "cursor create");
		exit(1);
	}

	printf("bucket\towner\tmd5\tsize|addr\tn_str\n");

	while (1) {
		struct db_obj_ent *obj;

		rc = cur->get(cur, &key, &val, DB_NEXT);
		if (rc)
			break;

		obj = val.data;
		print_obj(obj);

		count++;
	}

	fprintf(stderr, "%lu records\n", count);

	cur->close(cur);
}

static void do_obj_cnt(void)
{
	DBC *cur = NULL;
	DBT key, val;
	uint64_t objcount;	/* Host order */
	int rc;

	rc = tdb.oids->cursor(tdb.oids, NULL, &cur, 0);
	if (rc) {
		tdb.oids->err(tdb.oids, rc, "cursor create");
		exit(1);
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	/* read existing counter, if any */
	rc = cur->get(cur, &key, &val, DB_NEXT);
	if (rc == DB_NOTFOUND) {
		printf("-\n");
	} else if (rc) {
		printf("\n");
		fprintf(stderr, "objid get error %d\n", rc);
		exit(1);
	} else {
		if (val.size != sizeof(uint64_t)) {
			printf("\n");
			fprintf(stderr, "objid_init got size %d\n", val.size);
			exit(1);
		}

		objcount = GUINT64_FROM_LE(*(uint64_t *)val.data);
		printf("%llu\n", (unsigned long long) objcount);
	}

	cur->close(cur);
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	struct stat st;

	switch(key) {
	case 'a':
		mode_adm = mode_all_lists;
		break;
	case 'A':
		mode_adm = mode_acl_list;
		break;
	case 'B':
		mode_adm = mode_bucket_list;
		break;
	case 'O':
		mode_adm = mode_obj_list;
		break;
	case 't':
		if (stat(arg, &st) < 0) {
			perror(arg);
			return ARGP_ERR_UNKNOWN;
		}

		if (!S_ISDIR(st.st_mode))
			return ARGP_ERR_UNKNOWN;

		tdb_dir = arg;
		break;
	case 'u':
		mode_adm = mode_user;
		break;
	case 'U':
		mode_adm = mode_user_list;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	error_t aprc;
	int rc = 1;

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	if (!tdb_dir)
		die("no tdb dir (-t) specified\n");

	tdb.home = tdb_dir;
	if (tdb_open(&tdb, DB_RECOVER | DB_CREATE, DB_CREATE, "tdbadm", false))
		goto err_dbopen;

	switch (mode_adm) {
	case mode_user:
		do_mode_user();
		break;
	case mode_user_list:
		do_user_list();
		break;
	case mode_bucket_list:
		do_bucket_list();
		break;
	case mode_acl_list:
		do_acl_list();
		break;
	case mode_obj_list:
		do_obj_list();
		break;
	case mode_all_lists:
		printf("Users:\n");
		do_user_list();

		printf("\nBuckets:\n");
		do_bucket_list();

		printf("\nACLs:\n");
		do_acl_list();

		printf("\nObjects:\n");
		do_obj_list();

		printf("\nObjectCount: ");
		do_obj_cnt();
		break;
	default:
		fprintf(stderr, "%s: invalid mode\n", argv[0]);
		goto err_act;
	}

	rc = 0;

 err_act:
	tdb_close(&tdb);
 err_dbopen:
	return rc;
}
