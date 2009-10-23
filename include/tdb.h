#ifndef __TDB_H__
#define __TDB_H__

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

#include <stdint.h>
#include <stdbool.h>
#include <glib.h>
#include <db.h>

#define MAXWAY      3
#define INSIZE    120				/* arbitrary, needs benchmark */

#define DB_OBJ_INLINE        0x1

struct db_obj_addr {
	uint64_t oid;
	uint32_t nidv[MAXWAY];			/* 0 == absent */
};

struct db_obj_key {
	char		bucket[64];		/* bucket */
	char		key[0];			/* object key */
};

struct db_obj_ent {
	uint32_t	flags;
	uint32_t	n_str;			/* # attached string pairs */
	uint64_t	size;
	uint64_t	mtime;		/* UNIX time, but in microseconds */
	union {
		struct db_obj_addr a;
		unsigned char indata[INSIZE];
	} d;
	char		bucket[64];		/* bucket */
	char		owner[64];		/* object owner */
	char		md5[40];		/* data checksum */

	/* array of uint16_t
	   representing string lengths of HTTP headers.
	   first string length is always (key len) */

	/* packed (unaligned) string data...
	   the first string is this object's key */
};

struct db_bucket_ent {
	char		name[64];		/* bucket name */
	char		owner[64];		/* bucket owner */
	uint64_t	time_create;		/* creation timestamp */
};

struct db_acl_key {
	char		bucket[64];		/* bucket */
	char		key[0];			/* object key */
};

struct db_acl_ent {
	char		perm[128];		/* perm(s) granted */
	char		grantee[64];		/* grantee user */

	/* below this comment, the struct intentionally mirrors db_acl_key */
	char		bucket[64];		/* bucket */
	char		key[0];			/* object key */
};

#define DB_ACL_ANON	"*"

struct db_oid_key {
	uint64_t	oid;
};
struct db_oid_ent {
	uint64_t	oid;
};

enum db_event {
	TDB_EV_NONE, TDB_EV_CLIENT, TDB_EV_MASTER, TDB_EV_ELECTED
};

struct tabledb {
	bool		is_master;
	bool		keyed;			/* database uses AES key */

	const char	*home;			/* database home dir */
	void		(*state_cb)(enum db_event);

	DB_ENV		*env;			/* db4 env ptr */
	DB		*passwd;		/* user/password db */
	DB		*buckets;		/* bucket db */
	DB		*buckets_idx;		/* buckets owner idx */
	DB		*acls;			/* acl db */
	DB		*objs;			/* object metadata db */
	DB		*oids;			/* object ID db */
};

struct db_remote {	/* remotes for tdb_init */
	char *host;
	unsigned short port;
};

extern int tdb_init(struct tabledb *tdb, const char *home, const char *pass,
	unsigned int env_flags, const char *errpfx, bool do_syslog,
	GList *remotes, char *rep_host, unsigned short rep_port,
	void (*cb)(enum db_event));
extern int tdb_up(struct tabledb *tdb, unsigned int open_flags);
extern void tdb_down(struct tabledb *tdb);
extern void tdb_fini(struct tabledb *tdb);

/* util.c */
uint64_t objid_next(uint64_t *state, struct tabledb *tdbp);
int objid_init(uint64_t *state, struct tabledb *tdbp);

#endif /* __TDB_H__ */
