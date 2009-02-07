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


#include <stdbool.h>
#include <db.h>

struct db_obj_key {
	char		bucket[64];		/* bucket */
	char		key[0];			/* object key */
};

struct db_obj_ent {
	char		name[128];		/* local filename (no dirs) */
	char		bucket[64];		/* bucket */
	char		owner[64];		/* object owner */
	char		md5[32];		/* data checksum */
	uint32_t	n_str;			/* # attached string pairs */

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

struct tabledb {
	char		*home;			/* database home dir */
	char		*key;			/* database AES key */

	DB_ENV		*env;			/* db4 env ptr */
	DB		*passwd;		/* user/password db */
	DB		*buckets;		/* bucket db */
	DB		*buckets_idx;		/* buckets owner idx */
	DB		*acls;			/* acl db */
	DB		*objs;			/* object metadata db */
};


extern int tdb_open(struct tabledb *tdb, unsigned int env_flags,
	unsigned int flags, const char *errpfx, bool do_syslog);
extern void tdb_close(struct tabledb *tdb);

#endif /* __TDB_H__ */
