#ifndef __TDB_H__
#define __TDB_H__

#include <stdbool.h>
#include <db.h>

struct tabledb {
	char		*home;			/* database home dir */
	char		*key;			/* database AES key */

	DB_ENV		*env;			/* db4 env ptr */
	DB		*passwd;		/* user/password db */
};


extern int tdb_open(struct tabledb *tdb, unsigned int env_flags,
	unsigned int flags, const char *errpfx, bool do_syslog);
extern void tdb_close(struct tabledb *tdb);

#endif /* __TDB_H__ */
