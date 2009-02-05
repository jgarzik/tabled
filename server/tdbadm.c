
#include "tabled-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <argp.h>
#include <limits.h>

#include <tdb.h>

enum various_modes {
	mode_user		= 1,
	mode_user_list,
};

static int mode_adm;
static struct tabledb tdb;
static unsigned long invalid_lines;
static char *tdb_dir;

const char *argp_program_version = PACKAGE_VERSION;

static struct argp_option options[] = {
	{ "users", 'u', NULL, 0,
	  "User list input (into database)" },
	{ "list-users", 'U', NULL, 0,
	  "User list output (from database)" },
	{ "tdb", 't', "DIRECTORY", 0,
	  "Store TDB database environment in DIRECTORY" },
	{ }
};

static const char doc[] =
"tbladm - TDB administration";


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

	rc = tdb.passwd->put(tdb.passwd, txn, &key, &val, 0);
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

	tdb.home = tdb_dir;

	if (tdb_open(&tdb, DB_RECOVER | DB_CREATE, DB_CREATE,
		     "tdbadm", false))
		exit(1);

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

	tdb_close(&tdb);
}

static void do_user_list(void)
{
	int rc;
	DBC *cur = NULL;
	DBT key, val;
	unsigned long count = 0;

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	tdb.home = tdb_dir;

	if (tdb_open(&tdb, DB_RECOVER | DB_CREATE, DB_CREATE,
		     "tdbadm", false))
		exit(1);

	rc = tdb.passwd->cursor(tdb.passwd, NULL, &cur, 0);
	if (rc) {
		tdb.passwd->err(tdb.passwd, rc, "cursor create");
		exit(1);
	}

	while (1) {
		rc = cur->get(cur, &key, &val, DB_NEXT);
		if (rc)
			break;

		printf("%s:%s\n",
			(char *) key.data,
			(char *) val.data);
		count++;
	}

	fprintf(stderr, "%lu records\n", count);

	cur->close(cur);

	tdb_close(&tdb);
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	struct stat st;

	switch(key) {
	case 't':
		if (stat(arg, &st) < 0) {
			perror(tdb_dir);
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

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	if (!tdb_dir)
		die("no tdb dir (-d) specified\n");

	switch (mode_adm) {
	case mode_user:
		do_mode_user();
		break;
	case mode_user_list:
		do_user_list();
		break;
	default:
		fprintf(stderr, "%s: invalid mode\n", argv[0]);
		return 1;
	}

	return 0;
}
