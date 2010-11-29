#ifndef __TABLED_H__
#define __TABLED_H__

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
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <openssl/md5.h>
#include <curl/curl.h>
#include <glib.h>
#include <pcre.h>
#include <event.h>
#include <hstor.h>
#include <elist.h>
#include <tdb.h>
#include <hail_log.h>
#include <anet.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define ADDRSIZE	(sizeof(struct sockaddr_in6))	/* enough for v4 & v6 */

enum {
	TABLED_PGSZ_INODE	= 4096,
	TABLED_PGSZ_SESSION	= 4096,
	TABLED_PGSZ_LOCK	= 4096,

	TABLED_CHKPT_SEC	= 60 * 5,	/* secs between db4 chkpt */
	TABLED_RESCAN_SEC	= 60*3 + 7,	/* secs btw key rescans */
	TABLED_MCWAIT_SEC	= 35,		/* secs to moderate reconn. */
	TABLED_REUP_SEC		= 35,		/* secs to retry rtdb_restart */

	CHUNK_REBOOT_TIME	= 3*60,		/* secs to declare chunk dead */

	CLI_REQ_BUF_SZ		= 8192,		/* buffer for req + hdrs */
	CLI_DATA_BUF_SZ		= 65536,
};

enum errcode {
	RedirectClient,
	AccessDenied,
	BucketAlreadyExists,
	BucketNotEmpty,
	InternalError,
	InvalidArgument,
	InvalidBucketName,
	InvalidURI,
	MissingContentLength,
	NoSuchBucket,
	NoSuchKey,
	PreconditionFailed,
	SignatureDoesNotMatch,
};

struct client;

enum {
	pat_auth,
	pat_ipv4_addr,
};

struct compiled_pat {
	const char	*str;
	int		options;
	pcre		*re;
};

struct geo {
	char			*area;
	char			*zone;		/* Building */
	char			*rack;
};

enum storage_type {
	STT_CHUNK,		/* Hail chunkserver */
	STT_POSIX,		/* UNIX filesystem interface, may be NFS */
	STT_SWIFT		/* OpenStack storage (evolved CloudFiles) */
};

struct storage_node;
struct open_chunk;

struct st_node_ops {
	int (*open)(struct open_chunk *cep, struct storage_node *stn,
		    struct event_base *ev_base);
	int (*open_read)(struct open_chunk *cep,
			 void (*cb)(struct open_chunk *),
			 uint64_t key, uint64_t *psz);
	void (*close)(struct open_chunk *cep);
	void (*abort)(struct open_chunk *cep);
	int (*put_start)(struct open_chunk *cep,
			 void (*cb)(struct open_chunk *),
			 uint64_t key, uint64_t size);
	ssize_t (*put_buf)(struct open_chunk *cep, void *data, size_t len);
	bool (*put_end)(struct open_chunk *cep);
	ssize_t (*get_buf)(struct open_chunk *cep, void *data, size_t len);
	int (*obj_del)(struct storage_node *stn, uint64_t key);
	bool (*obj_test)(struct open_chunk *cep, uint64_t key);
	int (*node_check)(struct storage_node *stn);
};

struct storage_node {
	struct list_head	all_link;
	uint32_t		id;
	bool			reported;
	bool			up;
	time_t			last_up;
	enum storage_type	type;
	struct st_node_ops	*ops;

	int ref;		/* number of open_chunk or other */

	/* chunk */
	unsigned		alen;
	struct sockaddr_in6	addr;
	char			*hostname;

	/* file */
	char			*basepath;
};

typedef bool (*cli_evt_func)(struct client *, unsigned int,
			     bool *invalidate_cli);

/* an open chunkd client */
struct open_chunk {
	struct st_client	*stc;
	struct storage_node	*node;
	struct list_head	link;
	void			*cli;	/* usually struct client * */
	struct event_base	*evbase;

	uint64_t		key;
	void (*ocb)(struct open_chunk *);
	uint64_t		size;
	uint64_t		done;

	struct st_node_ops	*ops;

	/* chunk */
	int			wfd;
	bool			w_armed;
	struct event		wevt;
	void			*wbuf;
	size_t			wcnt;	/* in current buffer */

	int			rfd;
	bool			r_armed;
	struct event		revt;

	/* posix */
	/*
	 * Don't merge fd, rfd, wfd prematurely. A future backend may need
	 * several fds and then what? It's an implementation detail.
	 */
	int			pfd;
};

/* internal client socket state */
enum client_state {
	evt_read_req,				/* read request line */
	evt_parse_req,				/* parse request line */
	evt_read_hdr,				/* read header line */
	evt_parse_hdr,				/* parse header line */
	evt_http_req,				/* HTTP request fully rx'd */
	evt_http_data_in,			/* HTTP request's content */
	evt_dispose,				/* dispose of client */
	evt_recycle,				/* restart HTTP request parse */
};

struct client {
	enum client_state	state;		/* socket state */
	cli_evt_func		*evt_table;

	struct sockaddr_in6	addr;		/* inet address */
	char			addr_host[64];	/* ASCII version of inet addr */
	int			fd;		/* socket */
	bool			ev_active;
	struct event		ev;
	struct event		write_ev;

	struct atcp_wr_state	wst;
	/* some debugging stats */

	unsigned int		req_used;	/* amount of req_buf in use */
	char			*req_ptr;	/* start of unexamined data */

	char			*hdr_start;	/* current hdr start */
	char			*hdr_end;	/* current hdr end (so far) */

	struct list_head	out_ch;		/* open_chunk.link */
	char			*out_bucket;
	char			*out_key;
	char			*out_user;
	MD5_CTX			out_md5;
	long			out_len;
	uint64_t		out_size;
	uint64_t		out_objid;
	char			*out_buf;
	size_t			out_bcnt;	/* used length of out_buf */
	int			out_nput;	/* number of users of out_buf */

	struct open_chunk	in_ce;
	unsigned char		*in_mem;
	uint64_t		in_objid;
	long			in_len;
	int			in_retry;

	/* we put the big arrays and objects at the end... */

	struct http_req		req;		/* HTTP request */

	char			req_buf[CLI_REQ_BUF_SZ]; /* input buffer */
};

enum st_want {
	ST_W_INIT, ST_W_MASTER, ST_W_SLAVE
};

enum st_tdb {
	ST_TDB_INIT, ST_TDB_OPEN, ST_TDB_MASTER, ST_TDB_SLAVE,
	ST_TDBNUM
};

enum st_net {
	ST_NET_INIT, ST_NET_OPEN, ST_NET_LISTEN
};

struct server_stats {
	uint64_t		poll;		/* number polls */
	uint64_t		event;		/* events dispatched */
	uint64_t		tcp_accept;	/* TCP accepted cxns */
	uint64_t		opt_write;	/* optimistic writes */

	uint64_t		max_write_buf;
};

#define DBID_NONE      0
#define DBID_MIN       2
#define DBID_MAX     105

struct db_remote {		/* other DB nodes */
	char		*name;			/* do not resolve as a host */
	char		*host;
	unsigned short	port;
	int		dbid;			/* signed in db4, traditional */
};

struct listen_cfg {
	/* bool			encrypt; */
	/* char			*host; */
	char			*port;
	char			*port_file;
};

struct server {
	unsigned long		flags;		/* SFL_xxx above */
	int			pid_fd;		/* fd of pid_file */
	GMutex			*bigmutex;
	struct event_base	*evbase_main;
	int			ev_pipe[2];
	struct event		pevt;
	bool			mc_delay;
	struct event		mc_timer;

	char			*config;	/* config file (static) */

	char			*tdb_dir;	/* TDB metadata database dir */
	char			*pid_file;	/* PID file */
	char			*port;		/* bind port */
	char			*port_file;
	char			*chunk_user;	/* username for stc_new */
	char			*chunk_key;	/* key for stc_new */
	char			*rep_name;	/* db4 replication name */
	unsigned short		rep_port;	/* db4 replication port */
	char			*status_port;	/* status webserver */
	char			*group;		/* our group (both T and Ch) */

	char			*ourhost;	/* use this if DB master */
	struct database		*db;		/* database handle */
	GList			*rep_remotes;
	struct db_remote	*rep_master;	/* if we're slave */
	int			rep_next_id;
	struct event		reup_timer;

	GList			*sockets;
	struct list_head	all_stor;	/* struct storage_node */
	int			num_stor;	/* number of storage_node's  */
	uint64_t		object_count;

	enum st_want		state_want;
	enum st_tdb		state_tdb;
	enum st_net		state_net;

	struct event		chkpt_timer;	/* db4 checkpoint timer */

	struct server_stats	stats;		/* global statistics */
};

#define STOR_KEY_SLEN  16
#define STOR_KEY_FMT	"%016llx"

/*
 * Low-level channel, for both sides.
 *
 * The combined link state confuses session (e.g. login) and the framing, which
 * is not pretty but works. At least we have a separate link-state struct.
 *
 * In a settled state, db_conn corresponds 1:1 to db_remote, but
 * it's not necesserily so when connections are being established.
 */
enum dbc_state {  DBC_INIT, DBC_LOGIN, DBC_OPEN, DBC_DEAD };

struct db_link {
	int		fd;
	enum dbc_state	state;

	bool		writing;
	struct event	wrev;			/* when writing */
	unsigned char	*obuf;
	int		obuflen;
	int		done, togo;

	struct event	rcev;			/* whenever fd >= 0 */
	unsigned char	*ibuf;
	int		ibuflen;		/* currently allocated ibuf */
	int		cnt;			/* currently in ibuf */
	int		explen;			/* expected length */
};

struct db_conn {		/* a connection with other DB node */
	struct tablerep	*rtdb;
	struct db_remote *remote;
	struct list_head link;

	struct db_link	lk;
};

struct tablerep {
	struct tabledb	tdb;
	const char	*thisname;
	int		thisid;

	int		sockfd4, sockfd6;
	struct event	lsev4, lsev6;
	struct list_head conns;	// struct db_conn

	struct db_conn	*mdbc;
};

extern struct tablerep tdbrep;

/* bucket.c */
extern bool has_access(const char *user, const char *bucket, const char *key,
		const char *perm_in);
extern int add_access_canned(DB_TXN *txn, const char *bucket, const char *key,
		const char *user, enum ReqACLC canacl);
bool access_list(struct client *cli, const char *bucket, const char *key,
		const char *user);
extern bool bucket_list(struct client *cli, const char *user, const char *bucket);
extern bool bucket_del(struct client *cli, const char *user, const char *bucket);
extern bool bucket_add(struct client *cli, const char *user, const char *bucket);
extern bool bucket_valid(const char *bucket);
extern char *bucket_host(const char *host, const char *ourhost);
extern bool bucket_base(const char *uri_path, size_t uri_path_len,
			char **pbucket, char **ppath);
extern bool service_list(struct client *cli, const char *user);

/* object.c */
extern bool object_del_acls(DB_TXN *txn, const char *bucket, const char *key);
extern bool object_del(struct client *cli, const char *user,
			const char *bucket, const char *key);
extern bool object_put(struct client *cli, const char *user, const char *bucket,
		const char *key, long content_len, bool expect_cont);
extern bool object_get(struct client *cli, const char *user, const char *bucket,
                       const char *key, bool want_body);
extern bool cli_evt_http_data_in(struct client *cli, unsigned int events,
				bool *invalidate_cli);
extern void cli_out_end(struct client *cli);
extern void cli_in_end(struct client *cli);

/* cldu.c */
extern void cld_init(void);
extern int cld_begin(const char *fqdn, const char *group, const char *name,
		int verbose);
extern void cldu_add_host(const char *host, unsigned int port);
extern void cld_post_rep_conn(const char *rep_host, unsigned int rep_port);
extern void cld_end(void);

/* util.c */
extern size_t strlist_len(GList *l);
extern void __strlist_free(GList *l);
extern void strlist_free(GList *l);
extern void req_free(struct http_req *req);
extern int req_hdr_push(struct http_req *req, char *key, char *val);
extern char *req_hdr(struct http_req *req, const char *key);
extern GHashTable *req_query(struct http_req *req);
extern void applogerr(const char *prefix);
extern void strup(char *s);
extern int write_pid_file(const char *pid_fn);
extern int fsetflags(const char *prefix, int fd, int or_flags);
extern void md5str(const unsigned char *digest, char *outstr);
extern void req_sign(struct http_req *req, const char *bucket, const char *key,
	      char *b64hmac_out);

/* server.c */
extern int debugging;
extern struct server tabled_srv;
extern struct compiled_pat patterns[];
extern bool stat_status(struct client *cli, GList *content);
extern bool cli_err(struct client *cli, enum errcode code);
extern bool cli_err_write(struct client *cli, char *hdr, char *content);
extern bool cli_resp_xml(struct client *cli, int http_status, GList *content);
extern bool cli_resp_html(struct client *cli, int http_status, GList *content);
extern int cli_req_avail(struct client *cli);
extern void applog(int prio, const char *fmt, ...);
extern void cld_update_cb(void);
extern int stor_update_cb(void);
extern int tdb_slave_login_cb(int srcid);
extern void tdb_slave_disc_cb(void);
extern void tdb_conn_scrub_cb(void);
extern struct db_remote *tdb_find_remote_byname(const char *name);
extern struct db_remote *tdb_find_remote_byid(int id);

/* status.c */
extern bool stat_evt_http_req(struct client *cli, unsigned int events,
				bool *invalidate_cli);

/* config.c */
extern void read_config(void);

/* storage.c */
extern struct storage_node *stor_node_get(struct storage_node *stn);
extern void stor_node_put(struct storage_node *stn);
extern void stor_read_event(int fd, short events, void *userdata);
extern void stor_write_event(int fd, short events, void *userdata);
static inline int stor_open(struct open_chunk *cep, struct storage_node *stn,
			    struct event_base *ev_base)
{
	cep->ops = stn->ops;
	return cep->ops->open(cep, stn, ev_base);
}
static inline int stor_open_read(struct open_chunk *cep,
				 void (*cb)(struct open_chunk *),
				 uint64_t key, uint64_t *psz)
{
	return cep->ops->open_read(cep, cb, key, psz);
}
/*
 * The stor_abort and stor_close have an annoying convention of being possibly
 * called on an unopened open_chunk. We deal with that.
 */
static inline void stor_close(struct open_chunk *cep)
{
	if (cep->ops)
		cep->ops->close(cep);
}
static inline void stor_abort(struct open_chunk *cep)
{
	if (cep->ops)
		cep->ops->abort(cep);
}
static inline int stor_put_start(struct open_chunk *cep,
			  void (*cb)(struct open_chunk *),
			  uint64_t key, uint64_t size)
{
	return cep->ops->put_start(cep, cb, key, size);
}
static inline ssize_t stor_put_buf(struct open_chunk *cep, void *data,
				   size_t len)
{
	return cep->ops->put_buf(cep, data, len);
}
static inline bool stor_put_end(struct open_chunk *cep)
{
	return cep->ops->put_end(cep);
}
static inline ssize_t stor_get_buf(struct open_chunk *cep, void *data,
				   size_t len)
{
	return cep->ops->get_buf(cep, data, len);
}
static inline int stor_obj_del(struct storage_node *stn, uint64_t key)
{
	return stn->ops->obj_del(stn, key);
}
static inline bool stor_obj_test(struct open_chunk *cep, uint64_t key)
{
	return cep->ops->obj_test(cep, key);
}
static inline int stor_node_check(struct storage_node *stn)
{
	return stn->ops->node_check(stn);
}
extern struct storage_node *stor_node_by_nid(uint32_t nid);
extern void stor_add_node(uint32_t nid, enum storage_type type,
			  const char *base,
			  const char *hostname, const char *portstr,
			  struct geo *locp);
extern void stor_stats(void);
extern bool stor_status(struct client *cli, GList *content);

/* storparse.c */
extern void stor_parse(char *fname, const char *text, size_t len);

/* stor_chunk.c */
extern struct st_node_ops stor_ops_chunk;

/* stor_fs.c */
extern struct st_node_ops stor_ops_posix;

/* replica.c */
extern void rep_init(struct event_base *ev_base);
extern void rep_start(void);
extern void rep_stats(void);
extern bool rep_status(struct client *cli, GList *content);

/* metarep.c */
extern int rtdb_init(struct tablerep *rtdb, const char *thishost);
extern int rtdb_start(struct tablerep *rtdb, const char *db_home,
	bool we_are_master,
	struct db_remote *rep_master, unsigned short rep_port,
	void (*cb)(enum db_event));
extern void rtdb_mc_reset(struct tablerep *rtdb, bool we_are_master,
	struct db_remote *rep_master, unsigned short rep_port);
extern void rtdb_dbc_scrub(struct tablerep *rtdb);
extern int rtdb_restart(struct tablerep *rtdb, bool we_are_master);
extern void rtdb_fini(struct tablerep *rtdb);

#endif /* __TABLED_H__ */
