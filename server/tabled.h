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
#include <netinet/in.h>
#include <openssl/md5.h>
#include <glib.h>
#include <pcre.h>
#include <event.h>
#include <httputil.h>
#include <elist.h>
#include <tdb.h>
#include <hail_log.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define ADDRSIZE	24	/* Enough for IPv6, including port. */

enum {
	TABLED_PGSZ_INODE	= 4096,
	TABLED_PGSZ_SESSION	= 4096,
	TABLED_PGSZ_LOCK	= 4096,

	TABLED_CHKPT_SEC	= 60 * 5,	/* secs between db4 chkpt */

	CLI_REQ_BUF_SZ		= 8192,		/* buffer for req + hdrs */
	CLI_DATA_BUF_SZ		= 8192,
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
struct client_write;
struct server_socket;

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

struct storage_node {
	struct list_head	all_link;
	uint32_t		id;
	bool			up;

	unsigned		alen;
	int			addr_af;
	struct sockaddr_in6	addr;
	char *hostname;		/* Only used because stc_new is overly smart. */

	int nchu;		/* number of open_chunk */
};

typedef bool (*cli_evt_func)(struct client *, unsigned int);
typedef bool (*cli_write_func)(struct client *, struct client_write *, bool);

struct client_write {
	const void		*buf;		/* write buffer */
	int			len;		/* write buffer length */
	cli_write_func		cb;		/* callback */
	void			*cb_data;	/* data passed to cb */

	struct list_head	node;
};

/* an open chunkd client */
struct open_chunk {
	struct st_client	*stc;
	struct storage_node	*node;
	struct list_head	link;
	struct client		*cli;

	uint64_t		wtogo;
	uint64_t		wkey;
	void (*wcb)(struct open_chunk *);
	int			wfd;
	bool			w_armed;
	struct event		wevt;
	void			*wbuf;
	size_t			wcnt;	/* in current buffer */

	uint64_t		roff;
	uint64_t		rsize;
	void (*rcb)(struct open_chunk *);
	int			rfd;
	bool			r_armed;
	struct event		revt;
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

	struct sockaddr_in6	addr;		/* inet address */
	char			addr_host[64];	/* ASCII version of inet addr */
	int			fd;		/* socket */
	bool			ev_active;
	struct event		ev;
	struct event		write_ev;

	struct list_head	write_q;	/* list of async writes */
	size_t			write_cnt;	/* water level */
	bool			writing;

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

enum st_tdb {
	ST_TDB_INIT, ST_TDB_OPEN, ST_TDB_ACTIVE, ST_TDB_MASTER, ST_TDB_SLAVE,
	ST_TDBNUM
};

enum st_net {
	ST_NET_INIT, ST_NET_OPEN, ST_NET_LISTEN
};

struct server_stats {
	unsigned long		poll;		/* number polls */
	unsigned long		event;		/* events dispatched */
	unsigned long		tcp_accept;	/* TCP accepted cxns */
	unsigned long		opt_write;	/* optimistic writes */
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

	char			*config;	/* config file (static) */

	char			*tdb_dir;	/* TDB metadata database dir */
	char			*pid_file;	/* PID file */
	char			*port;		/* bind port */
	char			*port_file;
	char			*chunk_user;	/* username for stc_new */
	char			*chunk_key;	/* key for stc_new */
	unsigned short		rep_port;	/* db4 replication port */

	char			*ourhost;	/* use this if DB master */
	struct database		*db;		/* database handle */
	GList			*rep_remotes;

	GList			*sockets;
	struct list_head	all_stor;	/* struct storage_node */
	int			num_stor;	/* number of storage_node's  */
	uint64_t		object_count;

	enum st_tdb		state_tdb, state_tdb_new;
	enum st_net		state_net;

	struct event		chkpt_timer;	/* db4 checkpoint timer */

	struct server_stats	stats;		/* global statistics */
};

extern struct tabledb tdb;

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
extern bool bucket_base(const char *uri_path, char **pbucket, char **ppath);
extern bool service_list(struct client *cli, const char *user);

/* object.c */
extern bool object_del_acls(DB_TXN *txn, const char *bucket, const char *key);
extern bool object_del(struct client *cli, const char *user,
			const char *bucket, const char *key);
extern bool object_put(struct client *cli, const char *user, const char *bucket,
		const char *key, long content_len, bool expect_cont);
extern bool object_get(struct client *cli, const char *user, const char *bucket,
                       const char *key, bool want_body);
extern bool cli_evt_http_data_in(struct client *cli, unsigned int events);
extern void cli_out_end(struct client *cli);
extern void cli_in_end(struct client *cli);

/* cldu.c */
extern void cld_init(void);
extern int cld_begin(const char *fqdn, const char *cell);
extern void cldu_add_host(const char *host, unsigned int port);
extern void cld_end(void);
extern struct hail_log cldu_hail_log;

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
extern char *time2str(char *strbuf, time_t time);
extern void md5str(const unsigned char *digest, char *outstr);
extern void req_sign(struct http_req *req, const char *bucket, const char *key,
	      char *b64hmac_out);

/* server.c */
extern int debugging;
extern struct server tabled_srv;
extern struct compiled_pat patterns[];
extern bool cli_err(struct client *cli, enum errcode code);
extern bool cli_resp_xml(struct client *cli, int http_status,
			 GList *content);
extern int cli_writeq(struct client *cli, const void *buf, unsigned int buflen,
		     cli_write_func cb, void *cb_data);
extern size_t cli_wqueued(struct client *cli);
extern bool cli_cb_free(struct client *cli, struct client_write *wr,
			bool done);
extern bool cli_write_start(struct client *cli);
extern int cli_req_avail(struct client *cli);
extern void applog(int prio, const char *fmt, ...);
extern int stor_update_cb(void);

/* config.c */
extern void read_config(void);

/* storage.c */
extern int stor_open(struct open_chunk *cep, struct storage_node *stn);
extern int stor_open_read(struct open_chunk *cep,
			  void (*cb)(struct open_chunk *),
			  uint64_t key, uint64_t *psz);
extern void stor_close(struct open_chunk *cep);
extern void stor_abort(struct open_chunk *cep);
extern int stor_put_start(struct open_chunk *cep,
			  void (*cb)(struct open_chunk *),
			  uint64_t key, uint64_t size);
extern ssize_t stor_put_buf(struct open_chunk *cep, void *data, size_t len);
extern bool stor_put_end(struct open_chunk *cep);
extern ssize_t stor_get_buf(struct open_chunk *cep, void *data, size_t len);
extern int stor_obj_del(struct storage_node *stn, uint64_t key);
extern bool stor_obj_test(struct open_chunk *cep, uint64_t key);
extern struct storage_node *stor_node_by_nid(uint32_t nid);
extern void stor_add_node(uint32_t nid, const char *hostname,
			  const char *portstr, struct geo *locp);
extern int stor_node_check(struct storage_node *stn);

/* storparse.c */
extern void stor_parse(char *fname, const char *text, size_t len);

#endif /* __TABLED_H__ */
