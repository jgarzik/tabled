#ifndef __TABLED_H__
#define __TABLED_H__

#include <sys/epoll.h>
#include <netinet/in.h>
#include <openssl/md5.h>
#include <glib.h>
#include <pcre.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <httputil.h>
#include <elist.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

enum {
	TABLED_PGSZ_INODE	= 1024,
	TABLED_PGSZ_SESSION	= 512,
	TABLED_PGSZ_LOCK	= 512,

	CLI_REQ_BUF_SZ		= 8192,		/* buffer for req + hdrs */
	CLI_DATA_BUF_SZ		= 8192,
};

enum errcode {
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

enum sql_stmt_indices {
	st_begin,
	st_commit,
	st_rollback,
	st_service_list,
	st_add_bucket,
	st_del_bucket,
	st_del_bucket_acl,
	st_add_acl,
	st_bucket,
	st_bucket_objects,
	st_add_obj,
	st_del_obj,
	st_del_obj_acl,
	st_acl_bucket,
	st_acl_object,
	st_add_header,
	st_del_headers,
	st_headers,
	st_object,

	st_last = st_object
};

struct client;
struct client_write;
struct server_socket;

enum server_poll_type {
	spt_tcp_srv,				/* TCP server */
	spt_tcp_cli,				/* TCP client */
};

struct server_poll {
	enum server_poll_type	poll_type;	/* spt_xxx above */
	union {
		struct server_socket	*sock;
		struct client		*cli;
	} u;
};

enum {
	pat_bucket_name,
	pat_bucket_host,
	pat_bucket_path,
	pat_auth,
};

struct compiled_pat {
	const char	*str;
	int		options;
	pcre		*re;
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
	struct server_poll	poll;		/* poll info */
	struct epoll_event	evt;		/* epoll info */

	struct list_head	write_q;	/* list of async writes */

	unsigned int		req_used;	/* amount of req_buf in use */
	char			*req_ptr;	/* start of unexamined data */

	char			*hdr_start;	/* current hdr start */
	char			*hdr_end;	/* current hdr end (so far) */

	int			out_fd;		/* current output file */
	char			*out_fn;	/* current output filename */
	char			*out_bucket;
	char			*out_key;
	char			*out_user;
	MD5_CTX			out_md5;
	long			out_len;
	uint64_t		out_counter;

	int			in_fd;
	char			*in_fn;
	long			in_len;

	/* we put the big arrays and objects at the end... */

	struct http_req		req;		/* HTTP request */

	char			req_buf[CLI_REQ_BUF_SZ]; /* input buffer */
};

struct server_stats {
	unsigned long		poll;		/* number polls */
	unsigned long		event;		/* events dispatched */
	unsigned long		tcp_accept;	/* TCP accepted cxns */
	unsigned long		max_evt;	/* epoll events max'd out */
	unsigned long		opt_write;	/* optimistic writes */
};

struct server_socket {
	int			fd;
	struct server_poll	poll;
	struct epoll_event	evt;
};

struct server {
	unsigned long		flags;		/* SFL_xxx above */

	char			*data_dir;	/* database/log dir */
	char			*pid_file;	/* PID file */

	char			*port;		/* bind port */

	int			epoll_fd;	/* epoll descriptor */

	struct database		*db;		/* database handle */

	GList			*sockets;

	struct server_stats	stats;		/* global statistics */
};

/* bucket.c */
extern bool has_access(const char *user, const char *bucket, const char *key,
		const char *perm_in);
extern bool bucket_list(struct client *cli, const char *user, const char *bucket);
extern bool bucket_del(struct client *cli, const char *user, const char *bucket);
extern bool bucket_add(struct client *cli, const char *user, const char *bucket);
extern bool bucket_valid(const char *bucket);
extern bool service_list(struct client *cli, const char *user);

/* object.c */
extern bool object_del(struct client *cli, const char *user,
			const char *bucket, const char *key);
extern bool object_put(struct client *cli, const char *user, const char *bucket,
		const char *key, long content_len, bool expect_cont);
extern bool object_get(struct client *cli, const char *user, const char *bucket,
                       const char *key, bool want_body);
extern bool cli_evt_http_data_in(struct client *cli, unsigned int events);
extern void cli_out_end(struct client *cli);
extern void cli_in_end(struct client *cli);

/* util.c */
extern size_t strlist_len(GList *l);
extern void __strlist_free(GList *l);
extern void strlist_free(GList *l);
extern void req_free(struct http_req *req);
extern int req_hdr_push(struct http_req *req, char *key, char *val);
extern char *req_hdr(struct http_req *req, const char *key);
extern GHashTable *req_query(struct http_req *req);
extern void syslogerr(const char *prefix);
extern void strup(char *s);
extern int write_pid_file(const char *pid_fn);
extern int fsetflags(const char *prefix, int fd, int or_flags);
extern char *time2str(char *strbuf, time_t time);
extern void md5str(const unsigned char *digest, char *outstr);
extern void req_sign(struct http_req *req, const char *bucket, const char *key,
	      char *b64hmac_out);

extern sqlite3 *sqldb;
extern sqlite3_stmt *prep_stmts[];
extern bool sql_begin(void);
extern bool sql_commit(void);
extern bool sql_rollback(void);
extern void sql_done(void);
extern void sql_init(void);

/* server.c */
extern int debugging;
extern uint64_t counter;
extern struct server tabled_srv;
extern struct compiled_pat patterns[];
extern bool cli_err(struct client *cli, enum errcode code);
extern bool cli_resp_xml(struct client *cli, int http_status,
			 GList *content);
extern int cli_writeq(struct client *cli, const void *buf, unsigned int buflen,
		     cli_write_func cb, void *cb_data);
extern bool cli_cb_free(struct client *cli, struct client_write *wr,
			bool done);
extern bool cli_write_start(struct client *cli);
extern int cli_req_avail(struct client *cli);

#endif /* __TABLED_H__ */
