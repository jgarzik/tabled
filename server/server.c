
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

#define _GNU_SOURCE
#include "tabled-config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <signal.h>
#include <locale.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdarg.h>
#include <syslog.h>
#include <argp.h>
#include <errno.h>
#include <time.h>
#include <pcre.h>
#include <dirent.h>
#include <glib.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <elist.h>
#include <chunkc.h>
#include <cldc.h>
#include "tabled.h"

#define PROGRAM_NAME "tabled"

const char *argp_program_version = PACKAGE_VERSION;

enum {
	CLI_MAX_WR_IOV		= 32,		/* max iov per writev(2) */

	SFL_FOREGROUND		= (1 << 0),	/* run in foreground */
};

struct server_socket {
	bool			is_status;
	int			fd;
	struct event		ev;
};

static struct argp_option options[] = {
	{ "config", 'C', "/etc/tabled.conf", 0,
	  "Configuration file" },
	{ "debug", 'D', NULL, 0,
	  "Enable debug output" },
	{ "stderr", 'E', NULL, 0,
	  "Switch the log to standard error" },
	{ "pid", 'P', "FILE", 0,
	  "Write daemon process id to FILE" },
	{ "foreground", 'F', NULL, 0,
	  "Run in foreground, do not fork" },
	{ }
};

static const char doc[] =
PROGRAM_NAME " - distributed table daemon";

static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, NULL, doc };

static bool server_running = true;
static bool use_syslog = true;
int debugging = 0;

struct server tabled_srv = {
	.config			= "/etc/tabled.conf",
};

struct tabledb tdb;

enum {
	TT_CMD_DUMP,
	TT_CMD_TDBST_MASTER,
	TT_CMD_TDBST_SLAVE
};

struct compiled_pat patterns[] = {
	[pat_auth] =
	{ "^AWS (\\w+):(\\S+)", 0, },

	[pat_ipv4_addr] =
	{ "\\d+\\.\\d+\\.\\d+\\.\\d+" },
};

static char *state_name_tdb[ST_TDBNUM] = {
	"Init", "Open", "Active", "Master", "Slave"
};

static struct {
	const char	*code;
	int		status;
	const char	*msg;
} err_info[] = {
	[RedirectClient] =
	{ "Redirect", 307,
	  "Not a master" },

	[AccessDenied] =
	{ "AccessDenied", 403,
	  "Access denied" },

	[BucketAlreadyExists] =
	{ "BucketAlreadyExists", 409,
	  "The requested bucket name is not available" },

	[BucketNotEmpty] =
	{ "BucketNotEmpty", 409,
	  "The bucket you tried to delete is not empty" },

	[InternalError] =
	{ "InternalError", 500,
	  "We encountered an internal error. Please try again." },

	[InvalidArgument] =
	{ "InvalidArgument", 400,
	  "Invalid Argument" },

	[InvalidBucketName] =
	{ "InvalidBucketName", 400,
	  "The specified bucket is not valid" },

	[InvalidURI] =
	{ "InvalidURI", 400,
	  "Could not parse the specified URI" },

	[MissingContentLength] =
	{ "MissingContentLength", 411,
	  "You must provide the Content-Length HTTP header" },

	[NoSuchBucket] =
	{ "NoSuchBucket", 404,
	  "The specified bucket does not exist" },

	[NoSuchKey] =
	{ "NoSuchKey", 404,
	  "The resource you requested does not exist" },

	[PreconditionFailed] =
	{ "PreconditionFailed", 412,
	  "Precondition failed" },

	[SignatureDoesNotMatch] =
	{ "SignatureDoesNotMatch", 403,
	  "The calculated request signature does not match your provided one" },
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 'C':
		tabled_srv.config = arg;
		break;
	case 'D':
		debugging = 1;
		break;
	case 'E':
		use_syslog = false;
		break;
	case 'F':
		tabled_srv.flags |= SFL_FOREGROUND;
		break;
	case 'P':
		tabled_srv.pid_file = strdup(arg);
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);	/* too many args */
		break;
	case ARGP_KEY_END:
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

void applog(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (use_syslog) {
		vsyslog(prio, fmt, ap);
	} else {
		char *f;
		int len;
		int pid;

		pid = getpid() & 0xFFFFFFFF;
		len = sizeof(PROGRAM_NAME "[0123456789]: ") + strlen(fmt) + 2;
		f = alloca(len);
		sprintf(f, PROGRAM_NAME "[%u]: %s\n", pid, fmt);
		vfprintf(stderr, f, ap);	/* atomic write to stderr */
	}
	va_end(ap);
}

/*
 * Find out own hostname.
 * This is needed for:
 *  - announcing ourselves in CLD in case we're DB master
 *  - finding the local domain and its SRV records
 * Do this before our state machines start ticking, so we can quit with
 * a meaningful message easily.
 */
static char *get_hostname(void)
{
	enum { hostsz = 64 };
	char hostb[hostsz];
	char *ret;

	if (gethostname(hostb, hostsz-1) < 0) {
		applog(LOG_ERR, "get_hostname: gethostname error (%d): %s",
		       errno, strerror(errno));
		exit(1);
	}
	hostb[hostsz-1] = 0;
	if ((ret = strdup(hostb)) == NULL) {
		applog(LOG_ERR, "get_hostname: no core (%ld)",
		       (long)strlen(hostb));
		exit(1);
	}
	return ret;
}

/*
 * Allocate and return key iff path is not root.
 *
 * No path and empty path count as root.
 * Canonical "/" is root. Parameters like "/?prefix=foo" mean root.
 * We probably should account for "/%3Fprefix=foo" too, one day.
 * Fortunately, we don't support parameters "/&param=bar".
 * About "//" we haven't decided yet, return non-root for now.
 */
static char *pathtokey(const char *path)
{
	const char *end;
	char *key;
	int klen;

	if (path == NULL)
		return NULL;

	end = path;
	while (*end != 0 && *end != '?')
		end++;

	if (path == end)
		return NULL;
	if (*path != '/')
		return NULL;
	path++;
	if (path == end)
		return NULL;
	klen = end - path;

	key = malloc(klen + 1);
	memcpy(key, path, klen);
	key[klen] = 0;

	return key;
}

static int authcheck(struct http_req *req, char *extra_bucket,
    const char *auth, char **puser)
{
	char b64sig[64];
	int usiglen;
	int captured[16];
	char *user;
	char *pass;
	DBT key, val;
	int rc;
	int err;

	if (pcre_exec(patterns[pat_auth].re, NULL,
			      auth, strlen(auth), 0, 0, captured, 16) != 3) {
		err = InvalidArgument;
		goto err_pat;
	}

	user = g_strndup(auth + captured[2], captured[3] - captured[2]);
	usiglen = captured[5] - captured[4];

	memset(&key, 0, sizeof(key));
	key.data = user;
	key.size = strlen(user) + 1;

	memset(&val, 0, sizeof(val));
	val.flags = DB_DBT_MALLOC;

	/* to prevent attacks that validate a username's
	 * existence, we return the same error regardless
	 * of whether the user exists or signature does
	 * not match.
	 */

	rc = tdb.passwd->get(tdb.passwd, NULL, &key, &val, 0);
	if (rc) {
		pass = strdup("");

		if (debugging)
			applog(LOG_INFO, "id %s lookup fail (%d)", user, rc);
		if (rc != DB_NOTFOUND) {
			char s[64];

			snprintf(s, 64, "get user '%s'", user);
			tdb.passwd->err(tdb.passwd, rc, s);
		}
	} else {
		pass = val.data;
	}

	req_sign(req, extra_bucket, pass, b64sig);
	free(pass);

	if (strncmp(b64sig, auth + captured[4], usiglen) != 0) {
		err = SignatureDoesNotMatch;
		goto err_cmp;
	}

	*puser = user;
	return 0;

err_cmp:
	free(user);
err_pat:
	return err;
}

static void term_signal(int signo)
{
	server_running = false;
	event_loopbreak();
}

static void stats_signal(int signo)
{
	static const unsigned char cmd = TT_CMD_DUMP;
	write(tabled_srv.ev_pipe[1], &cmd, 1);
}

#define X(stat) \
	applog(LOG_INFO, "STAT %s %lu", #stat, tabled_srv.stats.stat)

static void stats_dump(void)
{
	X(poll);
	X(event);
	X(tcp_accept);
	X(opt_write);
	applog(LOG_INFO, "State: TDB %s",
	    state_name_tdb[tabled_srv.state_tdb]);
	stor_stats();
}

#undef X

static bool cli_write_free(struct client *cli, struct client_write *tmp,
			   bool done)
{
	bool rcb = false;

	cli->write_cnt -= tmp->length;
	list_del(&tmp->node);
	if (tmp->cb)
		rcb = tmp->cb(cli, tmp->cb_data, done);
	free(tmp);

	return rcb;
}

static void cli_write_free_all(struct client *cli)
{
	struct client_write *wr, *tmp;

	list_for_each_entry_safe(wr, tmp, &cli->write_q, node) {
		cli_write_free(cli, wr, false);
	}
}

static void cli_free(struct client *cli)
{
	cli_write_free_all(cli);

	cli_out_end(cli);
	cli_in_end(cli);

	/* clean up network socket */
	if (cli->fd >= 0) {
		if (cli->ev_active && event_del(&cli->ev) < 0)
			applog(LOG_WARNING, "TCP client event_del");
		cli->ev_active = false;
		close(cli->fd);
	}

	req_free(&cli->req);

	if (debugging)
		applog(LOG_INFO, "client %s ended", cli->addr_host);

	free(cli);
}

static bool cli_evt_dispose(struct client *cli, unsigned int events)
{
	/* if write queue is not empty, we should continue to get
	 * poll callbacks here until it is
	 */
	if (list_empty(&cli->write_q))
		cli_free(cli);

	return false;
}

static bool cli_evt_recycle(struct client *cli, unsigned int events)
{
	unsigned int slop;

	req_free(&cli->req);

	cli->hdr_start = NULL;
	cli->hdr_end = NULL;

	slop = cli_req_avail(cli);
	if (slop) {
		memmove(cli->req_buf, cli->req_ptr, slop);
		cli->req_used = slop;

		cli->state = evt_parse_hdr;
	} else {
		cli->req_used = 0;

		cli->state = evt_read_req;
	}
	cli->req_ptr = cli->req_buf;

	memset(&cli->req, 0, sizeof(cli->req));

	return true;
}

static void cli_writable(struct client *cli)
{
	int n_iov;
	struct client_write *tmp;
	ssize_t rc;
	struct iovec iov[CLI_MAX_WR_IOV];
	bool more_work;

restart:
	more_work = false;

	/* accumulate pending writes into iovec */
	n_iov = 0;
	list_for_each_entry(tmp, &cli->write_q, node) {
		if (n_iov == CLI_MAX_WR_IOV)
			break;
		/* bleh, struct iovec should declare iov_base const */
		iov[n_iov].iov_base = (void *) tmp->buf;
		iov[n_iov].iov_len = tmp->togo;
		n_iov++;
	}

	/* execute non-blocking write */
do_write:
	rc = writev(cli->fd, iov, n_iov);
	if (rc < 0) {
		if (errno == EINTR)
			goto do_write;
		if (errno != EAGAIN)
			goto err_out;
		return;
	}

	/* iterate through write queue, issuing completions based on
	 * amount of data written
	 */
	while (rc > 0) {
		int sz;

		/* get pointer to first record on list */
		tmp = list_entry(cli->write_q.next, struct client_write, node);

		/* mark data consumed by decreasing tmp->len */
		sz = (tmp->togo < rc) ? tmp->togo : rc;
		tmp->togo -= sz;
		tmp->buf += sz;
		rc -= sz;

		/* if tmp->len reaches zero, write is complete,
		 * call callback and clean up
		 */
		if (tmp->togo == 0)
			if (cli_write_free(cli, tmp, true))
				more_work = true;
	}

	if (more_work)
		goto restart;

	/* if we emptied the queue, clear write notification */
	if (list_empty(&cli->write_q)) {
		cli->writing = false;
		if (event_del(&cli->write_ev) < 0) {
			applog(LOG_WARNING, "cli_writable event_del");
			goto err_out;
		}
	}

	return;

err_out:
	cli->state = evt_dispose;
	cli_write_free_all(cli);
}

bool cli_write_start(struct client *cli)
{
	if (list_empty(&cli->write_q))
		return true;		/* loop, not poll */

	/* if write-poll already active, nothing further to do */
	if (cli->writing)
		return false;		/* poll wait */

	/* attempt optimistic write, in hopes of avoiding poll,
	 * or at least refill the write buffers so as to not
	 * get -immediately- called again by the kernel
	 */
	cli_writable(cli);
	if (list_empty(&cli->write_q)) {
		tabled_srv.stats.opt_write++;
		return true;		/* loop, not poll */
	}

	if (event_add(&cli->write_ev, NULL) < 0) {
		applog(LOG_WARNING, "cli_write event_add");
		return true;		/* loop, not poll */
	}

	cli->writing = true;

	return false;			/* poll wait */
}

int cli_writeq(struct client *cli, const void *buf, unsigned int buflen,
		     cli_write_func cb, void *cb_data)
{
	struct client_write *wr;

	if (!buf || !buflen)
		return -EINVAL;

	wr = calloc(1, sizeof(struct client_write));
	if (!wr)
		return -ENOMEM;

	wr->buf = buf;
	wr->togo = buflen;
	wr->length = buflen;
	wr->cb = cb;
	wr->cb_data = cb_data;
	list_add_tail(&wr->node, &cli->write_q);
	cli->write_cnt += buflen;

	return 0;
}

size_t cli_wqueued(struct client *cli)
{
	return cli->write_cnt;
}

static int cli_read(struct client *cli)
{
	ssize_t rc;

	/* read into remaining free space in buffer */
do_read:
	rc = read(cli->fd, cli->req_buf + cli->req_used,
		  CLI_REQ_BUF_SZ - cli->req_used);
	if (rc < 0) {
		if (errno == EINTR)
			goto do_read;
		if (errno == EAGAIN)
			return 0;
		return -errno;
	}

	cli->req_used += rc;

	/* if buffer is full, assume that data will continue
	 * to be received (by a malicious or broken client),
	 * so stop reading now and return an error.
	 *
	 * Therefore, it can be said that the maximum size of a
	 * request to this HTTP server is CLI_REQ_BUF_SZ-1.
	 */
	if (cli->req_used == CLI_REQ_BUF_SZ)
		return -ENOSPC;

	return 0;
}

bool cli_cb_free(struct client *cli, void *cb_data, bool done)
{
	free(cb_data);
	return false;
}

static int cli_write_list(struct client *cli, GList *list)
{
	int rc = 0;
	GList *tmp;

	tmp = list;
	while (tmp) {
		rc = cli_writeq(cli, tmp->data, strlen(tmp->data),
			        cli_cb_free, tmp->data);
		if (rc)
			goto out;

		tmp->data = NULL;
		tmp = tmp->next;
	}

out:
	__strlist_free(list);
	return rc;
}

bool cli_err(struct client *cli, enum errcode code)
{
	int rc;
	char timestr[50], *hdr = NULL, *content = NULL;

	applog(LOG_INFO, "client %s error %s",
	       cli->addr_host, err_info[code].code);

	content = g_markup_printf_escaped(
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<Error>\r\n"
"  <Code>%s</Code>\r\n"
"  <Message>%s</Message>\r\n"
"</Error>\r\n",
		     err_info[code].code,
		     err_info[code].msg);
	if (!content)
		return false;

	if (code == RedirectClient) {
		/*
		 * FIXME '*' for URI is bogus. We keep this until we know
		 * how to test this code path.
		 */
		rc = asprintf(&hdr,
			"HTTP/%d.%d %d x\r\n"
			"Content-Type: application/xml\r\n"
			"Content-Length: %zu\r\n"
			"Date: %s\r\n"
			"Connection: close\r\n"
			"Server: " PACKAGE_STRING "\r\n"
			"Location: %s\r\n"
			"\r\n",
			     cli->req.major,
			     cli->req.minor,
			     err_info[code].status,
			     strlen(content),
			     time2str(timestr, sizeof(timestr), time(NULL)),
			     "*");
		if (rc < 0) {
			free(content);
			return false;
		}
	} else {
		rc = asprintf(&hdr,
			"HTTP/%d.%d %d x\r\n"
			"Content-Type: application/xml\r\n"
			"Content-Length: %zu\r\n"
			"Date: %s\r\n"
			"Connection: close\r\n"
			"Server: " PACKAGE_STRING "\r\n"
			"\r\n",
			     cli->req.major,
			     cli->req.minor,
			     err_info[code].status,
			     strlen(content),
			     time2str(timestr, sizeof(timestr), time(NULL)));
		if (rc < 0) {
			free(content);
			return false;
		}
	}

	return cli_err_write(cli, hdr, content);
}

bool cli_err_write(struct client *cli, char *hdr, char *content)
{
	int rc;

	cli->state = evt_dispose;

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc)
		return true;
	rc = cli_writeq(cli, content, strlen(content), cli_cb_free, content);
	if (rc)
		return true;

	return cli_write_start(cli);
}

bool cli_resp(struct client *cli, int http_status, const char *content_type,
	      GList *content)
{
	int rc;
	char *hdr, timestr[50];
	bool rcb, cxn_close = !http11(&cli->req);

	if (asprintf(&hdr,
"HTTP/%d.%d %d x\r\n"
"Content-Type: %s\r\n"
"Content-Length: %zu\r\n"
"Date: %s\r\n"
"%s"
"Server: " PACKAGE_STRING "\r\n"
"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     http_status,
		     content_type,
		     strlist_len(content),
		     time2str(timestr, sizeof(timestr), time(NULL)),
		     cxn_close ? "Connection: close\r\n" : "") < 0) {
		__strlist_free(content);
		return false;
	}

	if (cxn_close)
		cli->state = evt_dispose;
	else
		cli->state = evt_recycle;

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc) {
		free(hdr);
		cli->state = evt_dispose;
		return true;
	}

	rc = cli_write_list(cli, content);
	if (rc) {
		cli->state = evt_dispose;
		return true;
	}

	rcb = cli_write_start(cli);

	if (cli->state == evt_recycle)
		return true;

	return rcb;
}

bool cli_resp_xml(struct client *cli, int http_status, GList *content)
{
	return cli_resp(cli, http_status, "application/xml", content);
}

bool cli_resp_html(struct client *cli, int http_status, GList *content)
{
	return cli_resp(cli, http_status, "text/html", content);
}

static bool cli_evt_http_req(struct client *cli, unsigned int events)
{
	struct http_req *req = &cli->req;
	char *host, *auth, *content_len_str;
	char *bucket = NULL;
	char *path = NULL;
	char *user = NULL;
	char *key = NULL;
	char *method = req->method;
	bool rcb, buck_in_path = false;
	bool expect_cont = false;
	enum errcode err;

	/*
 	 * We only start listen() when tdb elections are finished. So,
 	 * this can only trip if we go backwards from Master or Client,
	 * which should be impossible, but let's check anyway.
	 */
	if (!(tabled_srv.state_tdb == ST_TDB_MASTER ||
	      tabled_srv.state_tdb == ST_TDB_SLAVE)) {
		err = InternalError;
		goto err_out;
	}

	/* grab useful headers */
	host = req_hdr(req, "host");
	content_len_str = req_hdr(req, "content-length");
	auth = req_hdr(req, "authorization");
	if (req->major > 1 || req->minor > 0) {
		char *expect = req_hdr(req, "expect");
		if (expect && strcasestr(expect, "100-continue"))
			expect_cont = true;
	}

	if (!host)
		return cli_err(cli, InvalidArgument);

	/* attempt to obtain bucket name from Host */
	bucket = bucket_host(host, tabled_srv.ourhost);

	/* attempt to obtain bucket name from URI path */
	if (!bucket)
		buck_in_path = bucket_base(req->uri.path, req->uri.path_len,
					   &bucket, &path);
	else
		path = g_strndup(req->uri.path, req->uri.path_len);

	if (!path)
		path = strdup("/");
	key = pathtokey(path);

	if (debugging)
		applog(LOG_INFO,
		       "%s: method %s, path '%s', key '%s', bucket '%s'",
		       cli->addr_host, method, path, key, bucket);

	if (auth) {
		err = authcheck(&cli->req, buck_in_path? NULL: bucket, auth,
				&user);
		if (err)
			goto err_out;
	}

	/* no matter whether error or not, this is our next state.
	 * the main question is whether or not we will go immediately
	 * into it (return true) or wait for writes to complete (return
	 * false).
	 *
	 * the operations below may override this next-state setting,
	 * however.
	 */
	if (http11(req))
		cli->state = evt_recycle;
	else
		cli->state = evt_dispose;

	/*
	 * pre-operation checks
	 */

	if (bucket && !bucket_valid(bucket))
		rcb = cli_err(cli, InvalidBucketName);

	/*
	 * operations on objects
	 */
	else if (bucket && key && !strcmp(method, "HEAD"))
		rcb = object_get(cli, user, bucket, key, false);
	else if (bucket && key && !strcmp(method, "GET"))
		rcb = object_get(cli, user, bucket, key, true);
	else if (bucket && key && !strcmp(method, "PUT")) {
		long content_len;

		if (!content_len_str) {
			err = MissingContentLength;
			goto err_out;
		}
		if (tabled_srv.state_tdb != ST_TDB_MASTER) {
			err = RedirectClient;
			goto err_out;
		}

		content_len = atol(content_len_str);

		rcb = object_put(cli, user, bucket, key, content_len,
				 expect_cont);
	} else if (bucket && key && !strcmp(method, "DELETE")) {
		rcb = object_del(cli, user, bucket, key);
		if (tabled_srv.state_tdb != ST_TDB_MASTER) {
			err = RedirectClient;
			goto err_out;
		}
	}

	/*
	 * operations on buckets
	 */
	else if (bucket && !key && !strcmp(method, "GET")) {
		rcb = bucket_list(cli, user, bucket);
	}
	else if (bucket && !key && !strcmp(method, "PUT")) {
		if (!auth) {
			err = AccessDenied;
			goto err_out;
		}
		if (tabled_srv.state_tdb != ST_TDB_MASTER) {
			err = RedirectClient;
			goto err_out;
		}
		rcb = bucket_add(cli, user, bucket);
	}
	else if (bucket && !key && !strcmp(method, "DELETE")) {
		if (tabled_srv.state_tdb != ST_TDB_MASTER) {
			err = RedirectClient;
			goto err_out;
		}
		rcb = bucket_del(cli, user, bucket);
	}

	/*
	 * service-wide operations
	 */
	else if (!bucket && !key && !strcmp(method, "GET")) {
		if (!auth) {
			err = AccessDenied;
			goto err_out;
		}
		rcb = service_list(cli, user);
	}

	else {
		if (debugging)
			applog(LOG_INFO, "%s bucket %s through (auth %s)",
			   method, bucket, auth);
		rcb = cli_err(cli, InvalidURI);
	}

out:
	free(bucket);
	free(path);
	free(user);
	free(key);
	return rcb;

err_out:
	rcb = cli_err(cli, err);
	goto out;
}

int cli_req_avail(struct client *cli)
{
	int skip_len = cli->req_ptr - cli->req_buf;
	int search_len = cli->req_used - skip_len;

	return search_len;
}

static char *cli_req_eol(struct client *cli)
{
	/* find newline in unconsumed portion of buffer */
	return memchr(cli->req_ptr, '\n', cli_req_avail(cli));
}

static char *cli_req_line(struct client *cli)
{
	/* get start and end of line */
	char *buf_start = cli->req_ptr;
	char *buf_eol = cli_req_eol(cli);
	if (!buf_eol)
		return NULL;

	/* nul-terminate line, if found */
	*buf_eol = 0;
	cli->req_ptr = buf_eol + 1;

	/* chomp CR, if present */
	if (buf_eol != buf_start) {
		char *buf_cr = buf_eol - 1;
		if (*buf_cr == '\r')
			*buf_cr = 0;
	}

	/* return saved start-of-line */
	return buf_start;
}

static bool cli_hdr_flush(struct client *cli, bool *loop_state)
{
	char *tmp;
	enum errcode err_resp;

	if (!cli->hdr_start)
		return false;

	/* null terminate entire string (key+value) */
	*cli->hdr_end = 0;

	/* find end of key; ensure no whitespace in key */
	tmp = cli->hdr_start;
	while (*tmp) {
		if (isspace(*tmp)) {
			err_resp = InvalidArgument;
			goto err_out;
		}
		if (*tmp == ':')
			break;
		tmp++;
	}
	if (*tmp != ':') {
		err_resp = InvalidArgument;
		goto err_out;
	}

	/* null terminate key */
	*tmp = 0;

	/* add to list of headers */
	if (req_hdr_push(&cli->req, cli->hdr_start, tmp + 1)) {
		err_resp = InvalidArgument;
		goto err_out;
	}

	/* reset accumulation state */
	cli->hdr_start = NULL;
	cli->hdr_end = NULL;

	return false;

err_out:
	*loop_state = cli_err(cli, err_resp);
	return true;
}

static bool cli_evt_parse_hdr(struct client *cli, unsigned int events)
{
	char *buf, *buf_eol;
	bool eoh = false;

	/* get pointer to end-of-line */
	buf_eol = cli_req_eol(cli);
	if (!buf_eol) {
		cli->state = evt_read_hdr;
		return false;
	}

	/* mark data as consumed */
	buf = cli->req_ptr;
	cli->req_ptr = buf_eol + 1;

	/* convert newline into spaces, for continued header lines */
	*buf_eol = ' ';

	/* chomp CR, if present */
	if (buf_eol != buf) {
		char *buf_cr = buf_eol - 1;
		if (*buf_cr == '\r') {
			*buf_cr = ' ';
			buf_eol--;
		}
	}

	/* if beginning of line and buf_eol (beginning of \r\n) are
	 * the same, its a blank line, signalling end of headers
	 */
	if (buf == buf_eol)
		eoh = true;

	/* check need to flush accumulated header data */
	if (eoh || (!isspace(buf[0]))) {
		bool sent_resp, loop;

		sent_resp = cli_hdr_flush(cli, &loop);
		if (sent_resp)
			return loop;
	}

	/* if we have reached end of headers, deliver HTTP request */
	if (eoh) {
		cli->state = evt_http_req;
		return true;
	}

	/* otherwise, continue accumulating header data */
	if (!cli->hdr_start)
		cli->hdr_start = buf;
	cli->hdr_end = buf_eol;

	return true;
}

static bool cli_evt_read_hdr(struct client *cli, unsigned int events)
{
	int rc = cli_read(cli);
	if (rc < 0) {
		if (rc == -ENOSPC)
			return cli_err(cli, InvalidArgument);

		cli->state = evt_dispose;
	} else
		cli->state = evt_parse_hdr;

	return true;
}

static bool cli_evt_parse_req(struct client *cli, unsigned int events)
{
	char *sp1, *sp2, *buf;
	enum errcode err_resp;
	int len;

	/* get pointer to nul-terminated line received */
	buf = cli_req_line(cli);
	if (!buf) {
		cli->state = evt_read_req;
		return false;
	}

	len = strlen(buf);

	/* locate the first and second spaces, additionally ensuring
	 * that the first and second tokens are non-empty
	 */
	if (*buf == ' ') {
		err_resp = InvalidArgument;
		goto err_out;
	}
	sp1 = strchr(buf, ' ');
	if ((!sp1) || (*(sp1 + 1) == ' ')) {
		err_resp = InvalidArgument;
		goto err_out;
	}
	sp2 = strchr(sp1 + 1, ' ');
	if (!sp2) {
		err_resp = InvalidArgument;
		goto err_out;
	}

	/* convert the two spaces to nuls, thereby creating three
	 * nul-terminated strings for the three pieces we desire
	 */
	*sp1 = 0;
	*sp2 = 0;

	/* method is the first token, at the beginning of the buffer */
	cli->req.method = buf;
	strup(cli->req.method);

	/* URI is the second token, immediately following the first space */
	if (!uri_parse(&cli->req.uri, sp1 + 1)) {
		err_resp = InvalidURI;
		goto err_out;
	}

	cli->req.orig_path = g_strndup(cli->req.uri.path, cli->req.uri.path_len);

	cli->req.uri.path_len = field_unescape(cli->req.uri.path,
					       cli->req.uri.path_len);

	/* HTTP version is the final token, following second space */
	if ((sscanf(sp2 + 1, "HTTP/%d.%d", &cli->req.major, &cli->req.minor) != 2) ||
	    (cli->req.major != 1) || (cli->req.minor < 0) || (cli->req.minor > 1)) {
		err_resp = InvalidArgument;
		goto err_out;
	}

	cli->state = evt_parse_hdr;
	return true;

err_out:
	return cli_err(cli, err_resp);
}

static bool cli_evt_read_req(struct client *cli, unsigned int events)
{
	int rc = cli_read(cli);
	if (rc < 0) {
		if (rc == -ENOSPC)
			return cli_err(cli, InvalidArgument);

		cli->state = evt_dispose;
	} else
		cli->state = evt_parse_req;

	return true;
}

static cli_evt_func evt_funcs_server[] = {
	[evt_read_req]		= cli_evt_read_req,
	[evt_parse_req]		= cli_evt_parse_req,
	[evt_read_hdr]		= cli_evt_read_hdr,
	[evt_parse_hdr]		= cli_evt_parse_hdr,
	[evt_http_req]		= cli_evt_http_req,
	[evt_http_data_in]	= cli_evt_http_data_in,
	[evt_dispose]		= cli_evt_dispose,
	[evt_recycle]		= cli_evt_recycle,
};

static cli_evt_func evt_funcs_status[] = {
	[evt_read_req]		= cli_evt_read_req,
	[evt_parse_req]		= cli_evt_parse_req,
	[evt_read_hdr]		= cli_evt_read_hdr,
	[evt_parse_hdr]		= cli_evt_parse_hdr,
	[evt_http_req]		= stat_evt_http_req,
	[evt_http_data_in]	= cli_evt_http_data_in,
	[evt_dispose]		= cli_evt_dispose,
	[evt_recycle]		= cli_evt_recycle,
};

static struct client *cli_alloc(bool is_status)
{
	struct client *cli;

	/* alloc and init client info */
	cli = calloc(1, sizeof(*cli));
	if (!cli) {
		applog(LOG_ERR, "out of memory");
		return NULL;
	}

	cli->state = evt_read_req;
	cli->evt_table = is_status? evt_funcs_status: evt_funcs_server;
	INIT_LIST_HEAD(&cli->write_q);
	INIT_LIST_HEAD(&cli->out_ch);
	cli->req_ptr = cli->req_buf;
	memset(&cli->req, 0, sizeof(cli->req) - sizeof(cli->req.hdr));

	return cli;
}

static void tcp_cli_wr_event(int fd, short events, void *userdata)
{
	struct client *cli = userdata;

	cli_writable(cli);
}

static void tcp_cli_event(int fd, short events, void *userdata)
{
	struct client *cli = userdata;
	bool loop;

	do {
		loop = cli->evt_table[cli->state](cli, events);
	} while (loop);
}

static void tcp_srv_event(int fd, short events, void *userdata)
{
	struct server_socket *sock = userdata;
	socklen_t addrlen = sizeof(struct sockaddr_in6);
	struct client *cli;
	char host[64];
	int on = 1;

	/* alloc and init client info */
	cli = cli_alloc(sock->is_status);
	if (!cli) {
		struct sockaddr_in6 a;
		int cli_fd = accept(sock->fd, (struct sockaddr *) &a, &addrlen);
		close(cli_fd);
		return;
	}

	/* receive TCP connection from kernel */
	cli->fd = accept(sock->fd, (struct sockaddr *) &cli->addr, &addrlen);
	if (cli->fd < 0) {
		applogerr("tcp accept");
		goto err_out;
	}

	tabled_srv.stats.tcp_accept++;

	event_set(&cli->ev, cli->fd, EV_READ | EV_PERSIST, tcp_cli_event, cli);
	event_set(&cli->write_ev, cli->fd, EV_WRITE | EV_PERSIST,
		  tcp_cli_wr_event, cli);

	/* mark non-blocking, for upcoming poll use */
	if (fsetflags("tcp client", cli->fd, O_NONBLOCK) < 0)
		goto err_out_fd;

	/* disable delay of small output packets */
	if (setsockopt(cli->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
		applog(LOG_WARNING, "TCP_NODELAY failed: %s",
		       strerror(errno));

	/* add to poll watchlist */
	if (event_add(&cli->ev, NULL) < 0) {
		applog(LOG_WARNING, "tcp client event_add");
		goto err_out_fd;
	}
	cli->ev_active = true;

	/* pretty-print incoming cxn info */
	memset(host, 0, sizeof(host));
	getnameinfo((struct sockaddr *) &cli->addr, addrlen,
		    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	host[sizeof(host) - 1] = 0;
	applog(LOG_INFO, "client %s connected", host);

	strcpy(cli->addr_host, host);

	return;

err_out_fd:
	close(cli->fd);
err_out:
	free(cli);
}

static void add_chkpt_timer(void)
{
	struct timeval tv = { TABLED_CHKPT_SEC, 0 };

	if (evtimer_add(&tabled_srv.chkpt_timer, &tv) < 0)
		applog(LOG_WARNING, "unable to add checkpoint timer");
}

static void tdb_checkpoint(int fd, short events, void *userdata)
{
	DB_ENV *dbenv = tdb.env;
	int rc;

	if (debugging)
		applog(LOG_INFO, "db4 checkpoint");

	/* flush logs to db, if log files >= 1MB */
	rc = dbenv->txn_checkpoint(dbenv, 1024, 0, 0);
	if (rc)
		dbenv->err(dbenv, rc, "txn_checkpoint");

	/* reactivate timer, to call ourselves again */
	add_chkpt_timer();
}

static void tdb_state_cb(enum db_event event)
{
	unsigned char cmd;

	switch (event) {
	case TDB_EV_ELECTED:
		/*
		 * Safe to stop ignoring bogus client indication,
		 * so unmute us by advancing the state.
		 */
		if (tabled_srv.state_tdb == ST_TDB_OPEN)
			tabled_srv.state_tdb = ST_TDB_ACTIVE;
		break;
	case TDB_EV_CLIENT:
	case TDB_EV_MASTER:
		/*
		 * This callback runs on the context of the replication
		 * manager thread, and calling any of our functions thus
		 * turns our program into a multi-threaded one. Instead
		 * we signal the main thread to do the processing.
		 */
		if (tabled_srv.state_tdb != ST_TDB_INIT &&
		    tabled_srv.state_tdb != ST_TDB_OPEN) {
			if (event == TDB_EV_MASTER)
				cmd = TT_CMD_TDBST_MASTER;
			else
				cmd = TT_CMD_TDBST_SLAVE;
			write(tabled_srv.ev_pipe[1], &cmd, 1);
		}
		break;
	default:
		applog(LOG_WARNING, "API confusion with TDB, event 0x%x", event);
		tabled_srv.state_tdb = ST_TDB_OPEN;  /* wrong, stub for now */
	}
}

/*
 * Due to the way storage_node management is tightly woven into the
 * server, the management of nodes is not in storage.c, which deals
 * with the interface to Chunk and little more.
 *
 * We don't even bother with registering this callback, just call it by name. 
 *
 * The return value is used to re-arm storage rescan mechanism.
 */
int stor_update_cb(void)
{
	int num_up;
	struct storage_node *stn;
	unsigned int env_flags;

	if (debugging)
		applog(LOG_DEBUG, "Know of potential %d storage node(s)",
		       tabled_srv.num_stor);
	num_up = 0;
	list_for_each_entry(stn, &tabled_srv.all_stor, all_link) {
		if (stor_node_check(stn) == 0) {
			if (debugging)
				applog(LOG_DEBUG, " NID %u is up", stn->id);
			num_up++;
			stn->up = true;
			stn->last_up = time(NULL);
		} else {
			if (stn->last_up != 0 &&
			    time(NULL) >= stn->last_up + CHUNK_REBOOT_TIME) {
				applog(LOG_INFO, " NID %u went down", stn->id);
			}
		}
	}

	if (num_up < 1) {
		applog(LOG_INFO, "No active storage node(s), waiting");
		return num_up;
	}
	if (debugging)
		applog(LOG_DEBUG, "Active storage node(s): %d", num_up);

	/*
	 * We initiate operations even if there's no redundancy in order
	 * to permit bootstrapping and build-time self-checking.
	 */
	if (tabled_srv.state_tdb == ST_TDB_INIT) {
		tabled_srv.state_tdb = ST_TDB_OPEN;

		env_flags = DB_RECOVER | DB_CREATE | DB_THREAD;
		if (tdb_init(&tdb, tabled_srv.tdb_dir, NULL,
			     env_flags, "tabled", true,
			     tabled_srv.rep_remotes,
			     tabled_srv.ourhost, tabled_srv.rep_port,
			     tdb_state_cb)) {
			tabled_srv.state_tdb = ST_TDB_INIT;
			applog(LOG_ERR, "Failed to open TDB, limping");
		}
	} else if (tabled_srv.state_tdb == ST_TDB_MASTER) {
		/*
		 * FIXME This is where we should process redundancy decreases.
		 */
		;
	}
	return num_up;
}

static int net_open_socket(int addr_fam, int sock_type, int sock_prot,
			   int addr_len, void *addr_ptr, bool is_status)
{
	struct server_socket *sock;
	int fd, on;
	int rc;

	fd = socket(addr_fam, sock_type, sock_prot);
	if (fd < 0) {
		rc = errno;
		applogerr("tcp socket");
		return -rc;
	}

	on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		rc = errno;
		applogerr("setsockopt(SO_REUSEADDR)");
		close(fd);
		return -rc;
	}

	if (bind(fd, addr_ptr, addr_len) < 0) {
		rc = errno;
		applogerr("tcp bind");
		close(fd);
		return -rc;
	}

	rc = fsetflags("tcp server", fd, O_NONBLOCK);
	if (rc) {
		close(fd);
		return rc;
	}

	sock = calloc(1, sizeof(*sock));
	if (!sock) {
		close(fd);
		return -ENOMEM;
	}

	sock->fd = fd;
	sock->is_status = is_status;

	event_set(&sock->ev, fd, EV_READ | EV_PERSIST, tcp_srv_event, sock);

	tabled_srv.sockets = g_list_append(tabled_srv.sockets, sock);
	return fd;
}

static int net_write_port(const char *port_file,
			  const char *host, const char *port)
{
	FILE *portf;
	int rc;

	portf = fopen(port_file, "w");
	if (portf == NULL) {
		rc = errno;
		applog(LOG_INFO, "Cannot create port file %s: %s",
		       port_file, strerror(rc));
		return -rc;
	}
	fprintf(portf, "%s:%s\n", tabled_srv.ourhost, port);
	fclose(portf);
	return 0;
}

/*
 * This, annoyingly, has to have a side effect: it fills out tabled_srv.port
 * so that we can later export it into CLD.
 */
static int net_open_any(void)
{
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	int fd4, fd6;
	socklen_t addr_len;
	unsigned short port;
	int rc;

	port = 0;

	/* Thanks to Linux, IPv6 must be bound first. */
	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	memcpy(&addr6.sin6_addr, &in6addr_any, sizeof(struct in6_addr));
	fd6 = net_open_socket(AF_INET6, SOCK_STREAM, 0, sizeof(addr6), &addr6,
			      false);

	if (fd6 >= 0) {
		addr_len = sizeof(addr6);
		if (getsockname(fd6, &addr6, &addr_len) != 0) {
			rc = errno;
			applog(LOG_ERR, "getsockname failed: %s", strerror(rc));
			return -rc;
		}
		port = ntohs(addr6.sin6_port);
	}

	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_addr.s_addr = htonl(INADDR_ANY);
	/* If IPv6 worked, we must use the same port number for IPv4 */
	if (port)
		addr4.sin_port = port;
	fd4 = net_open_socket(AF_INET, SOCK_STREAM, 0, sizeof(addr4), &addr4,
			      false);

	if (!port) {
		if (fd4 < 0)
			return fd4;

		addr_len = sizeof(addr4);
		if (getsockname(fd4, &addr4, &addr_len) != 0) {
			rc = errno;
			applog(LOG_ERR, "getsockname failed: %s", strerror(rc));
			return -rc;
		}
		port = ntohs(addr4.sin_port);
	}

	applog(LOG_INFO, "Listening on port %u", port);

	rc = asprintf(&tabled_srv.port, "%u", port);
	if (rc < 0) {
		applog(LOG_ERR, "OOM");
		return -ENOMEM;
	}

	return 0;
}

static int net_open_known(const char *portstr, bool is_status)
{
	int ipv6_found;
	int rc;
	struct addrinfo hints, *res, *res0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(NULL, portstr, &hints, &res0);
	if (rc) {
		applog(LOG_ERR, "getaddrinfo(*:%s) failed: %s",
		       portstr, gai_strerror(rc));
		rc = -EINVAL;
		goto err_addr;
	}

	/*
	 * We rely on getaddrinfo to discover if the box supports IPv6.
	 * Much easier to sanitize its output than to try to figure what
	 * to put into ai_family.
	 *
	 * These acrobatics are required on Linux because we should bind
	 * to ::0 if we want to listen to both ::0 and 0.0.0.0. Else, we
	 * may bind to 0.0.0.0 by accident (depending on order getaddrinfo
	 * returns them), then bind(::0) fails and we only listen to IPv4.
	 */
	ipv6_found = 0;
	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family == PF_INET6)
			ipv6_found = 1;
	}

	for (res = res0; res; res = res->ai_next) {
		char listen_host[65], listen_serv[65];

		if (ipv6_found && res->ai_family == PF_INET)
			continue;

		rc = net_open_socket(res->ai_family, res->ai_socktype,
				     res->ai_protocol, 
				     res->ai_addrlen, res->ai_addr, is_status);
		if (rc < 0)
			goto err_out;
		getnameinfo(res->ai_addr, res->ai_addrlen,
			    listen_host, sizeof(listen_host),
			    listen_serv, sizeof(listen_serv),
			    NI_NUMERICHOST | NI_NUMERICSERV);

		applog(LOG_INFO, "Listening on %s port %s",
		       listen_host, listen_serv);
	}

	freeaddrinfo(res0);
	return 0;

err_out:
	freeaddrinfo(res0);
err_addr:
	return rc;
}

static int net_open(void)
{
	int rc;

	if (!strcmp(tabled_srv.port, "auto"))
		rc = net_open_any();
	else
		rc = net_open_known(tabled_srv.port, false);
	if (rc)
		return rc;

	if (tabled_srv.status_port)
		net_open_known(tabled_srv.status_port, true);

	if (tabled_srv.port_file) {
		rc = net_write_port(tabled_srv.port_file,
				    tabled_srv.ourhost, tabled_srv.port);
		if (rc)
			return rc;
	}

	tabled_srv.state_net = ST_NET_OPEN;
	return 0;
}

static void net_listen(void)
{
	GList *tmp;

	if (tabled_srv.state_net != ST_NET_OPEN)
		return;

	for (tmp = tabled_srv.sockets; tmp; tmp = tmp->next) {
		struct server_socket *sock = tmp->data;

		if (listen(sock->fd, 100) < 0) {
			applog(LOG_WARNING, "tcp socket listen: %s",
			       strerror(errno));
			continue;
		}

		if (event_add(&sock->ev, NULL) < 0) {
			applog(LOG_WARNING, "tcp socket event_add");
			continue;
		}
	}

	tabled_srv.state_net = ST_NET_LISTEN;
}

static void compile_patterns(void)
{
	int i;
	const char *error = NULL;
	int erroffset = -1;
	pcre *re;

	for (i = 0; i < ARRAY_SIZE(patterns); i++) {
		re = pcre_compile(patterns[i].str, patterns[i].options,
				  &error, &erroffset, NULL);
		if (!re) {
			fprintf(stderr, "BUG: pattern compile %d failed", i);
			exit(1);
		}

		patterns[i].re = re;
	}
}

static void tdb_state_process(enum st_tdb new_state)
{
	unsigned int db_flags;

	if (debugging)
		applog(LOG_DEBUG, "TDB state > %s", state_name_tdb[new_state]);
	if ((new_state == ST_TDB_MASTER || new_state == ST_TDB_SLAVE) &&
	    tabled_srv.state_tdb == ST_TDB_ACTIVE) {

		db_flags = DB_CREATE | DB_THREAD;
		if (tdb_up(&tdb, db_flags))
			return;

		if (objid_init(&tabled_srv.object_count, &tdb)) {
			tdb_down(&tdb);
			return;
		}
		add_chkpt_timer();
		rep_start();
		net_listen();
	}
}

static void internal_event(int fd, short events, void *userdata)
{
	unsigned char cmd;
	ssize_t rrc;

	rrc = read(tabled_srv.ev_pipe[0], &cmd, 1);
	if (rrc < 0) {
		applog(LOG_WARNING, "pipe read error: %s", strerror(errno));
		abort();
	}
	if (rrc < 1) {
		applog(LOG_WARNING, "pipe short read");
		abort();
	}

	switch (cmd) {
	case TT_CMD_DUMP:
		stats_dump();
		break;

	case TT_CMD_TDBST_MASTER:
		if (tabled_srv.state_tdb != ST_TDB_MASTER) {
			tdb_state_process(ST_TDB_MASTER);
			tabled_srv.state_tdb = ST_TDB_MASTER;
		}
		break;

	case TT_CMD_TDBST_SLAVE:
		if (tabled_srv.state_tdb != ST_TDB_SLAVE) {
			tdb_state_process(ST_TDB_SLAVE);
			tabled_srv.state_tdb = ST_TDB_SLAVE;
		}
		break;

	default:
		applog(LOG_WARNING, "%s BUG: command 0x%x", __func__, cmd);
		break;
	}
}

int main (int argc, char *argv[])
{
	error_t aprc;
	int rc = 1;
	struct event_base *event_base_rep;

	INIT_LIST_HEAD(&tabled_srv.all_stor);
	tabled_srv.state_tdb = ST_TDB_INIT;

	/* isspace() and strcasecmp() consistency requires this */
	setlocale(LC_ALL, "C");

	compile_patterns();

	g_thread_init(NULL);
	tabled_srv.bigmutex = g_mutex_new();

	SSL_library_init();
	SSL_load_error_strings();

	stc_init();

	cld_init();

	/*
	 * parse command line
	 */

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	/*
	 * open applog (currently does not depend on command line, but still)
	 */
	if (use_syslog)
		openlog(PROGRAM_NAME, LOG_PID, LOG_LOCAL3);
	if (debugging)
		applog(LOG_INFO, "Verbose debug output enabled");
	cldu_hail_log.verbose = debugging;

	/*
	 * now we can parse the configuration, errors to applog
	 */
	read_config();
	if (!tabled_srv.ourhost)
		tabled_srv.ourhost = get_hostname();
	else if (debugging)
		applog(LOG_INFO, "Forcing local hostname to %s",
		       tabled_srv.ourhost);

	/*
	 * background outselves, write PID file ASAP
	 */

	if ((!(tabled_srv.flags & SFL_FOREGROUND)) && (daemon(1, !use_syslog) < 0)) {
		applogerr("daemon");
		goto err_out;
	}

	rc = write_pid_file(tabled_srv.pid_file);
	if (rc < 0)
		goto err_out;
	tabled_srv.pid_fd = rc;

	/*
	 * properly capture TERM and other signals
	 */
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, term_signal);
	signal(SIGTERM, term_signal);
	signal(SIGUSR1, stats_signal);

	/*
	 * Prepare the libevent paraphernalia
	 */
	tabled_srv.evbase_main = event_init();
	event_base_rep = event_base_new();
	evtimer_set(&tabled_srv.chkpt_timer, tdb_checkpoint, NULL);

	/* set up internal communication pipe */
	if (pipe(tabled_srv.ev_pipe) < 0) {
		applogerr("pipe");
		goto err_evpipe;
	}
	event_set(&tabled_srv.pevt, tabled_srv.ev_pipe[0], EV_READ | EV_PERSIST,
		  internal_event, NULL);
	if (event_add(&tabled_srv.pevt, NULL) < 0) {
		applog(LOG_WARNING, "pevt event_add");
		goto err_pevt;
	}

	/* set up server networking */
	rc = net_open();
	if (rc)
		goto err_out_net;

	if (cld_begin(tabled_srv.ourhost, tabled_srv.group) != 0) {
		rc = 1;
		goto err_cld_session;
	}

	rep_init(event_base_rep);

	applog(LOG_INFO, "initialized (%s)",
	   (tabled_srv.flags & SFL_FOREGROUND)? "fg": "bg");

	while (server_running)
		event_dispatch();

	applog(LOG_INFO, "shutting down");

	rc = 0;

	cld_end();
err_cld_session:
	/* net_close(); */
err_out_net:
	if (tabled_srv.state_tdb == ST_TDB_MASTER ||
	    tabled_srv.state_tdb == ST_TDB_SLAVE) {
		tdb_down(&tdb);
		tdb_fini(&tdb);
	} else if (tabled_srv.state_tdb == ST_TDB_OPEN ||
		   tabled_srv.state_tdb == ST_TDB_ACTIVE) {
		tdb_fini(&tdb);
	}
/* err_tdb_init: */
err_pevt:
	close(tabled_srv.ev_pipe[0]);
	close(tabled_srv.ev_pipe[1]);
err_evpipe:
	unlink(tabled_srv.pid_file);
	close(tabled_srv.pid_fd);
err_out:
	closelog();
	return rc;
}

