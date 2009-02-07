
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <signal.h>
#include <locale.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <syslog.h>
#include <argp.h>
#include <errno.h>
#include <time.h>
#include <pcre.h>
#include <sys/types.h>
#include <dirent.h>
#include <glib.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <elist.h>
#include "tabled.h"

#define PROGRAM_NAME "tabled"

#define MY_ENDPOINT "pretzel.yyz.us"
#define TABLED_DEF_PORT "8080"

const char *argp_program_version = PACKAGE_VERSION;

enum {
	TABLED_EPOLL_INIT_SIZE	= 200,		/* passed to epoll_create(2) */
	TABLED_EPOLL_MAX_EVT	= 100,		/* max events per poll */

	CLI_MAX_WR_IOV		= 32,		/* max iov per writev(2) */

	SFL_FOREGROUND		= (1 << 0),	/* run in foreground */
};

static struct argp_option options[] = {
	{ "data", 'd', "DIRECTORY", 0,
	  "Store data in DIRECTORY" },
	{ "debug", 'D', NULL, 0,
	  "Enable debug output" },
	{ "foreground", 'F', NULL, 0,
	  "Run in foreground, do not fork" },
	{ "port", 'p', "PORT", 0,
	  "bind to port PORT" },
	{ "pid", 'P', "FILE", 0,
	  "Write daemon process id to FILE" },
	{ "tdb", 't', "DIRECTORY", 0,
	  "Store TDB metadata in DIRECTORY" },
	{ }
};

static const char doc[] =
PROGRAM_NAME " - distributed table daemon";


static error_t parse_opt (int key, char *arg, struct argp_state *state);


static const struct argp argp = { options, parse_opt, NULL, doc };

static bool server_running = true;
static bool dump_stats;
uint64_t counter;
int debugging = 0;

struct server tabled_srv = {
	.data_dir		= "/spare/tmp/tabled/lib",
	.tdb_dir		= "/spare/tmp/tabled/lib/tdb",
	.pid_file		= "/spare/tmp/tabled/run/tabled.pid",
	.port			= TABLED_DEF_PORT,
};

struct compiled_pat patterns[] = {
	[pat_bucket_name] =
	{ "^\\w+$", 0, },

	[pat_bucket_host] =
	{ "^\\s*(\\w+)\\.(\\w.*)$", 0, },

	[pat_bucket_path] =
	{ "^/(\\w+)(.*)$", 0, },

	[pat_auth] =
	{ "^AWS (\\w+):(\\S+)", 0, },
};

static struct {
	const char	*code;
	int		status;
	const char	*msg;
} err_info[] = {
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
	case 'd':
		tabled_srv.data_dir = arg;
		break;
	case 'D':
		debugging = 1;
		break;
	case 'F':
		tabled_srv.flags |= SFL_FOREGROUND;
		break;
	case 'p':
		if (atoi(arg) > 0 && atoi(arg) < 65536)
			tabled_srv.port = arg;
		else {
			fprintf(stderr, "invalid port %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'P':
		tabled_srv.pid_file = arg;
		break;
	case 't':
		tabled_srv.tdb_dir = arg;
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

static void term_signal(int signal)
{
	server_running = false;
}

static void stats_signal(int signal)
{
	dump_stats = true;
}

#define X(stat) \
	syslog(LOG_INFO, "STAT %s %lu", #stat, tabled_srv.stats.stat)

static void log_stats(void)
{
	X(poll);
	X(event);
	X(tcp_accept);
	X(max_evt);
	X(opt_write);
}

#undef X

static bool cli_write_free(struct client *cli, struct client_write *tmp,
			   bool done)
{
	bool rcb = false;

	if (tmp->cb)
		rcb = tmp->cb(cli, tmp, done);
	list_del(&tmp->node);
	free(tmp);

	return rcb;
}

static void cli_free(struct client *cli)
{
	struct client_write *wr, *tmp;

	list_for_each_entry_safe(wr, tmp, &cli->write_q, node) {
		cli_write_free(cli, wr, false);
	}

	cli_out_end(cli);
	cli_in_end(cli);

	/* clean up network socket */
	if (cli->fd >= 0) {
		if (epoll_ctl(tabled_srv.epoll_fd, EPOLL_CTL_DEL,
			      cli->fd, NULL) < 0)
			syslogerr("TCP client epoll_ctl(EPOLL_CTL_DEL)");
		close(cli->fd);
	}

	req_free(&cli->req);

	if (debugging)
		syslog(LOG_DEBUG, "client %s ended", cli->addr_host);

	free(cli);
}

static struct client *cli_alloc(void)
{
	struct client *cli;

	/* alloc and init client info */
	cli = calloc(1, sizeof(*cli));
	if (!cli) {
		syslog(LOG_ERR, "out of memory");
		return NULL;
	}

	cli->state = evt_read_req;
	cli->poll.poll_type = spt_tcp_cli;
	cli->poll.u.cli = cli;
	cli->evt.events = EPOLLIN | EPOLLHUP;
	cli->evt.data.ptr = &cli->poll;
	INIT_LIST_HEAD(&cli->write_q);
	cli->req_ptr = cli->req_buf;
	cli->out_fd = -1;
	cli->in_fd = -1;
	memset(&cli->req, 0, sizeof(cli->req) - sizeof(cli->req.hdr));

	return cli;
}

static bool cli_evt_dispose(struct client *cli, unsigned int events)
{
	/* if write queue is not empty, we should continue to get
	 * epoll callbacks here until it is
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
	unsigned int n_iov = 0;
	struct client_write *tmp;
	ssize_t rc;
	struct iovec iov[CLI_MAX_WR_IOV];
	bool more_work;

restart:
	more_work = false;

	/* accumulate pending writes into iovec */
	list_for_each_entry(tmp, &cli->write_q, node) {
		/* bleh, struct iovec should declare iov_base const */
		iov[n_iov].iov_base = (void *) tmp->buf;
		iov[n_iov].iov_len = tmp->len;
		n_iov++;
		if (n_iov == CLI_MAX_WR_IOV)
			break;
	}

	/* execute non-blocking write */
do_write:
	rc = writev(cli->fd, iov, n_iov);
	if (rc < 0) {
		if (errno == EINTR)
			goto do_write;
		if (errno != EAGAIN)
			cli->state = evt_dispose;
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
		sz = (tmp->len < rc) ? tmp->len : rc;
		tmp->len -= sz;
		rc -= sz;

		/* if tmp->len reaches zero, write is complete,
		 * call callback and clean up
		 */
		if (tmp->len == 0)
			if (cli_write_free(cli, tmp, true))
				more_work = true;
	}

	if (more_work)
		goto restart;

	/* if we emptied the queue, clear write notification */
	if (list_empty(&cli->write_q)) {
		cli->evt.events &= ~EPOLLOUT;
		int rrc = epoll_ctl(tabled_srv.epoll_fd, EPOLL_CTL_MOD,
				    cli->fd, &cli->evt);
		if (rrc < 0) {
			syslogerr("cli_writable epoll_ctl(EPOLL_CTL_MOD)");
			cli->state = evt_dispose;
		}
	}
}

bool cli_write_start(struct client *cli)
{
	int rc;

	if (list_empty(&cli->write_q))
		return true;		/* loop, not epoll */

	/* if EPOLLOUT already active, nothing further to do */
	if (cli->evt.events & EPOLLOUT)
		return false;		/* epoll wait */

	/* attempt optimistic write, in hopes of avoiding epoll,
	 * or at least refill the write buffers so as to not
	 * get -immediately- called again by the kernel
	 */
	cli_writable(cli);
	if (list_empty(&cli->write_q)) {
		tabled_srv.stats.opt_write++;
		return true;		/* loop, not epoll */
	}

	cli->evt.events |= EPOLLOUT;

	rc = epoll_ctl(tabled_srv.epoll_fd, EPOLL_CTL_MOD, cli->fd, &cli->evt);
	if (rc < 0) {
		syslogerr("cli_write epoll_ctl(EPOLL_CTL_MOD)");
		return true;		/* loop, not epoll */
	}

	return false;			/* epoll wait */
}

int cli_writeq(struct client *cli, const void *buf, unsigned int buflen,
		     cli_write_func cb, void *cb_data)
{
	struct client_write *wr;

	if (!buf || !buflen)
		return -EINVAL;

	wr = malloc(sizeof(struct client_write));
	if (!wr)
		return -ENOMEM;

	wr->buf = buf;
	wr->len = buflen;
	wr->cb = cb;
	wr->cb_data = cb_data;
	list_add_tail(&wr->node, &cli->write_q);

	return 0;
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

bool cli_cb_free(struct client *cli, struct client_write *wr,
			bool done)
{
	free(wr->cb_data);

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

	syslog(LOG_INFO, "client %s error %s",
	       cli->addr_host, err_info[code].code);

	if (asprintf(&content,
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<Error>\r\n"
"  <Code>%s</Code>\r\n"
"  <Message>%s</Message>\r\n"
"</Error>\r\n",
		     err_info[code].code,
		     err_info[code].msg) < 0)
		return false;

	if (asprintf(&hdr,
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
		     time2str(timestr, time(NULL))) < 0) {
		free(content);
		return false;
	}

	cli->state = evt_dispose;

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc)
		return true;
	rc = cli_writeq(cli, content, strlen(content), cli_cb_free, content);
	if (rc)
		return true;

	return cli_write_start(cli);
}

bool cli_resp_xml(struct client *cli, int http_status,
			 GList *content)
{
	int rc;
	char *hdr, timestr[50];
	bool rcb, cxn_close = !http11(&cli->req);

	if (asprintf(&hdr,
"HTTP/%d.%d %d x\r\n"
"Content-Type: application/xml\r\n"
"Content-Length: %zu\r\n"
"Date: %s\r\n"
"%s"
"Server: " PACKAGE_STRING "\r\n"
"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     http_status,
		     strlist_len(content),
		     time2str(timestr, time(NULL)),
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

static bool cli_evt_http_req(struct client *cli, unsigned int events)
{
	int captured[16];
	struct http_req *req = &cli->req;
	char *host, *auth, *content_len_str;
	char *bucket = NULL;
	char *path = NULL;
	char *user = NULL;
	char *key = NULL;
	char *method = req->method;
	bool rcb, pslash, buck_in_path = false;
	bool expect_cont = false;
	enum errcode err;

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
	if (pcre_exec(patterns[pat_bucket_host].re, NULL,
		      host, strlen(host), 0, 0, captured, 16) == 3) {
		if ((strlen(MY_ENDPOINT) == (captured[5] - captured[4])) &&
		    (!memcmp(MY_ENDPOINT, host + captured[4],
		    	     strlen(MY_ENDPOINT)))) {
			bucket = strndup(host + captured[2],
					 captured[3] - captured[2]);
			path = strndup(req->uri.path, req->uri.path_len);
		}
	}

	/* attempt to obtain bucket name from URI path */
	if (!bucket && pcre_exec(patterns[pat_bucket_path].re, NULL,
			   req->uri.path, req->uri.path_len,
			   0, 0, captured, 16) == 3) {
		bucket = strndup(req->uri.path + captured[2],
				 captured[3] - captured[2]);
		buck_in_path = true;

		if ((captured[5] - captured[4]) > 0)
			path = strndup(req->uri.path + captured[4],
				       captured[5] - captured[4]);
	}

	if (!path)
		path = strdup("/");
	pslash = (strcmp(path, "/") == 0);
	if ((strlen(path) > 1) && (*path == '/'))
		key = path + 1;

	if (debugging)
		syslog(LOG_DEBUG, "%s: method %s, path '%s', bucket '%s'",
		       cli->addr_host, method, path, bucket);

	/* parse Authentication header */
	if (auth) {
		char b64sig[64];
		int usiglen, rc;
		DBT key, val;

		if (pcre_exec(patterns[pat_auth].re, NULL,
			      auth, strlen(auth), 0, 0,
			      captured, 16) != 3) {
			err = InvalidArgument;
			goto err_out;
		}

		memset(&key, 0, sizeof(key));
		memset(&val, 0, sizeof(val));

		user = strndup(auth + captured[2], captured[3] - captured[2]);
		usiglen = captured[5] - captured[4];

		key.data = user;
		key.size = strlen(user) + 1;

		/* to prevent attacks that validate a username's
		 * existence, we return the same error regardless
		 * of whether the user exists or signature does
		 * not match.
		 */

		rc = tdb.passwd->get(tdb.passwd, NULL, &key, &val, 0);
		if (rc) {
			val.data = strdup("");

			if (rc != DB_NOTFOUND) {
				char s[64];

				sprintf(s, "get user '%s'", user);
				tdb.passwd->err(tdb.passwd, rc, s);
			}
		}

		req_sign(&cli->req, buck_in_path ? NULL : bucket,
			 val.data, b64sig);

		rc = strncmp(b64sig, auth + captured[4], usiglen);

		if (rc) {
			err = SignatureDoesNotMatch;
			goto err_out;
		}
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
	else if (bucket && !pslash && !strcmp(method, "HEAD"))
		rcb = object_get(cli, user, bucket, key, false);
	else if (bucket && !pslash && !strcmp(method, "GET"))
		rcb = object_get(cli, user, bucket, key, true);
	else if (bucket && !pslash && !strcmp(method, "PUT")) {
		long content_len;

		if (!content_len_str) {
			err = MissingContentLength;
			goto err_out;
		}

		content_len = atol(content_len_str);

		rcb = object_put(cli, user, bucket, key, content_len,
				 expect_cont);
	} else if (bucket && !pslash && !strcmp(method, "DELETE"))
		rcb = object_del(cli, user, bucket, key);

	/*
	 * operations on buckets
	 */
	else if (bucket && pslash && !strcmp(method, "GET")) {
		rcb = bucket_list(cli, user, bucket);
	}
	else if (bucket && pslash && !strcmp(method, "PUT")) {
		if (!auth) {
			err = AccessDenied;
			goto err_out;
		}
		rcb = bucket_add(cli, user, bucket);
	}
	else if (bucket && pslash && !strcmp(method, "DELETE")) {
		rcb = bucket_del(cli, user, bucket);
	}

	/*
	 * service-wide operations
	 */
	else if (!bucket && pslash && !strcmp(method, "GET")) {
		if (!auth) {
			err = AccessDenied;
			goto err_out;
		}
		rcb = service_list(cli, user);
	}

	else
		rcb = cli_err(cli, InvalidURI);

out:
	free(bucket);
	free(path);
	free(user);
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

	cli->req.orig_path = strndup(cli->req.uri.path, cli->req.uri.path_len);

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

static cli_evt_func state_funcs[] = {
	[evt_read_req]		= cli_evt_read_req,
	[evt_parse_req]		= cli_evt_parse_req,
	[evt_read_hdr]		= cli_evt_read_hdr,
	[evt_parse_hdr]		= cli_evt_parse_hdr,
	[evt_http_req]		= cli_evt_http_req,
	[evt_http_data_in]	= cli_evt_http_data_in,
	[evt_dispose]		= cli_evt_dispose,
	[evt_recycle]		= cli_evt_recycle,
};

static void tcp_cli_event(unsigned int events, struct client *cli)
{
	bool loop;

	if (events & EPOLLOUT) {
		events &= ~EPOLLOUT;
		cli_writable(cli);
	}

	do {
		loop = state_funcs[cli->state](cli, events);
	} while (loop);
}

static void tcp_srv_event(unsigned int events, struct server_socket *sock)
{
	socklen_t addrlen = sizeof(struct sockaddr_in6);
	struct client *cli;
	char host[64];
	int rc;

	/* alloc and init client info */
	cli = cli_alloc();
	if (!cli) {
		struct sockaddr_in6 a;
		int fd = accept(sock->fd, (struct sockaddr *) &a, &addrlen);
		close(fd);
		return;
	}

	/* receive TCP connection from kernel */
	cli->fd = accept(sock->fd, (struct sockaddr *) &cli->addr, &addrlen);
	if (cli->fd < 0) {
		syslogerr("tcp accept");
		goto err_out;
	}

	tabled_srv.stats.tcp_accept++;

	/* mark non-blocking, for upcoming epoll use */
	if (fsetflags("tcp client", cli->fd, O_NONBLOCK) < 0)
		goto err_out_fd;

	/* add to epoll watchlist */
	rc = epoll_ctl(tabled_srv.epoll_fd, EPOLL_CTL_ADD, cli->fd, &cli->evt);
	if (rc < 0) {
		syslogerr("tcp client epoll_ctl");
		goto err_out_fd;
	}

	/* pretty-print incoming cxn info */
	getnameinfo((struct sockaddr *) &cli->addr, sizeof(struct sockaddr_in6),
		    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	host[sizeof(host) - 1] = 0;
	syslog(LOG_INFO, "client %s connected", host);

	strcpy(cli->addr_host, host);

	return;

err_out_fd:
	close(cli->fd);
err_out:
	free(cli);
}

static int net_open(void)
{
	int ipv6_found;
	int rc;
	struct addrinfo hints, *res, *res0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(NULL, tabled_srv.port, &hints, &res0);
	if (rc) {
		syslog(LOG_ERR, "getaddrinfo(*:%s) failed: %s",
		       tabled_srv.port, gai_strerror(rc));
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
		struct server_socket *sock;
		int fd, on;

		if (ipv6_found && res->ai_family == PF_INET)
			continue;

		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0) {
			syslogerr("tcp socket");
			return -errno;
		}

		on = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on,
			       sizeof(on)) < 0) {
			syslogerr("setsockopt(SO_REUSEADDR)");
			rc = -errno;
			goto err_out;
		}

		if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
			syslogerr("tcp bind");
			rc = -errno;
			goto err_out;
		}

		if (listen(fd, 100) < 0) {
			syslogerr("tcp listen");
			rc = -errno;
			goto err_out;
		}

		rc = fsetflags("tcp server", fd, O_NONBLOCK);
		if (rc)
			goto err_out;

		sock = calloc(1, sizeof(*sock));
		if (!sock) {
			rc = -ENOMEM;
			goto err_out;
		}

		sock->fd = fd;
		sock->poll.poll_type = spt_tcp_srv;
		sock->poll.u.sock = sock;
		sock->evt.events = EPOLLIN;
		sock->evt.data.ptr = &sock->poll;

		rc = epoll_ctl(tabled_srv.epoll_fd, EPOLL_CTL_ADD, fd,
			       &sock->evt);
		if (rc < 0) {
			syslogerr("tcp socket epoll_ctl");
			rc = -errno;
			goto err_out;
		}

		tabled_srv.sockets =
			g_list_append(tabled_srv.sockets, sock);
	}

	freeaddrinfo(res0);

	return 0;

err_out:
	freeaddrinfo(res0);
err_addr:
	return rc;
}

static void handle_event(unsigned int events, void *event_data)
{
	struct server_poll *sp = event_data;

	tabled_srv.stats.event++;

	switch (sp->poll_type) {
	case spt_tcp_srv:
		tcp_srv_event(events, sp->u.sock);
		break;
	case spt_tcp_cli:
		tcp_cli_event(events, sp->u.cli);
		break;
	}
}

static void main_loop(void)
{
	struct epoll_event evt[TABLED_EPOLL_MAX_EVT];
	int rc, i;

	while (server_running) {
		rc = epoll_wait(tabled_srv.epoll_fd, evt, TABLED_EPOLL_MAX_EVT, -1);
		if (rc < 0) {
			if (errno == EINTR)
				continue;

			syslogerr("epoll_wait");
			return;
		}

		if (rc == TABLED_EPOLL_MAX_EVT)
			tabled_srv.stats.max_evt++;
		tabled_srv.stats.poll++;

		for (i = 0; i < rc; i++)
			handle_event(evt[i].events, evt[i].data.ptr);

		if (dump_stats) {
			log_stats();
			dump_stats = false;
		}
	}
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
			syslog(LOG_ERR, "BUG: pattern compile %d failed", i);
			exit(1);
		}

		patterns[i].re = re;
	}
}

int main (int argc, char *argv[])
{
	error_t aprc;
	int rc = 1;
	uint64_t r1, r2;

	srand(time(NULL));
	r1 = rand();
	r2 = rand();
	counter = (r1 << 32) | (r2 & 0xffffffff);

	/* isspace() and strcasecmp() consistency requires this */
	setlocale(LC_ALL, "C");

	/*
	 * parse command line
	 */

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	/*
	 * open syslog, background outselves, write PID file ASAP
	 */

	openlog(PROGRAM_NAME, LOG_PID, LOG_LOCAL3);

	if (debugging)
		syslog(LOG_INFO, "Verbose debug output enabled");

	compile_patterns();

	if ((!(tabled_srv.flags & SFL_FOREGROUND)) && (daemon(1, 0) < 0)) {
		syslogerr("daemon");
		goto err_out;
	}

	rc = write_pid_file(tabled_srv.pid_file);
	if (rc < 0)
		goto err_out;

	/*
	 * properly capture TERM and other signals
	 */

	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, term_signal);
	signal(SIGTERM, term_signal);
	signal(SIGUSR1, stats_signal);

	tdb_init();

	/* create master epoll fd */
	tabled_srv.epoll_fd = epoll_create(TABLED_EPOLL_INIT_SIZE);
	if (tabled_srv.epoll_fd < 0) {
		syslogerr("epoll_create");
		goto err_out_pid;
	}

	/* set up server networking */
	rc = net_open();
	if (rc)
		goto err_out_epoll;

	syslog(LOG_INFO, "initialized");

	main_loop();

	syslog(LOG_INFO, "shutting down");

	tdb_done();

	rc = 0;

err_out_epoll:
	close(tabled_srv.epoll_fd);
err_out_pid:
	unlink(tabled_srv.pid_file);
err_out:
	closelog();
	return rc;
}

