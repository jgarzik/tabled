
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

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>

#include "tabled.h"

static struct {
	const char	*code;
	int		status;
	const char	*msg;
} err_info[] = {

	[InvalidArgument] =
	{ "InvalidArgument", 400,
	  "Invalid Operation" },

	[AccessDenied] =
	{ "AccessDenied", 403,
	  "Access denied" },

	[InvalidURI] =
	{ "NotFound", 404,
	  "Not Found" },

	[InternalError] =
	{ "InternalError", 500,
	  "We encountered an internal error. Please try again." },
};

static const char stat_err_fmt1[] = {
"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\r\n"
"<html>\r\n"
" <head>\r\n"
"  <title>%d %s</title>\r\n"
" </head>\r\n"
" <body>\r\n"
"  <h1>%d %s</h1>\r\n"
" </body>\r\n"
"</html>\r\n"
};

bool stat_err(struct client *cli, enum errcode code)
{
	char *hdr = NULL, *content = NULL;
	int err_status;
	const char *err_code, *err_msg;
	char timestr[50];
	int rc;

	/*
	 * We do not use all codes that the main server can return,
	 * so our array is smaller and it has gaps. Must check, in case.
	 */
	if (code < 0 || code >= ARRAY_SIZE(err_info) || !err_info[code].code) {
		applog(LOG_INFO, "client %s status error %d",
		       cli->addr_host, code);
		code = InternalError;
	}

	err_status = err_info[code].status;
	err_code = err_info[code].code;
	err_msg = err_info[code].msg;

	applog(LOG_INFO, "client %s status error %s",
	       cli->addr_host, err_msg);

	rc = asprintf(&content, stat_err_fmt1,
		      err_status, err_code, err_status, err_msg);
	if (rc < 0)
		goto out;

	rc = asprintf(&hdr,
		      "HTTP/%d.%d %d x\r\n"
		      "Content-Type: text/html; charset=UTF-8\r\n"
		      "Content-Length: %zu\r\n"
		      "Date: %s\r\n"
		      "Connection: close\r\n"
		      "Server: " PACKAGE_STRING "\r\n"
		      "\r\n",
		      cli->req.major, cli->req.minor, err_status,
		      strlen(content),
		      time2str(timestr, sizeof(timestr), time(NULL)));
	if (rc < 0)
		goto out_hdr;

	return cli_err_write(cli, hdr, content);

out_hdr:
	free(content);
out:
	return false;
}

static bool stat_root(struct client *cli)
{
	GList *content = NULL;
	char *str;
	bool rcb;

	if (asprintf(&str,
		     "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\r\n"
		     "<html>\r\n"
		     " <head> <title>Status</title> </head>\r\n"
		     " <body>\r\n") < 0)
		goto out_err;
	content = g_list_append(content, str);

	if (!stat_status(cli, content))
		goto out_err;
	if (!stor_status(cli, content))
		goto out_err;
	if (!rep_status(cli, content))
		goto out_err;

	if (asprintf(&str,
		     " </body>\r\n"
		     "</html>\r\n") < 0)
		goto out_err;
	content = g_list_append(content, str);

	rcb = cli_resp_html(cli, 200, content);
	g_list_free(content);
	return rcb;

out_err:
	strlist_free(content);
	return cli_err(cli, InternalError);
}

bool stat_evt_http_req(struct client *cli, unsigned int events)
{
	struct http_req *req = &cli->req;
	char *method = req->method;
	// char *content_len_str;
	char *path = NULL;
	// int rc;
	bool rcb;

	/* grab useful headers */
	// content_len_str = req_hdr(req, "content-length");

	path = strdup(req->uri.path);
	if (!path)
		path = strdup("/");

	if (debugging)
		applog(LOG_INFO, "%s: status method %s, path '%s'",
		       cli->addr_host, method, path);

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

	if (!strcmp(method, "GET")) {
		if (!strcmp(path, "/")) {
			rcb = stat_root(cli);
		} else {
			rcb = stat_err(cli, InvalidURI);
		}
	}

	else {
		rcb = stat_err(cli, InvalidArgument);
	}

	free(path);
	return rcb;
}
