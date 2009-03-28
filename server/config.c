
/*
 * Copyright (c) 2009, Red Hat, Inc.
 */
#define _GNU_SOURCE
#include "tabled-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <glib.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "tabled.h"

struct config_context {
	char		*text;
	bool		in_listen;
	struct listen_cfg tmp_listen;
};

static void cfg_elm_start (GMarkupParseContext *context,
			 const gchar	 *element_name,
			 const gchar     **attribute_names,
			 const gchar     **attribute_values,
			 gpointer     user_data,
			 GError	     **error)
{
	struct config_context *cc = user_data;

	if (!strcmp(element_name, "Listen")) {
		if (!cc->in_listen) {
			cc->in_listen = true;
		} else {
			syslog(LOG_ERR, "Nested Listen in configuration");
		}
	}
}

static void cfg_elm_end (GMarkupParseContext *context,
			 const gchar	 *element_name,
			 gpointer	     user_data,
			 GError	     **error)
{
	struct config_context *cc = user_data;
	struct stat statb;
	int n;

	if (!strcmp(element_name, "PID") && cc->text) {
		if (tabled_srv.pid_file) {
			/* Silent about command line override. */
			free(cc->text);
		} else {
			tabled_srv.pid_file = cc->text;
		}
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "Data") && cc->text) {
		if (stat(cc->text, &statb) < 0) {
			syslog(LOG_ERR, "stat(2) on Path '%s' failed: %s",
			       cc->text, strerror(errno));
			return;
		}

		if (!S_ISDIR(statb.st_mode)) {
			syslog(LOG_ERR, "Path '%s' is not a directory",
			       cc->text);
			return;
		}

		free(tabled_srv.data_dir);
		tabled_srv.data_dir = cc->text;
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "TDB") && cc->text) {
		if (stat(cc->text, &statb) < 0) {
			syslog(LOG_ERR, "stat(2) on TDB '%s' failed: %s",
			       cc->text, strerror(errno));
			return;
		}

		if (!S_ISDIR(statb.st_mode)) {
			syslog(LOG_ERR, "TDB '%s' is not a directory",
			       cc->text);
			return;
		}

		free(tabled_srv.tdb_dir);
		tabled_srv.tdb_dir = cc->text;
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "Listen")) {
		cc->in_listen = false;

		if (!cc->tmp_listen.port) {
			syslog(LOG_WARNING, "TCP port not specified in Listen");
			return;
		}

		if (tabled_srv.port) {
			free(tabled_srv.port);
			tabled_srv.port = NULL;
		}

		tabled_srv.port = cc->tmp_listen.port;
		cc->tmp_listen.port = NULL;
	}

	else if (!strcmp(element_name, "Port")) {

		if (!cc->in_listen) {
			syslog(LOG_WARNING, "Port element not in Listen");
			return;
		}

		if (!cc->text) {
			syslog(LOG_WARNING, "Port element empty");
			return;
		}

		n = atoi(cc->text);
		if (n > 0 && n < 65536) {
			free(cc->tmp_listen.port);
			cc->tmp_listen.port = cc->text;
		} else {
			syslog(LOG_WARNING, "Port '%s' invalid, ignoring",
				cc->text);
			free(cc->text);
		}

		cc->text = NULL;
	}

#if 0
	else if (cc->in_listen && cc->text &&
		 !strcmp(element_name, "Node")) {
		cc->tmp_listen.node = cc->text;
		cc->text = NULL;
	}

	else if (cc->in_listen && cc->text &&
		 !strcmp(element_name, "Encrypt")) {
		if (!strcasecmp(cc->text, "yes") ||
		    !strcasecmp(cc->text, "true"))
			cc->tmp_listen.encrypt = true;

		free(cc->text);
		cc->text = NULL;
	}
#endif

	else {
		syslog(LOG_WARNING, "Unknown element \"%s\"", element_name);
	}

}

static void cfg_elm_text (GMarkupParseContext *context,
			  const gchar	*text,
			  gsize		text_len,  
			  gpointer	user_data,
			  GError	**error)
{
	struct config_context *cc = user_data;

	free(cc->text);
	cc->text = g_strndup(text, text_len);
}

static const GMarkupParser cfg_parse_ops = {
	.start_element		= cfg_elm_start,
	.end_element		= cfg_elm_end,
	.text			= cfg_elm_text,
};

void read_config(void)
{
	GMarkupParseContext* parser;
	char *text;
	gsize len;
	struct config_context ctx;

	memset(&ctx, 0, sizeof(struct config_context));

	tabled_srv.port = strdup("8080");

	if (!g_file_get_contents(tabled_srv.config, &text, &len, NULL)) {
		syslog(LOG_ERR, "failed to read config file %s",
			tabled_srv.config);
		exit(1);
	}

	parser = g_markup_parse_context_new(&cfg_parse_ops, 0, &ctx, NULL);
	if (!parser) {
		syslog(LOG_ERR, "g_markup_parse_context_new failed");
		exit(1);
	}

	if (!g_markup_parse_context_parse(parser, text, len, NULL)) {
		syslog(LOG_ERR, "config file parse failure");
		exit(1);
	}

	g_markup_parse_context_free(parser);
	free(ctx.text);
	free(text);

	if (!tabled_srv.data_dir) {
		syslog(LOG_ERR, "no directory Data defined in config file");
		exit(1);
	}
	if (!tabled_srv.tdb_dir) {
		syslog(LOG_ERR, "no directory TDB defined in config file");
		exit(1);
	}

	if (!tabled_srv.pid_file) {
		if (!(tabled_srv.pid_file = strdup("/var/run/tabled.pid"))) {
			syslog(LOG_ERR, "no core");
			exit(1);
		}
	}

	if (debugging)
		syslog(LOG_INFO, "Data %s TDB %s PID %s port %s\n",
		       tabled_srv.data_dir, tabled_srv.tdb_dir,
		       tabled_srv.pid_file, tabled_srv.port);
}
