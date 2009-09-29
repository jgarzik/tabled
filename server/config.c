
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
#include <errno.h>
#include <ctype.h>
#include <cldc.h>
#include "tabled.h"

struct config_context {
	char		*text;

	bool		in_listen;
	struct listen_cfg tmp_listen;

	bool		in_storage;
	unsigned int	stor_nid;
	char		*stor_port;
	char		*stor_host;

	bool		in_cld;
	unsigned short	cld_port;
	char		*cld_host;
	char		*cld_port_file;
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
			applog(LOG_ERR, "Nested Listen in configuration");
		}
	}
	else if (!strcmp(element_name, "StorageNode")) {
		if (!cc->in_storage) {
			cc->in_storage = true;
			cc->stor_nid++;
		} else {
			applog(LOG_ERR, "Nested StorageNode in configuration");
		}
	}
	else if (!strcmp(element_name, "CLD")) {
		if (!cc->in_cld) {
			cc->in_cld = true;
		} else {
			applog(LOG_ERR, "Nested CLD in configuration");
		}
	}
}

static void cfg_elm_end_listen(struct config_context *cc)
{
	if (cc->text) {
		applog(LOG_WARNING, "cfgfile: Extra text '%s' in Listen",
		       cc->text);
		free(cc->text);
		cc->text = NULL;
		return;
	}

	if (!cc->tmp_listen.port) {
		applog(LOG_ERR, "cfgfile: Listen with no Port");
		goto err;
	}

	if (tabled_srv.port) {
		free(tabled_srv.port);
		tabled_srv.port = NULL;
	}
	if (tabled_srv.port_file) {
		free(tabled_srv.port_file);
		tabled_srv.port_file = NULL;
	}

	tabled_srv.port = cc->tmp_listen.port;
	tabled_srv.port_file = cc->tmp_listen.port_file;
	memset(&cc->tmp_listen, 0, sizeof(struct listen_cfg));
	return;

 err:
	free(cc->tmp_listen.port);
	free(cc->tmp_listen.port_file);
	memset(&cc->tmp_listen, 0, sizeof(struct listen_cfg));
}

static void cfg_elm_end_storage(struct config_context *cc)
{
	struct geo dummy_loc;

	if (cc->text) {
		applog(LOG_WARNING, "Extra text in StorageNode element: \"%s\"",
		       cc->text);
		free(cc->text);
		cc->text = NULL;
		goto end;
	}

	if (!cc->stor_host) {
		applog(LOG_WARNING, "No host for StorageNode element");
		goto end;
	}
	if (!cc->stor_port) {
		applog(LOG_WARNING, "No port for StorageNode element");
		goto end;
	}

	memset(&dummy_loc, 0, sizeof(struct geo));
	stor_add_node(cc->stor_nid, cc->stor_host, cc->stor_port, &dummy_loc);
	/*
	 * We don't call stor_update_cb here because doing it so early
	 * hangs TDB replication for some reason (and produces a process
	 * that needs -9 to kill).
	 *
	 * Instead, there's a little plug in cldu.c that does it.
	 */

end:
	free(cc->stor_host);
	cc->stor_host = NULL;
	free(cc->stor_port);
	cc->stor_port = NULL;
}

static void cfg_elm_end_cld(struct config_context *cc)
{
	if (cc->text) {
		applog(LOG_WARNING, "Extra text in CLD element: \"%s\"",
		       cc->text);
		free(cc->text);
		cc->text = NULL;
		goto end;
	}

	if (!cc->cld_host) {
		applog(LOG_WARNING, "No host for CLD element");
		goto end;
	}
	if (!cc->cld_port && !cc->cld_port_file) {
		applog(LOG_WARNING, "No Port nor PortFile for CLD element");
		goto end;
	}

	/*
	 * Waiting here is disadvantageous, because it defeats testing
	 * of bootstrap robustness for Chunk as a client of CLD.
	 * But it's the most direct way to give us variable ports.
	 * Also, no mysterious sleep commands in start-daemon script.
	 */
	if (cc->cld_port_file) {
		int port;
		if ((port = cld_readport(cc->cld_port_file)) <= 0) {
			applog(LOG_INFO, "Waiting for CLD PortFile %s",
			       cc->cld_port_file);
			sleep(2);
			while ((port = cld_readport(cc->cld_port_file)) <= 0)
				sleep(3);
			applog(LOG_INFO, "Using CLD port %u", port);
		}
		cc->cld_port = port;
	}

	cldu_add_host(cc->cld_host, cc->cld_port);

end:
	free(cc->cld_host);
	cc->cld_host = NULL;
	cc->cld_port = 0;
}

static void cfg_elm_end (GMarkupParseContext *context,
			 const gchar	 *element_name,
			 gpointer	     user_data,
			 GError	     **error)
{
	struct config_context *cc = user_data;
	struct stat statb;
	long n;

	if (!strcmp(element_name, "PID") && cc->text) {
		if (tabled_srv.pid_file) {
			/* Silent about command line override. */
			free(cc->text);
		} else {
			tabled_srv.pid_file = cc->text;
		}
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "ForceHost") && cc->text) {
		free(tabled_srv.ourhost);
		tabled_srv.ourhost = cc->text;
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "TDB") && cc->text) {
		if (stat(cc->text, &statb) < 0) {
			applog(LOG_ERR, "stat(2) on TDB '%s' failed: %s",
			       cc->text, strerror(errno));
			return;
		}

		if (!S_ISDIR(statb.st_mode)) {
			applog(LOG_ERR, "TDB '%s' is not a directory",
			       cc->text);
			return;
		}

		free(tabled_srv.tdb_dir);
		tabled_srv.tdb_dir = cc->text;
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "TDBRepPort") && cc->text) {
		n = strtol(cc->text, NULL, 10);
		if (n <= 0 || n >= 65536) {
			applog(LOG_WARNING,
			       "TDBRepPort '%s' invalid, ignoring", cc->text);
			free(cc->text);
			cc->text = NULL;
			return;
		}
		tabled_srv.rep_port = n;
		free(cc->text);
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "Listen")) {
		cfg_elm_end_listen(cc);
		cc->in_listen = false;
	}

	else if (!strcmp(element_name, "StorageNode")) {
		cfg_elm_end_storage(cc);
		cc->in_storage = false;
	}

	else if (!strcmp(element_name, "CLD")) {
		cfg_elm_end_cld(cc);
		cc->in_cld = false;
	}

	else if (!strcmp(element_name, "Port")) {

		if (!cc->text) {
			applog(LOG_WARNING, "Port element empty");
			return;
		}

		if (cc->in_listen) {
			n = strtol(cc->text, NULL, 10);
			if ((n > 0 && n < 65536) ||
			    !strcmp(cc->text, "auto")) {
				free(cc->tmp_listen.port);
				cc->tmp_listen.port = cc->text;
			} else {
				applog(LOG_WARNING,
				       "Port '%s' invalid, ignoring", cc->text);
				free(cc->text);
			}
			cc->text = NULL;
		} else if (cc->in_storage) {
			n = strtol(cc->text, NULL, 10);
			if (n > 0 && n < 65536) {
				free(cc->stor_port);
				cc->stor_port = cc->text;
			} else {
				applog(LOG_WARNING,
				       "Port '%s' invalid, ignoring", cc->text);
				free(cc->text);
			}
			cc->text = NULL;
		} else if (cc->in_cld) {
			n = strtol(cc->text, NULL, 10);
			if (n > 0 && n < 65536)
				cc->cld_port = n;
			else
				applog(LOG_WARNING,
				       "Port '%s' invalid, ignoring", cc->text);
			free(cc->text);
			cc->text = NULL;
		} else {
			applog(LOG_WARNING,
			       "Port element not in Listen or StorageNode");
			return;
		}

	}

	else if (!strcmp(element_name, "Host")) {
		if (!cc->text) {
			applog(LOG_WARNING, "Host element empty");
			return;
		}

		if (cc->in_storage) {
			free(cc->stor_host);
			cc->stor_host = cc->text;
			cc->text = NULL;
		} else if (cc->in_cld) {
			free(cc->cld_host);
			cc->cld_host = cc->text;
			cc->text = NULL;
		} else {
			applog(LOG_WARNING, "Host element not in StorageNode");
		}
	}

	else if (!strcmp(element_name, "PortFile")) {
		if (!cc->text) {
			applog(LOG_WARNING, "PortFile element empty");
			return;
		}

		if (cc->in_listen) {
			free(cc->tmp_listen.port_file);
			cc->tmp_listen.port_file = cc->text;
		} else if (cc->in_cld) {
			free(cc->cld_port_file);
			cc->cld_port_file = cc->text;
		} else {
			applog(LOG_WARNING,
			       "PortFile element not in Listen or CLD");
			free(cc->text);
		}
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "ChunkUser") && cc->text) {
		free(tabled_srv.chunk_user);
		tabled_srv.chunk_user = cc->text;
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "ChunkKey") && cc->text) {
		free(tabled_srv.chunk_key);
		tabled_srv.chunk_key = cc->text;
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
		applog(LOG_WARNING, "Unknown element \"%s\"", element_name);
	}

}

static bool str_n_isspace(const char *s, size_t n)
{
	char c;
	size_t i;

	for (i = 0; i < n; i++) {
		c = *s++;
		if (!isspace(c))
			return false;
	}
	return true;
}

static void cfg_elm_text (GMarkupParseContext *context,
			  const gchar	*text,
			  gsize		text_len,
			  gpointer	user_data,
			  GError	**error)
{
	struct config_context *cc = user_data;

	free(cc->text);
	if (str_n_isspace(text, text_len))
		cc->text = NULL;
	else
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
	tabled_srv.rep_port = 8083;

	if (!g_file_get_contents(tabled_srv.config, &text, &len, NULL)) {
		applog(LOG_ERR, "failed to read config file %s",
			tabled_srv.config);
		exit(1);
	}

	parser = g_markup_parse_context_new(&cfg_parse_ops, 0, &ctx, NULL);
	if (!parser) {
		applog(LOG_ERR, "g_markup_parse_context_new failed");
		exit(1);
	}

	if (!g_markup_parse_context_parse(parser, text, len, NULL)) {
		applog(LOG_ERR, "config file parse failure");
		exit(1);
	}

	g_markup_parse_context_free(parser);
	free(ctx.text);
	free(text);

	if (!tabled_srv.tdb_dir) {
		applog(LOG_ERR, "no directory TDB defined in config file");
		exit(1);
	}

	if (!tabled_srv.pid_file) {
		if (!(tabled_srv.pid_file = strdup("/var/run/tabled.pid"))) {
			applog(LOG_ERR, "no core");
			exit(1);
		}
	}

	if (debugging)
		applog(LOG_INFO, "TDB %s PID %s port %s",
		       tabled_srv.tdb_dir,
		       tabled_srv.pid_file, tabled_srv.port);
}
