
/*
 * Copyright 2009 Red Hat, Inc.
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
#include <glib.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "tabled.h"

struct config_context {
	char		*text;

	char		*fname;

	bool		in_chunk;
	bool		in_chunk_reported;

	bool		in_storage;
	bool		stor_encrypt;
	char		*stor_port;
	char		*stor_host;

	bool		stor_ok;
	char		*stor_ok_port;
	char		*stor_ok_host;

	bool		in_geo;
	struct geo	loc;

	unsigned int	nid;
};

static void cfg_elm_start (GMarkupParseContext *context,
			 const gchar	 *element_name,
			 const gchar     **attribute_names,
			 const gchar     **attribute_values,
			 gpointer     user_data,
			 GError	     **error)
{
	struct config_context *cc = user_data;

	if (!strcmp(element_name, "Chunk")) {
		if (!cc->in_chunk)
			cc->in_chunk = true;
		else
			applog(LOG_ERR, "%s: Nested Chunk", cc->fname);
	} else {
		if (!cc->in_chunk) {
			/*
			 * We don't want to flood logs with bogus error
			 * messages if something benign happens to <Chunk>.
			 */
			if (!cc->in_chunk_reported) {
				applog(LOG_ERR,
				       "%s: Element %s outside of <Chunk>",
				       cc->fname);
				cc->in_chunk_reported = true;
			}
			return;
		}
	}

	if (!strcmp(element_name, "Socket")) {
		if (!cc->in_storage)
			cc->in_storage = true;
		else
			applog(LOG_ERR, "%s: Nested Socket", cc->fname);
	}
	else if (!strcmp(element_name, "Geo")) {
		if (!cc->in_geo)
			cc->in_geo = true;
		else
			applog(LOG_ERR, "%s: Nested CLD", cc->fname);
	}
}

static void cfg_elm_end_storage(struct config_context *cc)
{
	if (cc->text) {
		applog(LOG_WARNING, "%s: Extra text in Socket element: \"%s\"",
		       cc->fname, cc->text);
		free(cc->text);
		cc->text = NULL;
		goto end;
	}

	if (!cc->stor_host) {
		applog(LOG_WARNING, "%s: No host for Socket element",
		       cc->fname);
		goto end;
	}
	if (!cc->stor_port) {
		applog(LOG_WARNING, "%s: No port for Socket element",
		       cc->fname);
		goto end;
	}

	/* FIXME Chunkd with SSL needs certs, or else it's security theater. */
	if (cc->stor_encrypt) {
		applog(LOG_WARNING, "%s: Good Socket (%s,%s), but "
		       "SSL access to Chunk is not supported yet",
		       cc->fname,
		       cc->stor_host, cc->stor_port);
		goto end;
	}

	if (cc->stor_ok) {
		applog(LOG_WARNING, "%s: Good Socket (%s,%s), but "
		       "multihomed Chunk is not supported yet, using (%s,%s)",
		       cc->fname,
		       cc->stor_host, cc->stor_port,
		       cc->stor_ok_host, cc->stor_ok_port);
		goto end;
	}

	cc->stor_ok = true;
	cc->stor_ok_host = cc->stor_host;
	cc->stor_ok_port = cc->stor_port;
	
	cc->stor_encrypt = false;
	cc->stor_host = NULL;
	cc->stor_port = NULL;
	return;

end:
	free(cc->stor_host);
	cc->stor_host = NULL;
	free(cc->stor_port);
	cc->stor_port = NULL;
}

static void cfg_elm_end_geo(struct config_context *cc)
{
	if (cc->text) {
		applog(LOG_WARNING, "%s: Extra text in Geo element: \"%s\"",
		       cc->text);
		free(cc->text);
		cc->text = NULL;
		goto end;
	}

	if (!cc->loc.rack) {
		goto end;
	}

	/* do nothing - saving in-place */
	return;

end:
	free(cc->loc.area);
	free(cc->loc.zone);
	free(cc->loc.rack);
	cc->loc.area = NULL;
	cc->loc.zone = NULL;
	cc->loc.rack = NULL;
}

static void cfg_elm_end (GMarkupParseContext *context,
			 const gchar	 *element_name,
			 gpointer	     user_data,
			 GError	     **error)
{
	struct config_context *cc = user_data;
	long n;

	if (!strcmp(element_name, "NID") && cc->text) {
		if (!cc->text) {
			applog(LOG_WARNING, "%s: NID element empty", cc->fname);
			return;
		}

		n = strtol(cc->text, NULL, 10);
		if (n == 0 || (n & ~0xffffffff) != 0)
		{
			applog(LOG_WARNING,
			       "%s: NID '%s' invalid, ignoring",
			       cc->fname, cc->text);
			free(cc->text);
			cc->text = NULL;
			return;
		}
		cc->nid = n;
		free(cc->text);
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "Socket")) {
		cfg_elm_end_storage(cc);
		cc->in_storage = false;
	}

	else if (!strcmp(element_name, "Geo")) {
		cfg_elm_end_geo(cc);
		cc->in_geo = false;
	}

	else if (!strcmp(element_name, "Area")) {
		if (!cc->text)
			return;
		if (cc->text[0] == '-')
			return;

		if (cc->in_geo) {
			free(cc->loc.area);
			cc->loc.area = cc->text;
		} else {
			applog(LOG_WARNING,
			       "%s: Area not in Geo", cc->fname);
			free(cc->text);
		}
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "Building")) {
		if (!cc->text)
			return;
		if (cc->text[0] == '-')
			return;

		if (cc->in_geo) {
			free(cc->loc.zone);
			cc->loc.zone = cc->text;
		} else {
			applog(LOG_WARNING,
			       "%s: Building not in Geo", cc->fname);
			free(cc->text);
		}
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "Rack")) {
		if (!cc->text)
			return;
		if (cc->text[0] == '-')
			return;

		if (cc->in_geo) {
			free(cc->loc.rack);
			cc->loc.rack = cc->text;
		} else {
			applog(LOG_WARNING,
			       "%s: Rack not in Geo", cc->fname);
			free(cc->text);
		}
		cc->text = NULL;
	}

	else if (!strcmp(element_name, "Type")) {
		if (!cc->text) {
			applog(LOG_WARNING,
			       "%s: Type element empty", cc->fname);
			return;
		}

		if (!strcmp(cc->text, "chunk")) {
			;
		} else if (!strcmp(cc->text, "chunk-ssl")) {
			cc->stor_encrypt = true;
		} else {
			applog(LOG_WARNING, "%s: Type '%s' is invalid",
			       cc->fname, cc->text);
			return;
		}
	}

	else if (!strcmp(element_name, "Port")) {
		if (!cc->text) {
			applog(LOG_WARNING, "Port element empty");
			return;
		}

		if (cc->in_storage) {
			n = strtol(cc->text, NULL, 10);
			if (n > 0 && n < 65536) {
				free(cc->stor_port);
				cc->stor_port = cc->text;
			} else {
				applog(LOG_WARNING,
				       "%s: Port '%s' invalid, ignoring",
				       cc->fname, cc->text);
				free(cc->text);
			}
			cc->text = NULL;
		} else {
			applog(LOG_WARNING,
			       "%s: Port element not in Socket");
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
		} else {
			applog(LOG_WARNING, "%s: Host element not in Socket",
			       cc->fname);
		}
	}

	else if (!strcmp(element_name, "Chunk")) {
		if (cc->in_chunk) {
			cc->in_chunk = false;
		} else {
			applog(LOG_WARNING, "%s: Unbalanced closing Chunk",
			       cc->fname);
		}
	}

	else {
		applog(LOG_WARNING, "%s: Unknown element \"%s\"",
		       cc->fname, element_name);
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

void stor_parse(char *fname, const char *text, size_t len)
{
	GMarkupParseContext* parser;
	struct config_context ctx;

	memset(&ctx, 0, sizeof(struct config_context));
	ctx.fname = fname;

	parser = g_markup_parse_context_new(&cfg_parse_ops, 0, &ctx, NULL);
	if (!parser) {
		applog(LOG_ERR, "g_markup_parse_context_new failed");
		return;
	}

	if (!g_markup_parse_context_parse(parser, text, len, NULL)) {
		applog(LOG_ERR, "Parse failure for Chunk in %s", fname);
		g_markup_parse_context_free(parser);
		goto out_free_all;
	}

	g_markup_parse_context_free(parser);

	if (!ctx.nid) {
		applog(LOG_WARNING, "%s: No NID\n", fname);
		goto out_free_all;
	}
	if (!ctx.stor_ok) {
		applog(LOG_WARNING, "%s: No useable Socket clause", fname);
		goto out_free_all;
	}
	stor_add_node(ctx.nid, ctx.stor_ok_host, ctx.stor_ok_port, &ctx.loc);

out_free_all:
	free(ctx.text);

	free(ctx.stor_host);
	free(ctx.stor_port);

	free(ctx.stor_ok_host);
	free(ctx.stor_ok_port);

	free(ctx.loc.area);
	free(ctx.loc.zone);
	free(ctx.loc.rack);
	return;
}
