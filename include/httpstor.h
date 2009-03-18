#ifndef __HTTPSTOR_H__
#define __HTTPSTOR_H__

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
#include <stdint.h>
#include <curl/curl.h>
#include <glib.h>

struct httpstor_client {
	CURL		*curl;
	char		*host;
	char		*user;
	char		*key;
	bool		verbose;
};

struct httpstor_bucket {
	char		*name;
	char		*time_create;
};

struct httpstor_blist {
	char		*own_id;	/* ID */
	char		*own_name;	/* DisplayName */
	GList		*list;		/* list of httpstor_bucket */
};

struct httpstor_object {
	char		*key;
	char		*time_mod;
	char		*etag;
	uint64_t	size;
	char		*storage;
	char		*own_id;
	char		*own_name;
};

struct httpstor_keylist {
	char		*name;
	char		*prefix;
	char		*marker;
	char		*delim;
	unsigned int	max_keys;
	bool		trunc;
	GList		*contents;
	GList		*common_pfx;
};

extern void httpstor_free(struct httpstor_client *httpstor);
extern void httpstor_free_blist(struct httpstor_blist *blist);
extern void httpstor_free_bucket(struct httpstor_bucket *buck);
extern void httpstor_free_object(struct httpstor_object *obj);
extern void httpstor_free_keylist(struct httpstor_keylist *keylist);

extern struct httpstor_client *httpstor_new(const char *service_host,
				 const char *user, const char *secret_key);

extern bool httpstor_add_bucket(struct httpstor_client *httpstor, const char *name);
extern bool httpstor_del_bucket(struct httpstor_client *httpstor, const char *name);

extern struct httpstor_blist *httpstor_list_buckets(struct httpstor_client *httpstor);

extern bool httpstor_get(struct httpstor_client *httpstor, const char *bucket, const char *key,
	     size_t (*write_cb)(void *, size_t, size_t, void *),
	     void *user_data, bool want_headers);
extern void *httpstor_get_inline(struct httpstor_client *httpstor, const char *bucket,
			    const char *key, bool want_headers, size_t *len);
extern bool httpstor_put(struct httpstor_client *httpstor, const char *bucket, const char *key,
	     size_t (*read_cb)(void *, size_t, size_t, void *),
	     uint64_t len, void *user_data, char **user_hdrs);
extern bool httpstor_put_inline(struct httpstor_client *httpstor, const char *bucket,
			   const char *key, void *data, uint64_t len,
			   char **user_hdrs);
extern bool httpstor_del(struct httpstor_client *httpstor, const char *bucket, const char *key);

extern struct httpstor_keylist *httpstor_keys(struct httpstor_client *httpstor, const char *bucket,
			    const char *prefix, const char *marker,
			    const char *delim, unsigned int max_keys);

#endif /* __HTTPSTOR_H__ */
