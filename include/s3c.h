#ifndef __S3C_H__
#define __S3C_H__

#include <stdbool.h>
#include <stdint.h>
#include <curl/curl.h>
#include <glib.h>

struct s3_client {
	CURL		*curl;
	char		*host;
	char		*user;
	char		*key;
	bool		verbose;
};

struct s3_bucket {
	char		*name;
	char		*time_create;
};

struct s3_blist {
	char		*own_id;	/* ID */
	char		*own_name;	/* DisplayName */
	GList		*list;		/* list of s3_bucket */
};

struct s3_object {
	char		*key;
	char		*time_mod;
	char		*etag;
	uint64_t	size;
	char		*storage;
	char		*own_id;
	char		*own_name;
};

struct s3_keylist {
	char		*name;
	char		*prefix;
	char		*marker;
	char		*delim;
	unsigned int	max_keys;
	bool		trunc;
	GList		*contents;
	GList		*common_pfx;
};

extern void s3c_free(struct s3_client *s3c);
extern void s3c_free_blist(struct s3_blist *blist);
extern void s3c_free_bucket(struct s3_bucket *buck);
extern void s3c_free_object(struct s3_object *obj);
extern void s3c_free_keylist(struct s3_keylist *keylist);

extern struct s3_client *s3c_new(const char *service_host,
				 const char *user, const char *secret_key);

extern bool s3c_add_bucket(struct s3_client *s3c, const char *name);
extern bool s3c_del_bucket(struct s3_client *s3c, const char *name);

extern struct s3_blist *s3c_list_buckets(struct s3_client *s3c);

extern bool s3c_get(struct s3_client *s3c, const char *bucket, const char *key,
	     size_t (*write_cb)(void *, size_t, size_t, void *),
	     void *user_data, bool want_headers);
extern void *s3c_get_inline(struct s3_client *s3c, const char *bucket,
			    const char *key, bool want_headers, size_t *len);
extern bool s3c_put(struct s3_client *s3c, const char *bucket, const char *key,
	     size_t (*read_cb)(void *, size_t, size_t, void *),
	     uint64_t len, void *user_data, char **user_hdrs);
extern bool s3c_put_inline(struct s3_client *s3c, const char *bucket,
			   const char *key, void *data, uint64_t len,
			   char **user_hdrs);
extern bool s3c_del(struct s3_client *s3c, const char *bucket, const char *key);

extern struct s3_keylist *s3c_keys(struct s3_client *s3c, const char *bucket,
			    const char *prefix, const char *marker,
			    const char *delim, unsigned int max_keys);

#endif /* __S3C_H__ */
