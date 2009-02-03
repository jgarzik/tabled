
#define _GNU_SOURCE
#include "tabled-config.h"
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <libxml/tree.h>
#include <glib.h>
#include <s3c.h>
#include <httputil.h>

static int _strcasecmp(const unsigned char *a, const char *b)
{
	return xmlStrcasecmp(a, (const unsigned char *) b);
}

static int _strcmp(const unsigned char *a, const char *b)
{
	return xmlStrcmp(a, (const unsigned char *) b);
}

void s3c_free(struct s3_client *s3c)
{
	if (s3c->curl)
		curl_easy_cleanup(s3c->curl);
	free(s3c->host);
	free(s3c->user);
	free(s3c->key);
	free(s3c);
}

struct s3_client *s3c_new(const char *service_host,
				 const char *user, const char *secret_key)
{
	struct s3_client *s3c;

	s3c = calloc(1, sizeof(struct s3_client));
	if (!s3c)
		return NULL;

	s3c->host = strdup(service_host);
	s3c->user = strdup(user);
	s3c->key = strdup(secret_key);
	if (!s3c->host || !s3c->user || !s3c->key)
		goto err_out;

	if (curl_global_init(CURL_GLOBAL_ALL))
		goto err_out;

	s3c->curl = curl_easy_init();
	if (!s3c->curl)
		goto err_out;

	return s3c;

err_out:
	s3c_free(s3c);
	return NULL;
}

static size_t all_data_cb(void *ptr, size_t size, size_t nmemb, void *user_data)
{
	GByteArray *all_data = user_data;
	int len = size * nmemb;

	g_byte_array_append(all_data, ptr, len);

	return len;
}

void s3c_free_bucket(struct s3_bucket *buck)
{
	if (!buck)
		return;

	free(buck->name);
	free(buck->time_create);
	free(buck);
}

void s3c_free_blist(struct s3_blist *blist)
{
	GList *tmp;

	if (!blist)
		return;

	free(blist->own_id);
	free(blist->own_name);

	tmp = blist->list;
	while (tmp) {
		struct s3_bucket *buck;

		buck = tmp->data;
		s3c_free_bucket(buck);

		tmp = tmp->next;
	}

	g_list_free(blist->list);

	free(blist);
}

static void s3c_parse_buckets(xmlDocPtr doc, xmlNode *node,
			      struct s3_blist *blist)
{
	struct s3_bucket *buck;
	xmlNode *tmp;

	while (node) {
		if (node->type != XML_ELEMENT_NODE)
			goto next;

		if (_strcmp(node->name, "Bucket"))
			goto next;

		buck = calloc(1, sizeof(*buck));
		if (!buck)
			goto next;

		tmp = node->children;
		while (tmp) {
			if (tmp->type != XML_ELEMENT_NODE)
				goto next_tmp;

			if (!_strcmp(tmp->name, "Name"))
				buck->name = (char *) xmlNodeListGetString(doc,
							tmp->children, 1);

			else if (!_strcmp(tmp->name, "CreationDate"))
				buck->time_create = (char *)
					xmlNodeListGetString(doc,
							     tmp->children, 1);

next_tmp:
			tmp = tmp->next;
		}

		if (!buck->name)
			s3c_free_bucket(buck);
		else
			blist->list = g_list_append(blist->list, buck);

next:
		node = node->next;
	}
}

struct s3_blist *s3c_list_buckets(struct s3_client *s3c)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128], host[80];
	struct curl_slist *headers = NULL;
	struct s3_blist *blist;
	xmlDocPtr doc;
	xmlNode *node;
	xmlChar *xs;
	GByteArray *all_data;
	int rc;

	all_data = g_byte_array_new();
	if (!all_data)
		return NULL;

	memset(&req, 0, sizeof(req));
	req.method = "GET";
	req.orig_path = "/";

	sprintf(datestr, "Date: %s", time2str(timestr, time(NULL)));

	req_hdr_push(&req, "Date", timestr);

	req_sign(&req, NULL, s3c->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", s3c->user, hmac);
	sprintf(host, "Host: %s", s3c->host);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(s3c->curl);
	if (s3c->verbose)
		curl_easy_setopt(s3c->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(s3c->curl, CURLOPT_URL, "http://localhost:18080/");
	curl_easy_setopt(s3c->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(s3c->curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(s3c->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(s3c->curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(s3c->curl, CURLOPT_WRITEDATA, all_data);

	rc = curl_easy_perform(s3c->curl);

	curl_slist_free_all(headers);

	if (rc)
		goto err_out;

	doc = xmlReadMemory((char *) all_data->data, all_data->len,
			    "foo.xml", NULL, 0);
	if (!doc)
		goto err_out;

	node = xmlDocGetRootElement(doc);
	if (!node)
		goto err_out_doc;

	if (_strcmp(node->name, "ListAllMyBucketsResult"))
		goto err_out_doc;

	blist = calloc(1, sizeof(*blist));
	if (!blist)
		goto err_out_doc;

	node = node->children;
	while (node) {
		if (node->type != XML_ELEMENT_NODE) {
			node = node->next;
			continue;
		}

		if (!_strcmp(node->name, "Owner")) {
			xmlNode *tmp;

			tmp = node->children;
			while (tmp) {
				if (tmp->type != XML_ELEMENT_NODE) {
					tmp = tmp->next;
					continue;
				}

				if (!_strcmp(tmp->name, "ID")) {
					xs = xmlNodeListGetString(doc,
							tmp->children, 1);
					blist->own_id = strdup((char *)xs);
					xmlFree(xs);
				}

				else if (!_strcmp(tmp->name, "DisplayName")) {
					xs = xmlNodeListGetString(doc,
							tmp->children, 1);
					blist->own_name = strdup((char *)xs);
					xmlFree(xs);
				}

				tmp = tmp->next;
			}
		}

		else if (!_strcmp(node->name, "Buckets"))
			s3c_parse_buckets(doc, node->children, blist);

		node = node->next;
	}

	xmlFreeDoc(doc);
	g_byte_array_free(all_data, TRUE);
	all_data = NULL;

	return blist;

err_out_doc:
	xmlFreeDoc(doc);
err_out:
	g_byte_array_free(all_data, TRUE);
	all_data = NULL;
	return NULL;
}

static bool __s3c_ad_bucket(struct s3_client *s3c, const char *name,
			    bool delete)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128], host[80],
		url[80], orig_path[80];
	struct curl_slist *headers = NULL;
	int rc;

	sprintf(orig_path, "/%s/", name);

	memset(&req, 0, sizeof(req));
	req.method = delete ? "DELETE" : "PUT";
	req.orig_path = orig_path;

	sprintf(datestr, "Date: %s", time2str(timestr, time(NULL)));

	req_hdr_push(&req, "Date", timestr);

	req_sign(&req, NULL, s3c->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", s3c->user, hmac);
	sprintf(host, "Host: %s", s3c->host);
	sprintf(url, "http://localhost:18080/%s/", name);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(s3c->curl);
	if (s3c->verbose)
		curl_easy_setopt(s3c->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(s3c->curl, CURLOPT_URL, url);
	curl_easy_setopt(s3c->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(s3c->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(s3c->curl, CURLOPT_CUSTOMREQUEST, req.method);

	rc = curl_easy_perform(s3c->curl);

	curl_slist_free_all(headers);

	return (rc == 0);
}

bool s3c_add_bucket(struct s3_client *s3c, const char *name)
{
	return __s3c_ad_bucket(s3c, name, false);
}

bool s3c_del_bucket(struct s3_client *s3c, const char *name)
{
	return __s3c_ad_bucket(s3c, name, true);
}

bool s3c_get(struct s3_client *s3c, const char *bucket, const char *key,
	     size_t (*write_cb)(void *, size_t, size_t, void *),
	     void *user_data, bool want_headers)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128], host[80],
		url[80], *orig_path, *stmp;
	struct curl_slist *headers = NULL;
	int rc;

	if (asprintf(&stmp, "/%s/%s", bucket, key) < 0)
		return false;

	orig_path = field_escape(stmp, PATH_ESCAPE_MASK);

	memset(&req, 0, sizeof(req));
	req.method = "GET";
	req.orig_path = orig_path;

	sprintf(datestr, "Date: %s", time2str(timestr, time(NULL)));

	req_hdr_push(&req, "Date", timestr);

	req_sign(&req, NULL, s3c->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", s3c->user, hmac);
	sprintf(host, "Host: %s", s3c->host);
	sprintf(url, "http://localhost:18080%s", orig_path);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(s3c->curl);
	if (s3c->verbose)
		curl_easy_setopt(s3c->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(s3c->curl, CURLOPT_URL, url);
	curl_easy_setopt(s3c->curl, CURLOPT_HEADER, want_headers ? 1 : 0);
	curl_easy_setopt(s3c->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(s3c->curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(s3c->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(s3c->curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(s3c->curl, CURLOPT_WRITEDATA, user_data);

	rc = curl_easy_perform(s3c->curl);

	curl_slist_free_all(headers);
	free(orig_path);

	return (rc == 0);
}

void *s3c_get_inline(struct s3_client *s3c, const char *bucket, const char *key,
		     bool want_headers, size_t *len)
{
	bool rcb;
	void *mem;
	GByteArray *all_data;

	all_data = g_byte_array_new();
	if (!all_data)
		return NULL;

	rcb = s3c_get(s3c, bucket, key, all_data_cb, all_data, want_headers);
	if (!rcb) {
		g_byte_array_free(all_data, TRUE);
		return NULL;
	}

	if (len)
		*len = all_data->len;

	mem = all_data->data;

	g_byte_array_free(all_data, FALSE);
	return mem;
}

bool s3c_put(struct s3_client *s3c, const char *bucket, const char *key,
	     size_t (*read_cb)(void *, size_t, size_t, void *),
	     uint64_t len, void *user_data, char **user_hdrs)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128], host[80],
		url[80], *orig_path, *stmp;
	struct curl_slist *headers = NULL;
	int rc;

	if (asprintf(&stmp, "/%s/%s", bucket, key) < 0)
		return false;

	orig_path = field_escape(stmp, PATH_ESCAPE_MASK);

	memset(&req, 0, sizeof(req));
	req.method = "PUT";
	req.orig_path = orig_path;

	sprintf(datestr, "Date: %s", time2str(timestr, time(NULL)));

	req_hdr_push(&req, "Date", timestr);

	req_sign(&req, NULL, s3c->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", s3c->user, hmac);
	sprintf(host, "Host: %s", s3c->host);
	sprintf(url, "http://localhost:18080%s", orig_path);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	if (user_hdrs) {
		int idx = 0;

		while (user_hdrs[idx]) {
			headers = curl_slist_append(headers, user_hdrs[idx]);
			idx++;
		}
	}

	curl_easy_reset(s3c->curl);
	if (s3c->verbose)
		curl_easy_setopt(s3c->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(s3c->curl, CURLOPT_URL, url);
	curl_easy_setopt(s3c->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(s3c->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(s3c->curl, CURLOPT_READFUNCTION, read_cb);
	curl_easy_setopt(s3c->curl, CURLOPT_READDATA, user_data);
	curl_easy_setopt(s3c->curl, CURLOPT_CUSTOMREQUEST, req.method);
	curl_easy_setopt(s3c->curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(s3c->curl, CURLOPT_INFILESIZE_LARGE, len);

	rc = curl_easy_perform(s3c->curl);

	curl_slist_free_all(headers);
	free(orig_path);

	return (rc == 0);
}

struct s3c_put_info {
	void		*data;
	uint64_t	len;
};

static size_t read_inline_cb(void *ptr, size_t size, size_t nmemb,
			     void *user_data)
{
	struct s3c_put_info *spi = user_data;
	int len = size * nmemb;

	len = MIN(len, spi->len);
	if (len) {
		memcpy(ptr, spi->data, len);
		spi->data += len;
		spi->len -= len;
	}

	return len;
}

bool s3c_put_inline(struct s3_client *s3c, const char *bucket, const char *key,
	     void *data, uint64_t len, char **user_hdrs)
{
	struct s3c_put_info spi = { data, len };

	return s3c_put(s3c, bucket, key, read_inline_cb, len, &spi, user_hdrs);
}

bool s3c_del(struct s3_client *s3c, const char *bucket, const char *key)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128], host[80],
		url[80], *orig_path, *stmp;
	struct curl_slist *headers = NULL;
	int rc;

	if (asprintf(&stmp, "/%s/%s", bucket, key) < 0)
		return false;

	orig_path = field_escape(stmp, PATH_ESCAPE_MASK);

	memset(&req, 0, sizeof(req));
	req.method = "DELETE";
	req.orig_path = orig_path;

	sprintf(datestr, "Date: %s", time2str(timestr, time(NULL)));

	req_hdr_push(&req, "Date", timestr);

	req_sign(&req, NULL, s3c->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", s3c->user, hmac);
	sprintf(host, "Host: %s", s3c->host);
	sprintf(url, "http://localhost:18080%s", orig_path);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(s3c->curl);
	if (s3c->verbose)
		curl_easy_setopt(s3c->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(s3c->curl, CURLOPT_URL, url);
	curl_easy_setopt(s3c->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(s3c->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(s3c->curl, CURLOPT_CUSTOMREQUEST, req.method);

	rc = curl_easy_perform(s3c->curl);

	curl_slist_free_all(headers);
	free(orig_path);

	return (rc == 0);
}

GString *append_qparam(GString *str, const char *key, const char *val,
		       char *arg_char)
{
	char *stmp, s[32];

	str = g_string_append(str, arg_char);
	arg_char[0] = '&';

	sprintf(s, "%s=", key);
	str = g_string_append(str, key);

	stmp = field_escape(strdup(val), QUERY_ESCAPE_MASK);
	str = g_string_append(str, stmp);
	free(stmp);

	return str;
}

void s3c_free_object(struct s3_object *obj)
{
	if (!obj)
		return;

	free(obj->key);
	free(obj->time_mod);
	free(obj->etag);
	free(obj->storage);
	free(obj->own_id);
	free(obj->own_name);
	free(obj);
}

void s3c_free_keylist(struct s3_keylist *keylist)
{
	GList *tmp;

	if (!keylist)
		return;

	free(keylist->name);
	free(keylist->prefix);
	free(keylist->marker);
	free(keylist->delim);

	tmp = keylist->common_pfx;
	while (tmp) {
		free(tmp->data);
		tmp = tmp->next;
	}

	tmp = keylist->contents;
	while (tmp) {
		s3c_free_object(tmp->data);
		tmp = tmp->next;
	}
	g_list_free(keylist->contents);

	free(keylist);
}

static void s3c_parse_key(xmlDocPtr doc, xmlNode *node,
			  struct s3_keylist *keylist)
{
	struct s3_object *obj = calloc(1, sizeof(*obj));
	xmlChar *xs;

	obj = calloc(1, sizeof(*obj));
	if (!obj)
		return;

	while (node) {
		if (node->type != XML_ELEMENT_NODE) {
			node = node->next;
			continue;
		}

		if (!_strcmp(node->name, "Key")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			obj->key = strdup((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "LastModified")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			obj->time_mod = strdup((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "ETag")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			obj->etag = strdup((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "Size")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			obj->size = atoll((char *) xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "StorageClass")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			obj->storage = strdup((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "Owner")) {
			xmlNode *tmp;

			tmp = node->children;
			while (tmp) {
				if (tmp->type != XML_ELEMENT_NODE) {
					tmp = tmp->next;
					continue;
				}

				if (!_strcmp(tmp->name, "ID")) {
					xs = xmlNodeListGetString(doc,
							tmp->children, 1);
					obj->own_id = strdup((char *)xs);
					xmlFree(xs);
				}

				else if (!_strcmp(tmp->name, "DisplayName")) {
					xs = xmlNodeListGetString(doc,
							tmp->children, 1);
					obj->own_name = strdup((char *)xs);
					xmlFree(xs);
				}

				tmp = tmp->next;
			}
		}

		node = node->next;
	}

	if (obj->key)
		keylist->contents = g_list_append(keylist->contents, obj);
	else
		s3c_free_object(obj);
}

struct s3_keylist *s3c_keys(struct s3_client *s3c, const char *bucket,
			    const char *prefix, const char *marker,
			    const char *delim, unsigned int max_keys)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128], host[80];
	char orig_path[strlen(bucket) + 8];
	struct curl_slist *headers = NULL;
	struct s3_keylist *keylist;
	xmlDocPtr doc;
	xmlNode *node;
	xmlChar *xs;
	GByteArray *all_data;
	GString *url;
	int rc;
	char arg_char[2] = "?";

	all_data = g_byte_array_new();
	if (!all_data)
		return NULL;

	sprintf(orig_path, "/%s/", bucket);

	memset(&req, 0, sizeof(req));
	req.method = "GET";
	req.orig_path = orig_path;

	sprintf(datestr, "Date: %s", time2str(timestr, time(NULL)));

	req_hdr_push(&req, "Date", timestr);

	req_sign(&req, NULL, s3c->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", s3c->user, hmac);
	sprintf(host, "Host: %s", s3c->host);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	url = g_string_sized_new(256);
	if (!url) {
		curl_slist_free_all(headers);
		goto err_out;
	}

	url = g_string_append(url, "http://localhost:18080");
	url = g_string_append(url, orig_path);

	if (prefix)
		url = append_qparam(url, "prefix", prefix, arg_char);
	if (marker)
		url = append_qparam(url, "marker", marker, arg_char);
	if (delim)
		url = append_qparam(url, "delimiter", delim, arg_char);
	if (max_keys) {
		char mk[32];
		sprintf(mk, "%smax-keys=%u", arg_char, max_keys);
		url = g_string_append(url, mk);
	}

	curl_easy_reset(s3c->curl);
	if (s3c->verbose)
		curl_easy_setopt(s3c->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(s3c->curl, CURLOPT_URL, url->str);
	curl_easy_setopt(s3c->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(s3c->curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(s3c->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(s3c->curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(s3c->curl, CURLOPT_WRITEDATA, all_data);

	rc = curl_easy_perform(s3c->curl);

	g_string_free(url, TRUE);
	curl_slist_free_all(headers);

	if (rc)
		goto err_out;

	doc = xmlReadMemory((char *) all_data->data, all_data->len,
			    "foo.xml", NULL, 0);
	if (!doc)
		goto err_out;

	node = xmlDocGetRootElement(doc);
	if (!node)
		goto err_out_doc;

	if (_strcmp(node->name, "ListBucketResult"))
		goto err_out_doc;

	keylist = calloc(1, sizeof(*keylist));
	if (!keylist)
		goto err_out_doc;

	node = node->children;
	while (node) {
		if (node->type != XML_ELEMENT_NODE) {
			node = node->next;
			continue;
		}

		if (!_strcmp(node->name, "Name")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			keylist->name = strdup((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "Prefix")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			keylist->prefix = strdup((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "Marker")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			keylist->marker = strdup((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "Delimiter")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			keylist->delim = strdup((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "MaxKeys")) {
			xs = xmlNodeListGetString(doc, node->children, 1);
			keylist->max_keys = (unsigned int) atoi((char *)xs);
			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "IsTruncated")) {
			xs = xmlNodeListGetString(doc, node->children, 1);

			if (!_strcasecmp(xs, "true"))
				keylist->trunc = true;
			else if (!_strcasecmp(xs, "1"))
				keylist->trunc = true;
			else
				keylist->trunc = false;

			xmlFree(xs);
		}
		else if (!_strcmp(node->name, "CommonPrefixes")) {
			xmlNode *tmp;

			tmp = node->children;
			while (tmp) {
				if (tmp->type != XML_ELEMENT_NODE) {
					tmp = tmp->next;
					continue;
				}

				if (!_strcmp(tmp->name, "Prefix")) {
					xs = xmlNodeListGetString(doc,
							tmp->children, 1);
					keylist->common_pfx =
						g_list_append(
							keylist->common_pfx,
							strdup((char *)xs));
					xmlFree(xs);
				}

				tmp = tmp->next;
			}
		}
		else if (!_strcmp(node->name, "Contents"))
			s3c_parse_key(doc, node->children, keylist);

		node = node->next;
	}

	xmlFreeDoc(doc);
	g_byte_array_free(all_data, TRUE);
	all_data = NULL;

	return keylist;

err_out_doc:
	xmlFreeDoc(doc);
err_out:
	g_byte_array_free(all_data, TRUE);
	all_data = NULL;
	return NULL;
}

