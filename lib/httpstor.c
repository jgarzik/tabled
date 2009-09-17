
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
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <libxml/tree.h>
#include <glib.h>
#include <httpstor.h>
#include <httputil.h>

static int _strcasecmp(const unsigned char *a, const char *b)
{
	return xmlStrcasecmp(a, (const unsigned char *) b);
}

static int _strcmp(const unsigned char *a, const char *b)
{
	return xmlStrcmp(a, (const unsigned char *) b);
}

void httpstor_free(struct httpstor_client *httpstor)
{
	if (httpstor->curl)
		curl_easy_cleanup(httpstor->curl);
	free(httpstor->acc);
	free(httpstor->host);
	free(httpstor->user);
	free(httpstor->key);
	free(httpstor);
}

/*
 * The service accessor is a "host:port" string that gets resolved to IP
 * address and then create a TCP connection to the server. The service host,
 * however, is used to form the "Host: host" HTTP header. The host of the
 * accessor should be the same on the sane installations, but whatever.
 */
struct httpstor_client *httpstor_new(const char *service_acc,
	const char *service_host, const char *user, const char *secret_key)
{
	struct httpstor_client *httpstor;

	httpstor = calloc(1, sizeof(struct httpstor_client));
	if (!httpstor)
		return NULL;

	httpstor->acc = strdup(service_acc);
	httpstor->host = strdup(service_host);
	httpstor->user = strdup(user);
	httpstor->key = strdup(secret_key);
	if (!httpstor->acc || !httpstor->host || !httpstor->user || !httpstor->key)
		goto err_out;

	if (curl_global_init(CURL_GLOBAL_ALL))
		goto err_out;

	httpstor->curl = curl_easy_init();
	if (!httpstor->curl)
		goto err_out;

	return httpstor;

err_out:
	httpstor_free(httpstor);
	return NULL;
}

static size_t all_data_cb(void *ptr, size_t size, size_t nmemb, void *user_data)
{
	GByteArray *all_data = user_data;
	int len = size * nmemb;

	g_byte_array_append(all_data, ptr, len);

	return len;
}

void httpstor_free_bucket(struct httpstor_bucket *buck)
{
	if (!buck)
		return;

	free(buck->name);
	free(buck->time_create);
	free(buck);
}

void httpstor_free_blist(struct httpstor_blist *blist)
{
	GList *tmp;

	if (!blist)
		return;

	free(blist->own_id);
	free(blist->own_name);

	tmp = blist->list;
	while (tmp) {
		struct httpstor_bucket *buck;

		buck = tmp->data;
		httpstor_free_bucket(buck);

		tmp = tmp->next;
	}

	g_list_free(blist->list);

	free(blist);
}

static void httpstor_parse_buckets(xmlDocPtr doc, xmlNode *node,
			      struct httpstor_blist *blist)
{
	struct httpstor_bucket *buck;
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
			httpstor_free_bucket(buck);
		else
			blist->list = g_list_append(blist->list, buck);

next:
		node = node->next;
	}
}

struct httpstor_blist *httpstor_list_buckets(struct httpstor_client *httpstor)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128], host[80], url[80];
	struct curl_slist *headers = NULL;
	struct httpstor_blist *blist;
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

	req_sign(&req, NULL, httpstor->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", httpstor->user, hmac);
	sprintf(host, "Host: %s", httpstor->host);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	snprintf(url, sizeof(url), "http://%s/", httpstor->acc);

	curl_easy_reset(httpstor->curl);
	if (httpstor->verbose)
		curl_easy_setopt(httpstor->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(httpstor->curl, CURLOPT_URL, url);
	curl_easy_setopt(httpstor->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(httpstor->curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(httpstor->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(httpstor->curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(httpstor->curl, CURLOPT_WRITEDATA, all_data);
	curl_easy_setopt(httpstor->curl, CURLOPT_TCP_NODELAY, 1);

	rc = curl_easy_perform(httpstor->curl);

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
			httpstor_parse_buckets(doc, node->children, blist);

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

static bool __httpstor_ad_bucket(struct httpstor_client *httpstor, const char *name,
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

	req_sign(&req, NULL, httpstor->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", httpstor->user, hmac);
	sprintf(host, "Host: %s", httpstor->host);
	snprintf(url, sizeof(url), "http://%s/%s/", httpstor->acc, name);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(httpstor->curl);
	if (httpstor->verbose)
		curl_easy_setopt(httpstor->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(httpstor->curl, CURLOPT_URL, url);
	curl_easy_setopt(httpstor->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(httpstor->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(httpstor->curl, CURLOPT_CUSTOMREQUEST, req.method);
	curl_easy_setopt(httpstor->curl, CURLOPT_TCP_NODELAY, 1);

	rc = curl_easy_perform(httpstor->curl);

	curl_slist_free_all(headers);

	return (rc == 0);
}

bool httpstor_add_bucket(struct httpstor_client *httpstor, const char *name)
{
	return __httpstor_ad_bucket(httpstor, name, false);
}

bool httpstor_del_bucket(struct httpstor_client *httpstor, const char *name)
{
	return __httpstor_ad_bucket(httpstor, name, true);
}

bool httpstor_get(struct httpstor_client *httpstor, const char *bucket, const char *key,
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

	req_sign(&req, NULL, httpstor->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", httpstor->user, hmac);
	sprintf(host, "Host: %s", httpstor->host);
	snprintf(url, sizeof(url), "http://%s%s", httpstor->acc, orig_path);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(httpstor->curl);
	if (httpstor->verbose)
		curl_easy_setopt(httpstor->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(httpstor->curl, CURLOPT_URL, url);
	curl_easy_setopt(httpstor->curl, CURLOPT_HEADER, want_headers ? 1 : 0);
	curl_easy_setopt(httpstor->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(httpstor->curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(httpstor->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(httpstor->curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(httpstor->curl, CURLOPT_WRITEDATA, user_data);
	curl_easy_setopt(httpstor->curl, CURLOPT_TCP_NODELAY, 1);

	rc = curl_easy_perform(httpstor->curl);

	curl_slist_free_all(headers);
	free(orig_path);

	return (rc == 0);
}

void *httpstor_get_inline(struct httpstor_client *httpstor, const char *bucket, const char *key,
		     bool want_headers, size_t *len)
{
	bool rcb;
	void *mem;
	GByteArray *all_data;

	all_data = g_byte_array_new();
	if (!all_data)
		return NULL;

	rcb = httpstor_get(httpstor, bucket, key, all_data_cb, all_data, want_headers);
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

bool httpstor_put(struct httpstor_client *httpstor, const char *bucket, const char *key,
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

	req_sign(&req, NULL, httpstor->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", httpstor->user, hmac);
	sprintf(host, "Host: %s", httpstor->host);
	snprintf(url, sizeof(url), "http://%s%s", httpstor->acc, orig_path);

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

	curl_easy_reset(httpstor->curl);
	if (httpstor->verbose)
		curl_easy_setopt(httpstor->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(httpstor->curl, CURLOPT_URL, url);
	curl_easy_setopt(httpstor->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(httpstor->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(httpstor->curl, CURLOPT_READFUNCTION, read_cb);
	curl_easy_setopt(httpstor->curl, CURLOPT_READDATA, user_data);
	curl_easy_setopt(httpstor->curl, CURLOPT_CUSTOMREQUEST, req.method);
	curl_easy_setopt(httpstor->curl, CURLOPT_UPLOAD, 1);
	curl_easy_setopt(httpstor->curl, CURLOPT_INFILESIZE_LARGE,
			 (curl_off_t)len);
	curl_easy_setopt(httpstor->curl, CURLOPT_TCP_NODELAY, 1);

	rc = curl_easy_perform(httpstor->curl);

	curl_slist_free_all(headers);
	free(orig_path);

	return (rc == 0);
}

struct httpstor_put_info {
	void		*data;
	uint64_t	len;
};

static size_t read_inline_cb(void *ptr, size_t size, size_t nmemb,
			     void *user_data)
{
	struct httpstor_put_info *spi = user_data;
	int len = size * nmemb;

	len = MIN(len, spi->len);
	if (len) {
		memcpy(ptr, spi->data, len);
		spi->data += len;
		spi->len -= len;
	}

	return len;
}

bool httpstor_put_inline(struct httpstor_client *httpstor, const char *bucket, const char *key,
	     void *data, uint64_t len, char **user_hdrs)
{
	struct httpstor_put_info spi = { data, len };

	return httpstor_put(httpstor, bucket, key, read_inline_cb, len, &spi, user_hdrs);
}

bool httpstor_del(struct httpstor_client *httpstor, const char *bucket, const char *key)
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

	req_sign(&req, NULL, httpstor->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", httpstor->user, hmac);
	sprintf(host, "Host: %s", httpstor->host);
	snprintf(url, sizeof(url), "http://%s%s", httpstor->acc, orig_path);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	curl_easy_reset(httpstor->curl);
	if (httpstor->verbose)
		curl_easy_setopt(httpstor->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(httpstor->curl, CURLOPT_URL, url);
	curl_easy_setopt(httpstor->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(httpstor->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(httpstor->curl, CURLOPT_CUSTOMREQUEST, req.method);
	curl_easy_setopt(httpstor->curl, CURLOPT_TCP_NODELAY, 1);

	rc = curl_easy_perform(httpstor->curl);

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

void httpstor_free_object(struct httpstor_object *obj)
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

void httpstor_free_keylist(struct httpstor_keylist *keylist)
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
		httpstor_free_object(tmp->data);
		tmp = tmp->next;
	}
	g_list_free(keylist->contents);

	free(keylist);
}

static void httpstor_parse_key(xmlDocPtr doc, xmlNode *node,
			  struct httpstor_keylist *keylist)
{
	struct httpstor_object *obj = calloc(1, sizeof(*obj));
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
		httpstor_free_object(obj);
}

struct httpstor_keylist *httpstor_keys(struct httpstor_client *httpstor, const char *bucket,
			    const char *prefix, const char *marker,
			    const char *delim, unsigned int max_keys)
{
	struct http_req req;
	char datestr[80], timestr[64], hmac[64], auth[128], host[80];
	char orig_path[strlen(bucket) + 8];
	struct curl_slist *headers = NULL;
	struct httpstor_keylist *keylist;
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

	req_sign(&req, NULL, httpstor->key, hmac);

	sprintf(auth, "Authorization: AWS %s:%s", httpstor->user, hmac);
	sprintf(host, "Host: %s", httpstor->host);

	headers = curl_slist_append(headers, host);
	headers = curl_slist_append(headers, datestr);
	headers = curl_slist_append(headers, auth);

	url = g_string_sized_new(256);
	if (!url) {
		curl_slist_free_all(headers);
		goto err_out;
	}

	url = g_string_append(url, "http://");
	url = g_string_append(url, httpstor->acc);
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

	curl_easy_reset(httpstor->curl);
	if (httpstor->verbose)
		curl_easy_setopt(httpstor->curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(httpstor->curl, CURLOPT_URL, url->str);
	curl_easy_setopt(httpstor->curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(httpstor->curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(httpstor->curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(httpstor->curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(httpstor->curl, CURLOPT_WRITEDATA, all_data);
	curl_easy_setopt(httpstor->curl, CURLOPT_TCP_NODELAY, 1);

	rc = curl_easy_perform(httpstor->curl);

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
			httpstor_parse_key(doc, node->children, keylist);

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

