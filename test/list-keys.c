
/*
 * Copyright 2008-2010 Red Hat, Inc.
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

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
// #include <ctype.h>
#include <locale.h>
#include <glib.h>
#include <hstor.h>
#include "test.h"

static char bucket[] = "test-hdr-meta";
static char key[] = "test-key";
static char value[] = "test-value";

static void runtest(struct hstor_client *hstor)
{
	struct hstor_keylist *keylist;
	struct hstor_object *obj;
	GList *tmp;
	int cnt;

	keylist = hstor_keys(hstor, bucket, "", NULL, "/", 20);
	OK(keylist);

	cnt = 0;
	tmp = keylist->contents;
	while (tmp) {
		obj = tmp->data;
		if (strcmp(obj->key, key) != 0) {
			fprintf(stderr, "bad object key %s\n", obj->key);
			exit(1);
		}
		if (obj->size != sizeof(value)) {
			fprintf(stderr, "bad object size %ld\n",
				(long)obj->size);
			exit(1);
		}
		cnt++;
		tmp = tmp->next;
	}
	if (cnt != 1) {
		fprintf(stderr, "bad object count %d\n", cnt);
		exit(1);
	}

	hstor_free_keylist(keylist);
}

int main(int argc, char *argv[])
{
	struct hstor_client *hstor;
	char accbuf[80];
	int rc;
	bool rcb;

	setlocale(LC_ALL, "C");

	rc = tb_readport(TEST_FILE_TB, accbuf, sizeof(accbuf));
	OK(rc > 0);

	hstor = hstor_new(accbuf, TEST_HOST, TEST_USER, TEST_USER_KEY);
	OK(hstor);

	/* add bucket - since tests are independent, we do not rely on others */
	rcb = hstor_add_bucket(hstor, bucket);
	OK(rcb);

	rcb = hstor_put_inline(hstor, bucket, key, value, sizeof(value), NULL);
	OK(rcb);

	runtest(hstor);

	rcb = hstor_del(hstor, bucket, key);
	OK(rcb);

	rcb = hstor_del_bucket(hstor, bucket);
	OK(rcb);

	return 0;
}

