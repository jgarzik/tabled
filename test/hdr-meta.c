
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
#include <ctype.h>
#include <locale.h>
#include <httpstor.h>
#include <httputil.h>
#include "test.h"

static char bucket[] = "test-hdr-meta";
static char key[] = "Key of HDR meta test";
static char value[] = "Value of HDR meta test";

static char *user_hdrs[] = {
	"x-amz-meta-test1: foo bar",
	"x-amz-meta-test2: foo bar baz zonk zip",
	NULL
};

static void runtest(struct httpstor_client *httpstor)
{
	bool rcb;
	void *data = NULL;
	size_t data_len = 0;
	int idx;

	rcb = httpstor_put_inline(httpstor, bucket, key,
				  value, strlen(value) + 1, user_hdrs);
	OK(rcb);

	data = httpstor_get_inline(httpstor, bucket, key, true, &data_len);
	OK(data);
	OK(data_len > 0);

	idx = 0;
	while (user_hdrs[idx]) {
		rcb = find_our_hdr(user_hdrs[idx], data, data_len);
		OK(rcb);

		idx++;
	}

	free(data);
}

int main(int argc, char *argv[])
{
	struct httpstor_client *httpstor;
	char accbuf[80];
	int rc;
	bool rcb;

	setlocale(LC_ALL, "C");

	rc = tb_readport(TEST_FILE_TB, accbuf, sizeof(accbuf));
	OK(rc > 0);

	httpstor = httpstor_new(accbuf, TEST_HOST, TEST_USER, TEST_USER_KEY);
	OK(httpstor);

	/* add bucket - since tests are independent, we do not rely on others */
	rcb = httpstor_add_bucket(httpstor, bucket);
	OK(rcb);

	runtest(httpstor);

	rcb = httpstor_del(httpstor, bucket, key);
	OK(rcb);

	rcb = httpstor_del_bucket(httpstor, bucket);
	OK(rcb);

	return 0;
}
