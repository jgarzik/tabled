
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
/*
 * A large object test verifies the workings of bizarrely complicated and
 * subtle mechanics of the sliding windows and flow control when tabled
 * pipes the data between its client and the back-end chunkservers.
 * As such, we have to defend against hungs as well as corruption.
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

static char bucket[] = "test-hdr-ctt";
static char key[] = "Key of HDR ctt test";
static char value[] = "Value of HDR ctt test";

static char *user_hdrs[] = {
	"Content-type: text/x-tabled-test",
	NULL
};

static bool find_our_hdr(const void *data, size_t data_len)
{
	const void *p = data;
	size_t len = data_len;

	while (len > 0) {
		void *eol;
		size_t llen, real_len;
		const char *s;

		eol = memchr(p, '\n', len);
		if (!eol)
			llen = len;
		else
			llen = eol - p + 1;

		real_len = llen;
		s = p;
		while (real_len > 0) {
			if (!isspace(s[real_len - 1]))
				break;

			real_len--;
		}

		if (!strncasecmp(user_hdrs[0], p, real_len))
			return true;

		p += llen;
		len -= llen;
	}

	return false;
}

static void runtest(struct httpstor_client *httpstor)
{
	bool rcb;
	void *data = NULL;
	size_t data_len = 0;

	rcb = httpstor_put_inline(httpstor, bucket, key,
				  value, strlen(value) + 1, user_hdrs);
	OK(rcb);

	data = httpstor_get_inline(httpstor, bucket, key, true, &data_len);
	OK(data);
	OK(data_len > 0);

	rcb = find_our_hdr(data, data_len);
	OK(rcb);

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
