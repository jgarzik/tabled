
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
#include <hstor.h>
#include "test.h"

static char bucket[] = "test-hdr-ctt";
static char key[] = "Key of HDR ctt test";
static char value[] = "Value of HDR ctt test";

static char *user_hdrs[] = {
	"Content-type: text/x-tabled-test",
	NULL
};

static void runtest(struct hstor_client *hstor)
{
	bool rcb;
	void *data = NULL;
	size_t data_len = 0;

	rcb = hstor_put_inline(hstor, bucket, key,
				  value, strlen(value) + 1, user_hdrs);
	OK(rcb);

	data = hstor_get_inline(hstor, bucket, key, true, &data_len);
	OK(data);
	OK(data_len > 0);

	rcb = find_our_hdr(user_hdrs[0], data, data_len);
	OK(rcb);

	free(data);
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

	runtest(hstor);

	rcb = hstor_del(hstor, bucket, key);
	OK(rcb);

	rcb = hstor_del_bucket(hstor, bucket);
	OK(rcb);

	return 0;
}
