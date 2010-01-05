
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

#include <string.h>
#include <locale.h>
#include <httpstor.h>
#include <httputil.h>
#include "test.h"

int main(int argc, char *argv[])
{
	static char bucket[] = "test1";
	static char key[] = "my first key";
	struct httpstor_client *httpstor;
	char accbuf[80];
	int rc;
	bool rcb;
	char val[] = "my first value";
	size_t len = 0;
	void *mem;

	setlocale(LC_ALL, "C");

	rc = tb_readport(TEST_FILE_TB, accbuf, sizeof(accbuf));
	OK(rc > 0);

	httpstor = httpstor_new(accbuf, TEST_HOST, TEST_USER, TEST_USER_KEY);
	OK(httpstor);

	/* add bucket */
	rcb = httpstor_add_bucket(httpstor, bucket);
	OK(rcb);

	/* store object */
	rcb = httpstor_put_inline(httpstor, bucket, key, val, strlen(val), NULL);
	OK(rcb);

	/* get object */
	mem = httpstor_get_inline(httpstor, bucket, key, false, &len);
	OK(mem);
	OK(len == strlen(val));
	OK(!memcmp(val, mem, strlen(val)));

	/* delete object */
	rcb = httpstor_del(httpstor, bucket, key);
	OK(rcb);

	/* delete bucket */
	rcb = httpstor_del_bucket(httpstor, bucket);
	OK(rcb);

	return 0;
}
