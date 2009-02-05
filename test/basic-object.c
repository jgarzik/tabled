
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

#include "tabled-config.h"
#include <string.h>
#include <locale.h>
#include <s3c.h>
#include "test.h"

int main(int argc, char *argv[])
{
	struct s3_client *s3c;
	bool rcb;
	char val[] = "my first value";
	char key[] = "my first key";
	size_t len = 0;
	void *mem;

	setlocale(LC_ALL, "C");

	s3c = s3c_new(TEST_HOST, TEST_USER, TEST_USER_KEY);
	OK(s3c);

	/* add bucket */
	rcb = s3c_add_bucket(s3c, "test1");
	OK(rcb);

	/* store object */
	rcb = s3c_put_inline(s3c, "test1", key, val, strlen(val), NULL);
	OK(rcb);

	/* get object */
	mem = s3c_get_inline(s3c, "test1", key, false, &len);
	OK(mem);
	OK(len == strlen(val));
	OK(!memcmp(val, mem, strlen(val)));

	/* delete object */
	rcb = s3c_del(s3c, "test1", key);
	OK(rcb);

	/* delete bucket */
	rcb = s3c_del_bucket(s3c, "test1");
	OK(rcb);

	return 0;
}
