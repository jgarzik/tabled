
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
	struct s3_blist *blist;

	setlocale(LC_ALL, "C");

	s3c = s3c_new(TEST_HOST, TEST_USER, TEST_USER_KEY);
	OK(s3c);

	blist = s3c_list_buckets(s3c);
	OK(blist);

	OK(!strcmp(blist->own_id, s3c->user));
	OK(!strcmp(blist->own_name, s3c->user));
	OK(!blist->list);

	return 0;
}
