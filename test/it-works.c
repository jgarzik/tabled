
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
	struct httpstor_client *httpstor;
	struct httpstor_blist *blist;
	char accbuf[80];
	int rc;

	setlocale(LC_ALL, "C");

	rc = tb_readport(TEST_FILE_TB, accbuf, sizeof(accbuf));
	OK(rc > 0);

	httpstor = httpstor_new(accbuf, TEST_HOST, TEST_USER, TEST_USER_KEY);
	OK(httpstor);

	blist = httpstor_list_buckets(httpstor);
	OK(blist);

	OK(!strcmp(blist->own_id, httpstor->user));
	OK(!strcmp(blist->own_name, httpstor->user));
	OK(!blist->list);

	return 0;
}
