
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
	struct httpstor_bucket *buck;
	bool rcb;
	char accbuf[80];
	int rc;

	setlocale(LC_ALL, "C");

	rc = tb_readport(TEST_FILE_TB, accbuf, sizeof(accbuf));
	OK(rc > 0);

	httpstor = httpstor_new(accbuf, TEST_HOST, TEST_USER, TEST_USER_KEY);
	OK(httpstor);

	/* make sure bucket list is empty */
	blist = httpstor_list_buckets(httpstor);
	OK(blist);
	OK(!blist->list);

	httpstor_free_blist(blist);

	/* add bucket */
	rcb = httpstor_add_bucket(httpstor, "test1");
	OK(rcb);

	/* make sure bucket list contains one item */
	blist = httpstor_list_buckets(httpstor);
	OK(blist);
	OK(blist->list);
	OK(blist->list->next == NULL);

	buck = blist->list->data;
	OK(!strcmp(buck->name, "test1"));

	httpstor_free_blist(blist);

	/* delete bucket */
	rcb = httpstor_del_bucket(httpstor, "test1");
	OK(rcb);

	/* make sure bucket list is empty */
	blist = httpstor_list_buckets(httpstor);
	OK(blist);
	OK(!blist->list);

	httpstor_free_blist(blist);

	return 0;
}
