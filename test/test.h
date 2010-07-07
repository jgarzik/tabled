#ifndef __TABLED_TEST_H__
#define __TABLED_TEST_H__

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

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#define TEST_HOST "pretzel.yyz.us"
#define TEST_USER "testuser"
#define TEST_USER_KEY "testpw"

#define TEST_FILE_TB  "tabled.acc"

#define OK(expr)				\
	do {					\
		if (!(expr)) {			\
			fprintf(stderr, "test failed on line %d\n", \
				__LINE__);	\
			exit(1);		\
		}				\
	} while (0)

extern bool find_our_hdr(const char *hdr, const void *data, size_t data_len);
extern int tb_readport(const char *fname, char *buf, size_t len);

#endif /* __TABLED_TEST_H__ */
