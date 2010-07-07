
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
#include <locale.h>
#include <hstor.h>
#include "test.h"

#define BLKSZ0	1024
#define NBLKS0	1

#define BLKSZ1	15001
#define NBLKS1	211

#define BLKSZ2	256
#define NBLKS2	30000

struct put_ctx {
	unsigned int csum;
	unsigned int blksize;
	unsigned long off;
	unsigned long total;
};

struct get_ctx {
	unsigned int csum;
	unsigned int blksize;
	unsigned long off;
};

static char bucket[] = "test-large";
static char key[] = "Key of Large Object";

#define CSUM_INIT  0xFFFFFFFF

static void incrsum(unsigned int *psum, unsigned char *data, size_t len)
{
	unsigned int sum;

	sum = *psum;
	while (len) {
		sum ^= *data;
		sum = sum << 1 | sum >> 31;
		data++;
		--len;
	}
	*psum = sum;
}

static size_t put_cb(void *ptr, size_t membsize, size_t nmemb, void *user_data)
{
	struct put_ctx *ctx = user_data;
	unsigned char *data = ptr;
	unsigned num;
	size_t rem;
	size_t off;

	OK(membsize == 1);

	if (ctx->off >= ctx->total)
		return 0;

	num = ctx->off / ctx->blksize;		/* current block number */
	off = ctx->off % ctx->blksize;		/* done in the block */
	rem = ctx->blksize - off;		/* to do in the block */
	if (rem > nmemb)
		rem = nmemb;
	if (rem > ctx->total - ctx->off)
		rem = ctx->total - ctx->off;

	memset(data, 0, rem);
	if (off + rem == ctx->blksize)
		data[rem - 1] = ~num;
	if (off == 0)
		data[0] = num;

	incrsum(&ctx->csum, data, rem);

	ctx->off += rem;

	return rem;
}

static size_t get_one(struct get_ctx *ctx, unsigned char *data, size_t len)
{
	unsigned num;
	size_t rem;
	size_t off;

	num = ctx->off / ctx->blksize;		/* current block number */
	off = ctx->off % ctx->blksize;		/* done in the block */
	rem = ctx->blksize - off;		/* to do in the block */
	if (rem > len)
		rem = len;

	if (off + rem == ctx->blksize) {
		if (data[rem - 1] != (unsigned char) ~num) {
			fprintf(stderr, "get chk fail tail:"
				" blk %u data 0x%02x blksize"
				" %u off %lu rem %lu\n",
				num, data[rem-1], ctx->blksize,
				(long)off, (long)rem);
			exit(1);
		}
	}
	if (off == 0) {
		if (data[0] != (unsigned char) num) {
			fprintf(stderr, "get chk fail head:"
				" blk %u data 0x%02x blksize %u\n",
				num, data[0], ctx->blksize);
			exit(1);
		}
	}

	ctx->off += rem;
	return rem;
}

static size_t get_cb(void *ptr, size_t membsize, size_t nmemb, void *user_data)
{
	struct get_ctx *ctx = user_data;
	size_t togo, len;

	OK(membsize == 1);

	incrsum(&ctx->csum, ptr, nmemb);

	togo = nmemb;
	while (togo) {
		len = get_one(ctx, ptr, togo);
		togo -= len;
		ptr += len;
	}
	return nmemb;
}

static void runtest(struct hstor_client *hstor,
		    size_t blklen, int nblks)
{
	off_t total = blklen * nblks;
	unsigned int checksum;
	struct put_ctx putctx;
	struct get_ctx getctx;
	bool rcb;

	memset(&putctx, 0, sizeof(putctx));
	putctx.csum = CSUM_INIT;
	putctx.blksize = blklen;
	putctx.total = total;

	rcb = hstor_put(hstor, bucket, key, put_cb, total, &putctx, NULL);
	OK(rcb);
	OK(putctx.off == total);

	checksum = putctx.csum;

	memset(&getctx, 0, sizeof(getctx));
	getctx.csum = CSUM_INIT;
	getctx.blksize = blklen;

	rcb = hstor_get(hstor, bucket, key, get_cb, &getctx, false);
	OK(rcb);
	OK(getctx.off == total);

	OK(checksum == getctx.csum);
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

	runtest(hstor, BLKSZ0, NBLKS0);
	runtest(hstor, BLKSZ1, NBLKS1);
	runtest(hstor, BLKSZ2, NBLKS2);

	rcb = hstor_del(hstor, bucket, key);
	OK(rcb);

	rcb = hstor_del_bucket(hstor, bucket);
	OK(rcb);

	return 0;
}
