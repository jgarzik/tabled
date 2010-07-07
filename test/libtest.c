
/*
 * Copyright 2010 Red Hat, Inc.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include "test.h"

bool find_our_hdr(const char *hdr, const void *data, size_t data_len)
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

		/* stop scan at first blank line (end of headers) */
		if (real_len == 0)
			break;

		if (!strncasecmp(hdr, p, real_len))
			return true;

		p += llen;
		len -= llen;
	}

	return false;
}

/*
 * Read a port number from a port file, fill buffer.
 * Unlike cld_readport, host is included as well, and we use strings.
 */
int tb_readport(const char *fname, char *buf, size_t len)
{
	int fd;
	char *s;
	int rc;

	if (len < 3)
		return -EDOM;
	if ((fd = open(fname, O_RDONLY)) == -1)
		return -errno;
	rc = read(fd, buf, len-1);
	close(fd);
	if (rc < 0)
		return -errno;
	if (rc == 0)
		return -EPIPE;
	buf[rc] = 0;

	s = strchr(buf, '\n');
	if (s) {
		*s = 0;
		rc = s - buf; 
	}

	return rc;
}

