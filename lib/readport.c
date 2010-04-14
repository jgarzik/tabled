
/*
 * Copyright 2009 Red Hat, Inc.
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <httputil.h>

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

