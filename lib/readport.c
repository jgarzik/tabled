#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * Read a port number from a port file, fill buffer.
 * Unlike cld_readport, host is included as well, and we use strings.
 */
int tb_readport(const char *fname, char *buf, size_t len)
{
	long port;
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

