
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

#define _GNU_SOURCE
#include "tabled-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <glib.h>
#include <event.h>
#include "tabled.h"

static const char stor_key_fmt[] = STOR_KEY_FMT;

static char *fs_obj_pathname(const char *base, uint64_t key)
{
	enum { PREFIX_LEN = 3 };
	char prefix[PREFIX_LEN + 1];
	char stckey[STOR_KEY_SLEN+1];
	char *s;
	int rc;

	/* we know that stckey is going to be longer than PREFIX_LEN */
	sprintf(stckey, stor_key_fmt, (unsigned long long) key);
	memcpy(prefix, stckey, PREFIX_LEN);
	prefix[PREFIX_LEN] = 0;

	rc = asprintf(&s, "%s/%s/%s", base, prefix, stckey + PREFIX_LEN);
	if (rc < 0)
		goto err_out;

	return s;

err_out:
	return NULL;
}

static char *fs_ctl_pathname(const char *base, const char *file)
{
	char *s;
	int rc;

	rc = asprintf(&s, "%s/%s", base, file);
	if (rc < 0)
		return NULL;
	return s;
}

static int fs_obj_mkpath(const char *path)
{
	struct stat statb;
	char *s;
	int rc;

	/* one dir is enough */
	/* not using dirname because on some platforms it modifies its arg. */
	s = strrchr(path, '/');
	if (s == NULL)
		return -EINVAL;
	s = strndup(path, s-path);
	if (!s)
		return -ENOMEM;

	/* create subdir on the fly, if not already exists */
	if (stat(s, &statb) < 0) {
		rc = errno;
		if (rc != ENOENT)
			goto err_out;
		if (mkdir(s, 0777) < 0) {
			rc = errno;
			/*
			 * Directory already exists, perhaps
			 * because we raced with another thread.
			 */
			if (rc != EEXIST)
				goto err_out;
		}
	} else {
		if (!S_ISDIR(statb.st_mode)) {
			rc = EINVAL;
			goto err_out;
		}
	}

	free(s);
	return 0;

err_out:
	free(s);
	return -rc;
}

static int fs_open(struct open_chunk *cep, struct storage_node *stn,
		   struct event_base *ev_base)
{
	if (cep->node)
		return -EBUSY;

	if (!stn->basepath) {
		applog(LOG_WARNING,
		       "No base path for Posix chunk, nid %u", stn->id);
		return -EINVAL;
	}

	cep->evbase = ev_base;
	cep->node = stor_node_get(stn);
	cep->pfd = -1;

	return 0;
}

static int fs_open_read(struct open_chunk *cep,
			void (*cb)(struct open_chunk *),
			uint64_t key, uint64_t *psize)
{
	char *objpath;
	struct stat statb;
	uint64_t size;
	int rc;

	if (!cep->node || cep->key)
		return -EBUSY;

	objpath = fs_obj_pathname(cep->node->basepath, key);
	if (!objpath) {
		applog(LOG_WARNING, "No core");
		return -ENOMEM;
	}

	rc = open(objpath, O_RDONLY);
	if (rc == -1) {
		rc = errno;
		applog(LOG_WARNING, "Cannot open file %s oid %llX: %s",
		       objpath, (long long) key, strerror(rc));
		free(objpath);
		return -rc;
	}
	cep->pfd = rc;

	if (fstat(cep->pfd, &statb) < 0) {
		rc = errno;
		applog(LOG_WARNING, "Cannot stat file %s: %s",
		       objpath, strerror(rc));
		close(cep->pfd);
		cep->pfd = -1;
		free(objpath);
		return -rc;
	}
	size = statb.st_size;

	*psize = size;
	cep->size = size;
	cep->done = 0;
	cep->key = key;
	cep->ocb = cb;

	/*
	 * We cannot call cep->ocb directly. Instead, we steal the
	 * arm-disarm mechanism from chunk. This works because in Linux
	 * regular files can be polled and always return ready.
	 */
	event_set(&cep->revt, cep->pfd, EV_READ, stor_read_event, cep);
	event_base_set(cep->evbase, &cep->revt);

	free(objpath);
	return 0;
}

static void fs_close(struct open_chunk *cep)
{
	if (cep->node) {
		stor_node_put(cep->node);
		cep->node = NULL;
		if (cep->pfd != -1) {
			close(cep->pfd);
			cep->pfd = -1;
		}
	}

	cep->done = 0;
	cep->size = 0;

	if (cep->r_armed) {
		event_del(&cep->revt);
		cep->r_armed = false;
	}

	if (cep->w_armed) {
		event_del(&cep->wevt);
		cep->w_armed = false;
	}

	cep->key = 0;
}

static void fs_abort(struct open_chunk *cep)
{
	if (cep->r_armed) {
		event_del(&cep->revt);
		cep->r_armed = false;
	}
	if (cep->w_armed) {
		event_del(&cep->wevt);
		cep->w_armed = false;
	}
	/* XXX delete the unfinished object under write */
	cep->key = 0;
}

static int fs_put_start(struct open_chunk *cep,
			void (*cb)(struct open_chunk *),
			uint64_t key, uint64_t size)
{
	char *objpath;
	int rc;

	if (!cep->node || cep->key)
		return -EBUSY;

	objpath = fs_obj_pathname(cep->node->basepath, key);
	if (!objpath) {
		applog(LOG_WARNING, "No core");
		return -ENOMEM;
	}

	rc = fs_obj_mkpath(objpath);
	if (rc) {
		applog(LOG_WARNING, "Cannot create a directory for %s: %s",
		       objpath, strerror(-rc));
		free(objpath);
		return rc;
	}

	rc = open(objpath, O_WRONLY|O_TRUNC|O_CREAT, 0666);
	if (rc == -1) {
		rc = errno;
		applog(LOG_WARNING, "Cannot create file %s: %s",
		       objpath, strerror(rc));
		free(objpath);
		return -rc;
	}
	cep->pfd = rc;

	cep->size = size;
	cep->done = 0;
	cep->key = key;
	cep->ocb = cb;
	event_set(&cep->wevt, cep->pfd, EV_WRITE, stor_write_event, cep);
	event_base_set(cep->evbase, &cep->wevt);

	free(objpath);
	return 0;
}

static ssize_t fs_put_buf(struct open_chunk *cep, void *data, size_t len)
{
	ssize_t rcs;

	if (len == 0) {
		applog(LOG_ERR, "Put length zero remaining %ld",
		       cep->size - cep->done);
		return -EIO;		/* will spin otherwise, better error */
	}

	if (cep->done + len > cep->size) {
		/* P3 */ applog(LOG_ERR, "Put length %ld remaining %ld",
		       (long) len, (long) (cep->size - cep->done));
		if (cep->done == cep->size)
			return -EIO;	/* will spin otherwise, better error */
		len = cep->size - cep->done;
	}

	if (!cep->node)
		return -EPIPE;

	rcs = write(cep->pfd, data, len);
	if (rcs < 0)
		return -errno;

	if (!cep->w_armed) {
		event_add(&cep->wevt, NULL);
		cep->w_armed = true;
	}

	cep->done += rcs;
	if (rcs < len)
		return rcs;

	return len;
}

static bool fs_put_end(struct open_chunk *cep)
{
	if (!cep->node)
		return true;
	if (cep->pfd != -1) {
		if (fdatasync(cep->pfd) != 0)
			return false;
		close(cep->pfd);
		cep->pfd = -1;
	}
	if (cep->w_armed) {
		event_del(&cep->wevt);
		cep->w_armed = false;
	}
	return true;
}

static ssize_t fs_get_buf(struct open_chunk *cep, void *data, size_t req_len)
{
	size_t xfer_len;
	ssize_t rcs;

	if (!cep->node)
		return -EDOM;

	if (cep->done + req_len < cep->done)	/* wrap */
		return -EINVAL;
	if (cep->done + req_len > cep->size)
		xfer_len = cep->size - cep->done;
	else
		xfer_len = req_len;
	if (xfer_len == 0)
		return 0;

	rcs = read(cep->pfd, data, xfer_len);
	if (rcs < 0)
		return -errno;

	cep->done += rcs;
	if (cep->done == cep->size) {
		cep->done = 0;
		cep->size = 0;
		close(cep->pfd);
		cep->pfd = -1;
		if (cep->r_armed) {
			event_del(&cep->revt);
			cep->r_armed = false;
		}
		return rcs;
	}

	if (xfer_len != rcs && cep->size && !cep->r_armed) {
		cep->r_armed = true;
		if (event_add(&cep->revt, NULL))
			cep->r_armed = false;
	}

	return rcs;
}

static int fs_obj_del(struct storage_node *stn, uint64_t key)
{
	char *objpath;
	int rc;

	objpath = fs_obj_pathname(stn->basepath, key);
	if (!objpath) {
		applog(LOG_WARNING, "No core");
		return -ENOMEM;
	}

	if (unlink(objpath) != 0) {
		rc = errno;
		applog(LOG_WARNING, "Cannot unlink oid %llX file %s: %s",
		       (long long)key, objpath, strerror(rc));
		free(objpath);
		return -rc;
	}

	free(objpath);
	return 0;
}

static bool fs_obj_test(struct open_chunk *cep, uint64_t key)
{
	struct stat statb;
	char *objpath;

	objpath = fs_obj_pathname(cep->node->basepath, key);
	if (!objpath) {
		applog(LOG_WARNING, "No core");
		return false;
	}

	if (stat(objpath, &statb) != 0) {
		applog(LOG_WARNING, "Cannot stat oid %llX file %s: %s",
		       (long long)key, objpath, strerror(errno));
		free(objpath);
		return false;
	}

	free(objpath);
	return true;
}

static long stor_readnid(const char *fname)
{
	enum { LEN = 45 };
	char buf[LEN+1];
	long num;
	int fd;
	int rc;

	if ((fd = open(fname, O_RDONLY)) == -1)
		return -errno;
	rc = read(fd, buf, LEN);
	close(fd);
	if (rc < 0)
		return -errno;
	if (rc == 0)
		return -EPIPE;
	buf[rc] = 0;

	num = strtol(buf, NULL, 10);
	if (num < INT_MIN || num > INT_MAX)
		return -ERANGE;

	return num;
}

static int fs_node_check(struct storage_node *stn)
{
	char *objpath;
	long rcl;

	if (!stn->basepath)
		return -1;

	objpath = fs_ctl_pathname(stn->basepath, "NID");
	if (!objpath) {
		applog(LOG_WARNING, "No core");
		return -1;
	}

	rcl = stor_readnid(objpath);
	if (rcl < 0) {
		if (!stn->reported) {
			applog(LOG_ERR, "Cannot verify nid %u path %s: %s",
			       stn->id, objpath, strerror(-rcl));
			stn->reported = true;
		}
		free(objpath);
		return -1;
	}

	/*
	 * This prevents a catastrophy of two entries in CLD pointing
	 * to the same directory. Happens way easier than one expects.
	 */
	if (stn->id != rcl) {
		if (!stn->reported) {
			applog(LOG_ERR, "Mismatch nid %u fetched %u",
			       stn->id, rcl);
			stn->reported = true;
		}
		free(objpath);
		return -1;
	}

	free(objpath);
	return 0;
}

struct st_node_ops stor_ops_posix = {
	.open =		fs_open,
	.open_read =	fs_open_read,
	.close =	fs_close,
	.abort =	fs_abort,
	.put_start =	fs_put_start,
	.put_buf =	fs_put_buf,
	.put_end =	fs_put_end,
	.get_buf =	fs_get_buf,
	.obj_del =	fs_obj_del,
	.obj_test =	fs_obj_test,
	.node_check =	fs_node_check,
};

