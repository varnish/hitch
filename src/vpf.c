/*-
 * Copyright (c) 2005 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * Derived from:
 * $FreeBSD: head/lib/libutil/pidfile.c 184091 2008-10-20 17:41:08Z des $
 */

#include "config.h"

#include <sys/param.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "flopen.h"
#include "vpf.h"

struct vpf_fh {
	int	pf_fd;
	char	pf_path[MAXPATHLEN + 1];
	dev_t	pf_dev;
	ino_t	pf_ino;
};

static int _VPF_Remove(struct vpf_fh *pfh, int freeit);

static int
vpf_verify(const struct vpf_fh *pfh)
{
	struct stat sb;

	if (pfh == NULL || pfh->pf_fd == -1)
		return (EINVAL);
	/*
	 * Check remembered descriptor.
	 */
	if (fstat(pfh->pf_fd, &sb) == -1)
		return (errno);
	if (sb.st_dev != pfh->pf_dev || sb.st_ino != pfh->pf_ino)
		return (EINVAL);
	return (0);
}

static int
vpf_read(const char *path, pid_t *pidptr)
{
	char buf[16], *endptr;
	int error, fd, i;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return (errno);

	i = read(fd, buf, sizeof(buf) - 1);
	error = errno;	/* Remember errno in case close() wants to change it. */
	(void)close(fd);
	if (i == -1)
		return (error);
	buf[i] = '\0';

	*pidptr = strtol(buf, &endptr, 10);
	if (endptr != &buf[i])
		return (EINVAL);

	return (0);
}

struct vpf_fh *
VPF_Open(const char *path, mode_t mode, pid_t *pidptr)
{
	struct vpf_fh *pfh;
	struct stat sb;
	int error, fd, len;

	pfh = malloc(sizeof(*pfh));
	if (pfh == NULL)
		return (NULL);

#if 0
	if (path == NULL)
		len = snprintf(pfh->pf_path, sizeof(pfh->pf_path),
		    "/var/run/%s.pid", getprogname());
	else
#endif
	{
		assert(path != NULL);
		len = snprintf(pfh->pf_path, sizeof(pfh->pf_path),
		    "%s", path);
	}
	if (len >= (int)sizeof(pfh->pf_path)) {
		free(pfh);
		errno = ENAMETOOLONG;
		return (NULL);
	}

	/*
	 * Open the PID file and obtain exclusive lock.
	 * We truncate PID file here only to remove old PID immediatelly,
	 * PID file will be truncated again in VPF_Write(), so
	 * VPF_Write() can be called multiple times.
	 */
	fd = flopen(pfh->pf_path,
	    O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK, mode);
	if (fd == -1) {
		if (errno == EWOULDBLOCK && pidptr != NULL) {
			errno = vpf_read(pfh->pf_path, pidptr);
			if (errno == 0)
				errno = EEXIST;
		}
		free(pfh);
		return (NULL);
	}
	/*
	 * Remember file information, so in VPF_Write() we are sure we write
	 * to the proper descriptor.
	 */
	if (fstat(fd, &sb) == -1) {
		error = errno;
		(void)unlink(pfh->pf_path);
		(void)close(fd);
		free(pfh);
		errno = error;
		return (NULL);
	}

	pfh->pf_fd = fd;
	pfh->pf_dev = sb.st_dev;
	pfh->pf_ino = sb.st_ino;

	return (pfh);
}

int
VPF_Write(struct vpf_fh *pfh)
{
	char pidstr[16];
	int error, fd;

	/*
	 * Check remembered descriptor, so we don't overwrite some other
	 * file if pidfile was closed and descriptor reused.
	 */
	errno = vpf_verify(pfh);
	if (errno != 0) {
		/*
		 * Don't close descriptor, because we are not sure if it's ours.
		 */
		return (-1);
	}
	fd = pfh->pf_fd;

	/*
	 * Truncate PID file, so multiple calls of VPF_Write() are allowed.
	 */
	if (ftruncate(fd, 0) == -1) {
		error = errno;
		(void)_VPF_Remove(pfh, 0);
		errno = error;
		return (-1);
	}

	error = snprintf(pidstr, sizeof(pidstr), "%ju", (uintmax_t)getpid());
	assert(error < (int) sizeof pidstr);
	if (pwrite(fd, pidstr, strlen(pidstr), 0) != (ssize_t)strlen(pidstr)) {
		error = errno;
		(void)_VPF_Remove(pfh, 0);
		errno = error;
		return (-1);
	}

	return (0);
}

int
VPF_Close(struct vpf_fh *pfh)
{
	int error;

	error = vpf_verify(pfh);
	if (error != 0) {
		errno = error;
		return (-1);
	}

	if (close(pfh->pf_fd) == -1)
		error = errno;
	free(pfh);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

static int
_VPF_Remove(struct vpf_fh *pfh, int freeit)
{
	int error;

	error = vpf_verify(pfh);
	if (error != 0) {
		errno = error;
		return (-1);
	}

	if (unlink(pfh->pf_path) == -1)
		error = errno;
	if (close(pfh->pf_fd) == -1) {
		if (error == 0)
			error = errno;
	}
	if (freeit)
		free(pfh);
	else
		pfh->pf_fd = -1;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

int
VPF_Remove(struct vpf_fh *pfh)
{

	return (_VPF_Remove(pfh, 1));
}
