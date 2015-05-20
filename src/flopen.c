/*-
 * Copyright (c) 2007 Dag-Erling Coïdan Smørgrav
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * Derived from:
 * $FreeBSD: head/lib/libutil/flopen.c 184094 2008-10-20 18:11:30Z des $
 */

#include "config.h"

#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "flopen.h"

int
flopen(const char *path, int flags, ...)
{
	int fd, operation, serrno, trunc;
	struct flock lock;
	struct stat sb, fsb;
	mode_t mode;

#ifdef O_EXLOCK
	flags &= ~O_EXLOCK;
#endif

	mode = 0;
	if (flags & O_CREAT) {
		va_list ap;

		va_start(ap, flags);
		mode = (mode_t)va_arg(ap, int); /* mode_t promoted to int */
		va_end(ap);
	}

	memset(&lock, 0, sizeof lock);
	lock.l_type = ((flags & O_ACCMODE) == O_RDONLY) ? F_RDLCK : F_WRLCK;
	lock.l_whence = SEEK_SET;
	operation = (flags & O_NONBLOCK) ? F_SETLK : F_SETLKW;

	trunc = (flags & O_TRUNC);
	flags &= ~O_TRUNC;

	for (;;) {
		if ((fd = open(path, flags, mode)) == -1)
			/* non-existent or no access */
			return (-1);
		if (fcntl(fd, operation, &lock) == -1) {
			/* unsupported or interrupted */
			serrno = errno;
			(void)close(fd);
			errno = serrno;
			return (-1);
		}
		if (stat(path, &sb) == -1) {
			/* disappeared from under our feet */
			(void)close(fd);
			continue;
		}
		if (fstat(fd, &fsb) == -1) {
			/* can't happen [tm] */
			serrno = errno;
			(void)close(fd);
			errno = serrno;
			return (-1);
		}
		if (sb.st_dev != fsb.st_dev ||
		    sb.st_ino != fsb.st_ino) {
			/* changed under our feet */
			(void)close(fd);
			continue;
		}
		if (trunc && ftruncate(fd, 0) != 0) {
			/* can't happen [tm] */
			serrno = errno;
			(void)close(fd);
			errno = serrno;
			return (-1);
		}
		return (fd);
	}
}

/* Tests if the given fd is locked through flopen
 * If pid is non-NULL, stores the pid of the process holding the lock there
 * Returns 1 if the file is locked
 * Returns 0 if the file is unlocked
 * Returns -1 on error (and errno)
 */
int
fltest(int fd, pid_t *pid)
{
	struct flock lock;

	memset(&lock, 0, sizeof lock);
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;

	if (fcntl(fd, F_GETLK, &lock) == -1)
		return (-1);
	if (lock.l_type == F_UNLCK)
		return (0);
	if (pid != NULL)
		*pid = lock.l_pid;
	return (1);
}
