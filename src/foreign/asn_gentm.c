/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* This code is borrowed from the openssl library, which conveniently
 * doesn't expose any functions for converting an ASN1_GENERALIZEDTIME
 * to a sane timestamp format.
 */

#include <stdio.h>
#include <time.h>
#include <openssl/asn1.h>

/*
 * Convert date to and from julian day Uses Fliegel & Van Flandern algorithm
 */

static void
julian_to_date(long jd, int *y, int *m, int *d)
{
	long L = jd + 68569;
	long n = (4 * L) / 146097;
	long i, j;

	L = L - (146097 * n + 3) / 4;
	i = (4000 * (L + 1)) / 1461001;
	L = L - (1461 * i) / 4 + 31;
	j = (80 * L) / 2447;
	*d = L - (2447 * j) / 80;
	L = j / 11;
	*m = j + 2 - (12 * L);
	*y = 100 * (n - 49) + i + L;
}

static long
date_to_julian(int y, int m, int d)
{
	return (1461 * (y + 4800 + (m - 14) / 12)) / 4 +
	    (367 * (m - 2 - 12 * ((m - 14) / 12))) / 12 -
	    (3 * ((y + 4900 + (m - 14) / 12) / 100)) / 4 + d - 32075;
}


#define SECS_PER_DAY (24 * 60 * 60)

/* Convert tm structure and offset into julian day and seconds */
static int
julian_adj(const struct tm *tm, int off_day, long offset_sec,
    long *pday, int *psec)
{
	int offset_hms, offset_day;
	long time_jd;
	int time_year, time_month, time_day;
	/* split offset into days and day seconds */
	offset_day = offset_sec / SECS_PER_DAY;
	/* Avoid sign issues with % operator */
	offset_hms = offset_sec - (offset_day * SECS_PER_DAY);
	offset_day += off_day;
	/* Add current time seconds to offset */
	offset_hms += tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec;
	/* Adjust day seconds if overflow */
	if (offset_hms >= SECS_PER_DAY) {
		offset_day++;
		offset_hms -= SECS_PER_DAY;
	} else if (offset_hms < 0) {
		offset_day--;
		offset_hms += SECS_PER_DAY;
	}

	/*
	 * Convert date of time structure into a Julian day number.
	 */

	time_year = tm->tm_year + 1900;
	time_month = tm->tm_mon + 1;
	time_day = tm->tm_mday;

	time_jd = date_to_julian(time_year, time_month, time_day);

	/* Work out Julian day of new date */
	time_jd += offset_day;

	if (time_jd < 0)
		return 0;

	*pday = time_jd;
	*psec = offset_hms;
	return 1;
}

static
int openssl_gmtime_adj(struct tm *tm, int off_day, long offset_sec)
{
	int time_sec, time_year, time_month, time_day;
	long time_jd;

	/* Convert time and offset into Julian day and seconds */
	if (!julian_adj(tm, off_day, offset_sec, &time_jd, &time_sec))
		return 0;

	/* Convert Julian day back to date */

	julian_to_date(time_jd, &time_year, &time_month, &time_day);

	if (time_year < 1900 || time_year > 9999)
		return 0;

	/* Update tm structure */

	tm->tm_year = time_year - 1900;
	tm->tm_mon = time_month - 1;
	tm->tm_mday = time_day;

	tm->tm_hour = time_sec / 3600;
	tm->tm_min = (time_sec / 60) % 60;
	tm->tm_sec = time_sec % 60;

	return 1;

}

static
int asn1_generalizedtime_to_tm(struct tm *tm, const ASN1_GENERALIZEDTIME *d)
{
	static const int min[9] = { 0, 0, 1, 1, 0, 0, 0, 0, 0 };
	static const int max[9] = { 99, 99, 12, 31, 23, 59, 59, 12, 59 };
	char *a;
	int n, i, l, o;

	if (d->type != V_ASN1_GENERALIZEDTIME)
		return (0);
	l = d->length;
	a = (char *)d->data;
	o = 0;
	/*
	 * GENERALIZEDTIME is similar to UTCTIME except the year is represented
	 * as YYYY. This stuff treats everything as a two digit field so make
	 * first two fields 00 to 99
	 */
	if (l < 13)
		goto err;
	for (i = 0; i < 7; i++) {
		if ((i == 6) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
			i++;
			if (tm)
				tm->tm_sec = 0;
			break;
		}
		if ((a[o] < '0') || (a[o] > '9'))
			goto err;
		n = a[o] - '0';
		if (++o > l)
			goto err;

		if ((a[o] < '0') || (a[o] > '9'))
			goto err;
		n = (n * 10) + a[o] - '0';
		if (++o > l)
			goto err;

		if ((n < min[i]) || (n > max[i]))
			goto err;
		if (tm) {
			switch (i) {
			case 0:
				tm->tm_year = n * 100 - 1900;
				break;
			case 1:
				tm->tm_year += n;
				break;
			case 2:
				tm->tm_mon = n - 1;
				break;
			case 3:
				tm->tm_mday = n;
				break;
			case 4:
				tm->tm_hour = n;
				break;
			case 5:
				tm->tm_min = n;
				break;
			case 6:
				tm->tm_sec = n;
				break;
			}
		}
	}
	/*
	 * Optional fractional seconds: decimal point followed by one or more
	 * digits.
	 */
	if (a[o] == '.') {
		if (++o > l)
			goto err;
		i = o;
		while ((o <= l) && (a[o] >= '0') && (a[o] <= '9'))
			o++;
		/* Must have at least one digit after decimal point */
		if (i == o)
			goto err;
	}

	if (a[o] == 'Z')
		o++;
	else if ((a[o] == '+') || (a[o] == '-')) {
		int offsign = a[o] == '-' ? -1 : 1, offset = 0;
		o++;
		if (o + 4 > l)
			goto err;
		for (i = 7; i < 9; i++) {
			if ((a[o] < '0') || (a[o] > '9'))
				goto err;
			n = a[o] - '0';
			o++;
			if ((a[o] < '0') || (a[o] > '9'))
				goto err;
			n = (n * 10) + a[o] - '0';
			if ((n < min[i]) || (n > max[i]))
				goto err;
			if (tm) {
				if (i == 7)
					offset = n * 3600;
				else if (i == 8)
					offset += n * 60;
			}
			o++;
		}
		if (offset && !openssl_gmtime_adj(tm, 0, offset * offsign))
			return 0;
	} else if (a[o]) {
		/* Missing time zone information. */
		goto err;
	}
	return (o == l);
err:
	return (0);
}

double
asn1_gentime_parse(const ASN1_GENERALIZEDTIME *d) {
	struct tm tm = { .tm_min = 0 };

	if (d == NULL)
		return (-1.0);

	if (asn1_generalizedtime_to_tm(&tm, d) == 0)
		return (-1.0);

	return (double) (mktime(&tm));
}
