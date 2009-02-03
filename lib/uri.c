/*
 * Taken from GNet and modified for tabled
 */

/* GNet - Networking library
 * Copyright (C) 2000-2003  David Helder, David Bolcsfoldi, Eric Williams
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA  02111-1307, USA.
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <httputil.h>

/* our own ISSPACE.  ANSI isspace is locale dependent */
#define ISSPACE(C) (((C) >= 9 && (C) <= 13) || (C) == ' ')

#define ASSIGN(token, ptr, len)			\
	do {					\
		uri->token = (ptr);		\
		uri->token##_len = (len);	\
	} while (0)

struct uri *uri_parse(struct uri *uri, char *uri_text)
{
	char *p, *temp;

	memset(uri, 0, sizeof(*uri));

	/* Skip initial whitespace */
	p = uri_text;
	while (*p && ISSPACE((int)*p))
		++p;
	if (!*p)		/* Error if it's just a string of space */
		return NULL;

	/* Scheme */
	temp = p;
	while (*p && *p != ':' && *p != '/' && *p != '?' && *p != '#')
		++p;
	if (*p == ':') {
		ASSIGN(scheme, temp, p - temp);
		++p;
	} else			/* This char is NUL, /, ?, or # */
		p = temp;

	/* Authority */
	if (*p == '/' && p[1] == '/') {
		p += 2;

		/* Userinfo */
		temp = p;
		while (*p && *p != '@' && *p != '/')	/* Look for @ or / */
			++p;
		if (*p == '@') {	/* Found userinfo */
			ASSIGN(userinfo, temp, p - temp);
			++p;
		} else
			p = temp;

		/* Hostname */

		/* Check for no hostname at all (e.g. file:// URIs) */
		if (*p == '/')
			goto path;

		/* Check for IPv6 canonical hostname in brackets */
		if (*p == '[') {
			p++;	/* Skip [ */
			temp = p;
			while (*p && *p != ']')
				++p;
			if ((p - temp) == 0)
				goto error;
			ASSIGN(hostname, temp, p - temp);
			if (*p)
				p++;	/* Skip ] (if there) */
		} else {
			temp = p;
			while (*p && *p != '/' && *p != '?' && *p != '#'
			       && *p != ':')
				++p;
			if ((p - temp) == 0)
				goto error;
			ASSIGN(hostname, temp, p - temp);
		}

		/* Port */
		if (*p == ':') {
			for (++p; isdigit((int)*p); ++p)
				uri->port = uri->port * 10 + (*p - '0');
		}

	}

	/* Path (we are liberal and won't check if it starts with /) */

path:
	temp = p;
	while (*p && *p != '?' && *p != '#')
		++p;
	if (p != temp)
		ASSIGN(path, temp, p - temp);

	/* Query */
	if (*p == '?') {
		temp = p + 1;
		while (*p && *p != '#')
			++p;
		ASSIGN(query, temp, p - temp);
	}

	/* Fragment */
	if (*p == '#') {
		++p;
		uri->fragment = p;
		/* FIXME: assign uri->fragment_len! */
	}

	return uri;

error:
	return NULL;
}

int field_unescape(char *s, int s_len)
{
	int dst_len = 0;
	char *src;
	char *dst;

	for (src = dst = s; s_len; ++src, ++dst, ++dst_len, --s_len) {
		if (src[0] == '%' && (s_len > 2)) {
			int high, low;

			if ('a' <= src[1] && src[1] <= 'f')
				high = src[1] - 'a' + 10;
			else if ('A' <= src[1] && src[1] <= 'F')
				high = src[1] - 'A' + 10;
			else if ('0' <= src[1] && src[1] <= '9')
				high = src[1] - '0';
			else	/* malformed */
				goto regular_copy;

			if ('a' <= src[2] && src[2] <= 'f')
				low = src[2] - 'a' + 10;
			else if ('A' <= src[2] && src[2] <= 'F')
				low = src[2] - 'A' + 10;
			else if ('0' <= src[2] && src[2] <= '9')
				low = src[2] - '0';
			else	/* malformed */
				goto regular_copy;

			*dst = (char)((high << 4) + low);
			src += 2;
			s_len -= 2;
		} else {
regular_copy:
			/* micro-opt: a lot of URIs do not include escape
			 * sequences.  by testing the pointer addresses
			 * we can avoid a lot of reading+writing of the
			 * same data
			 */
			if (dst != src)
				*dst = *src;
		}
	}

	return dst_len;
}

static const guchar neednt_escape_table[] =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x0f, 0x00, 0x00, 0x0f, 0x00, 0x0f, 0x0f,
	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0e,
	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
	0x0f, 0x0f, 0x0f, 0x0f, 0x00, 0x0f, 0x00, 0x0c,
	0x0e, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
	0x0f, 0x0f, 0x0f, 0x00, 0x0f, 0x00, 0x00, 0x0f,
	0x00, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
	0x0f, 0x0f, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

char* field_escape (char *signed_str, unsigned char mask)
{
  int len;
  int i;
  bool must_escape = false;
  unsigned char *str;
  char *dst;
  gint j;

  str = (unsigned char *) signed_str;

  if (str == NULL)
    return NULL;

  /* Roughly calculate buffer size */
  len = 0;
  for (i = 0; str[i]; i++)
    {
      if (neednt_escape_table[str[i]] & mask)
	len++;
      else
	{
	  len += 3;
	  must_escape = TRUE;
	}
    }

  /* Don't escape if unnecessary */
  if (must_escape == FALSE)
    return signed_str;

  /* Allocate buffer */
  dst = (gchar*) g_malloc(len + 1);

  /* Copy */
  for (i = j = 0; str[i]; i++, j++)
    {
      /* Unescaped character */
      if (neednt_escape_table[str[i]] & mask)
	{
	  dst[j] = str[i];
	}

      /* Escaped character */
      else
	{
	  dst[j] = '%';

	  if (((str[i] & 0xf0) >> 4) < 10)
	    dst[j+1] = ((str[i] & 0xf0) >> 4) + '0';
	  else
	    dst[j+1] = ((str[i] & 0xf0) >> 4) + 'a' - 10;

	  if ((str[i] & 0x0f) < 10)
	    dst[j+2] = (str[i] & 0x0f) + '0';
	  else
	    dst[j+2] = (str[i] & 0x0f) + 'a' - 10;

	  j += 2;  /* and j is incremented in loop too */
	}
    }
  dst[j] = '\0';

  g_free (signed_str);
  return dst;
}

