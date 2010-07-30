dnl Process this file with autoconf 2.52+ to produce a configure script.
dnl
dnl Copyright (C) 2001 Philipp Rumpf
dnl Copyright (C) 2004 Henrique de Moraes Holschuh <hmh@debian.org>
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

AC_INIT([tabled], [0.5.1git],
        [http://hail.wiki.kernel.org/])

AC_PREREQ(2.52)
AC_CONFIG_SRCDIR([server/server.c])
AM_INIT_AUTOMAKE([gnu])
AC_CONFIG_HEADERS([tabled-config.h])

dnl Make sure anyone changing configure.ac/Makefile.am has a clue
AM_MAINTAINER_MODE

dnl Checks for programs
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AC_PROG_RANLIB
PKG_PROG_PKG_CONFIG

dnl Checks for header files.
dnl AC_HEADER_STDC
dnl AC_CHECK_HEADERS(sys/ioctl.h unistd.h)

dnl Checks for typedefs, structures, and compiler characteristics.
dnl AC_TYPE_SIZE_T
dnl AC_TYPE_PID_T

dnl -----------------------------
dnl Checks for required libraries
dnl -----------------------------
AC_CHECK_LIB(pcre, pcre_compile, PCRE_LIBS=-lpcre)
AC_CHECK_LIB(crypto, MD5_Init, CRYPTO_LIBS=-lcrypto)
AC_CHECK_LIB(ssl, SSL_new, SSL_LIBS=-lssl)
AC_CHECK_LIB(db-5.0, db_create, DB4_LIBS=-ldb-5.0,
	AC_CHECK_LIB(db-4.9, db_create, DB4_LIBS=-ldb-4.9,
	AC_CHECK_LIB(db-4.8, db_create, DB4_LIBS=-ldb-4.8,
	AC_CHECK_LIB(db-4.7, db_create, DB4_LIBS=-ldb-4.7,
	AC_CHECK_LIB(db-4.6, db_create, DB4_LIBS=-ldb-4.6,
	AC_CHECK_LIB(db-4.5, db_create, DB4_LIBS=-ldb-4.5,
	AC_CHECK_LIB(db-4.4, db_create, DB4_LIBS=-ldb-4.4,
	AC_CHECK_LIB(db-4.3, db_create, DB4_LIBS=-ldb-4.3,
  [AC_MSG_ERROR([Missing required libdb 4.x])]))))))))
AC_CHECK_LIB(event, event_base_new, EVENT_LIBS=-levent,
  [AC_MSG_ERROR([Missing required libevent])])
AC_SEARCH_LIBS(argp_parse, argp)
AC_SEARCH_LIBS(bind, socket)
PKG_CHECK_MODULES(HAIL, libhail)

dnl -------------------------------------
dnl Checks for optional library functions
dnl -------------------------------------

dnl -----------------
dnl Configure options
dnl -----------------

dnl --------------------------
dnl autoconf output generation
dnl --------------------------

AM_PATH_GLIB_2_0(2.0.0, , exit 1, gthread)
AM_PATH_XML2(2.6.0, ,
  [AC_MSG_ERROR([Missing required XML2 >= 2.6.0])])
LIBCURL_CHECK_CONFIG(, 7.10.1, ,
  [AC_MSG_ERROR([Missing required libcurl >= 7.10.1])])

AC_SUBST(PCRE_LIBS)
AC_SUBST(CRYPTO_LIBS)
AC_SUBST(SSL_LIBS)
AC_SUBST(DB4_LIBS)
AC_SUBST(EVENT_LIBS)

AC_CONFIG_FILES([doc/Makefile
		 lib/Makefile
		 include/Makefile
		 server/Makefile
		 test/Makefile
		 Makefile])
AC_OUTPUT
