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

m4_define([libhttpstor_major_version], [1])
m4_define([libhttpstor_minor_version], [1])
m4_define([libhttpstor_micro_version], [1])
m4_define([libhttpstor_interface_age], [1])
# If you need a modifier for the version number. 
# Normally empty, but can be used to make "fixup" releases.
m4_define([libhttpstor_extraversion], [])

dnl libtool versioning from libhttpstor
m4_define([libhttpstor_current], [m4_eval(100 * libhttpstor_minor_version + libhttpstor_micro_version - libhttpstor_interface_age)])
m4_define([libhttpstor_binary_age], [m4_eval(100 * libhttpstor_minor_version + libhttpstor_micro_version)])
m4_define([libhttpstor_revision], [libhttpstor_interface_age])
m4_define([libhttpstor_age], [m4_eval(libhttpstor_binary_age - libhttpstor_interface_age)])
m4_define([libhttpstor_version], [libhttpstor_major_version().libhttpstor_minor_version().libhttpstor_micro_version()libhttpstor_extraversion()])

AC_INIT([tabled], [0.4],
        [http://hail.wiki.kernel.org/])

AC_PREREQ(2.52)
AC_CONFIG_SRCDIR([server/server.c])
AM_INIT_AUTOMAKE([gnu])
AC_CONFIG_HEADERS([tabled-config.h])

LIBHTTPSTOR_MAJOR_VERSION=libhttpstor_major_version
LIBHTTPSTOR_MINOR_VERSION=libhttpstor_minor_version
LIBHTTPSTOR_MICRO_VERSION=libhttpstor_micro_version
LIBHTTPSTOR_INTERFACE_AGE=libhttpstor_interface_age

LIBHTTPSTOR_CURRENT=libhttpstor_current
LIBHTTPSTOR_REVISION=libhttpstor_revision
LIBHTTPSTOR_AGE=libhttpstor_age

AC_SUBST(LIBHTTPSTOR_CURRENT)
AC_SUBST(LIBHTTPSTOR_REVISION)
AC_SUBST(LIBHTTPSTOR_AGE)

dnl Make sure anyone changing configure.ac/Makefile.am has a clue
AM_MAINTAINER_MODE

dnl Checks for programs
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AM_PROG_LIBTOOL
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
AC_CHECK_LIB(db-4.7, db_create, DB4_LIBS=-ldb-4.7,
	AC_CHECK_LIB(db-4.6, db_create, DB4_LIBS=-ldb-4.6,
	AC_CHECK_LIB(db-4.5, db_create, DB4_LIBS=-ldb-4.5,
	AC_CHECK_LIB(db-4.4, db_create, DB4_LIBS=-ldb-4.4,
	AC_CHECK_LIB(db-4.3, db_create, DB4_LIBS=-ldb-4.3,
  [AC_MSG_ERROR([Missing required libdb 4.x])])))))
AC_CHECK_LIB(event, event_base_new, EVENT_LIBS=-levent,
  [AC_MSG_ERROR([Missing required libevent])])
AC_CHECK_LIB(argp, argp_parse, ARGP_LIBS=-largp)
PKG_CHECK_MODULES(CHUNKDC, libchunkdc)
PKG_CHECK_MODULES(CLDC, libcldc)

dnl -------------------------------------
dnl Checks for optional library functions
dnl -------------------------------------

dnl -----------------
dnl Configure options
dnl -----------------

dnl --------------------------
dnl autoconf output generation
dnl --------------------------

AM_PATH_GLIB_2_0(2.0.0)
AM_PATH_XML2(2.6.0, ,
  [AC_MSG_ERROR([Missing required XML2 >= 2.6.0])])
LIBCURL_CHECK_CONFIG(, 7.10.1, ,
  [AC_MSG_ERROR([Missing required libcurl >= 7.10.1])])

AC_SUBST(PCRE_LIBS)
AC_SUBST(CRYPTO_LIBS)
AC_SUBST(SSL_LIBS)
AC_SUBST(DB4_LIBS)
AC_SUBST(EVENT_LIBS)
AC_SUBST(ARGP_LIBS)
dnl PKG_CHECK_MODULES has AC_SUBST inside?
dnl AC_SUBST(CHUNKDC_LIBS)

AC_CONFIG_FILES([doc/Makefile
		 lib/Makefile
		 lib/libhttpstor.pc
		 lib/libhttpstor-uninstalled.pc
		 include/Makefile
		 server/Makefile
		 test/Makefile
		 Makefile])
AC_OUTPUT
