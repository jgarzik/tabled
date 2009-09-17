
INCLUDES		= -I$(top_srcdir)/include	\
			  @LIBCURL_CPPFLAGS@ @GLIB_CFLAGS@ @XML_CPPFLAGS@

noinst_LIBRARIES	= libhttputil.a libtdb.a

libhttputil_a_SOURCES	= httputil.c uri.c readport.c

libtdb_a_SOURCES	= tdb.c

EXTRA_DIST =
	libhttpstor.pc.in libhttpstor-uninstalled.pc.in

LINK = $(LIBTOOL) --mode=link $(CC) $(CFLAGS) $(LDFLAGS) -o $@

lib_LTLIBRARIES		= libhttpstor.la

libhttpstor_la_SOURCES	= httpstor.c

libhttpstor_la_LDFLAGS = \
	-version-info $(LIBHTTPSTOR_CURRENT):$(LIBHTTPSTOR_REVISION):$(LIBHTTPSTOR_AGE) \
	-no-undefined \
	-export-symbols-regex "^[^_].*"

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libhttpstor.pc

