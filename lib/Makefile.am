
INCLUDES		= -I$(top_srcdir)/include	\
			  @LIBCURL_CPPFLAGS@ @GLIB_CFLAGS@ @XML_CPPFLAGS@

noinst_LIBRARIES	= libhttputil.a libtdb.a

libhttputil_a_SOURCES	= httputil.c uri.c

libtdb_a_SOURCES	= tdb.c

EXTRA_DIST =
	libs3c.pc.in libs3c-uninstalled.pc.in

LINK = $(LIBTOOL) --mode=link $(CC) $(CFLAGS) $(LDFLAGS) -o $@

lib_LTLIBRARIES		= libs3c.la

libs3c_la_SOURCES	= s3c.c

libs3c_la_LDFLAGS = \
	-version-info $(LIBS3C_CURRENT):$(LIBS3C_REVISION):$(LIBS3C_AGE) \
	-no-undefined \
	-export-symbols-regex "^[^_].*"

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libs3c.pc

