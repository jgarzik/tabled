
INCLUDES	= -I$(top_srcdir)/include @GLIB_CFLAGS@

sbin_PROGRAMS	= tabled tdbadm

tabled_SOURCES	= tabled.h		\
		  bucket.c object.c server.c config.c util.c
tabled_LDADD	= ../lib/libhttputil.a ../lib/libtdb.a		\
		  @PCRE_LIBS@ @GLIB_LIBS@ @CRYPTO_LIBS@ @DB4_LIBS@ \
		  @EVENT_LIBS@ @ARGP_LIBS@

tdbadm_SOURCES	= tdbadm.c
tdbadm_LDADD	= ../lib/libtdb.a @GLIB_LIBS@ @DB4_LIBS@ @ARGP_LIBS@

