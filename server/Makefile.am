
INCLUDES	= -I$(top_srcdir)/include @GLIB_CFLAGS@ @CHUNKDC_CFLAGS@ @CLDC_CFLAGS@

sbin_PROGRAMS	= tabled tdbadm

tabled_SOURCES	= tabled.h		\
		  bucket.c object.c server.c storage.c cldu.c config.c util.c
tabled_LDADD	= ../lib/libhttputil.a ../lib/libtdb.a		\
		  @CHUNKDC_LIBS@ @CLDC_LIBS@ @PCRE_LIBS@ @GLIB_LIBS@ \
		  @CRYPTO_LIBS@ @DB4_LIBS@ @EVENT_LIBS@ @ARGP_LIBS@ @SSL_LIBS@

tdbadm_SOURCES	= tdbadm.c
tdbadm_LDADD	= ../lib/libtdb.a @GLIB_LIBS@ @DB4_LIBS@ @ARGP_LIBS@

