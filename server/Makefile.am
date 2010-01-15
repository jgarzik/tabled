
INCLUDES	= -I$(top_srcdir)/include @GLIB_CFLAGS@ @CHUNKDC_CFLAGS@ @CLDC_CFLAGS@

sbin_PROGRAMS	= tabled tdbadm

tabled_SOURCES	= tabled.h		\
		  bucket.c cldu.c config.c object.c replica.c \
		  server.c status.c storage.c storparse.c util.c
tabled_LDADD	= ../lib/libhttputil.a ../lib/libtdb.a		\
		  @CHUNKDC_LIBS@ @CLDC_LIBS@ @PCRE_LIBS@ @GLIB_LIBS@ \
		  @CRYPTO_LIBS@ @DB4_LIBS@ @EVENT_LIBS@ @SSL_LIBS@

tdbadm_SOURCES	= tdbadm.c
tdbadm_LDADD	= ../lib/libtdb.a @GLIB_LIBS@ @DB4_LIBS@

