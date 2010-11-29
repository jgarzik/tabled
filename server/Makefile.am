
INCLUDES	= -I$(top_srcdir)/include	\
		  @LIBCURL_CPPFLAGS@ @GLIB_CFLAGS@ @HAIL_CFLAGS@

sbin_PROGRAMS	= tabled tdbadm

tabled_SOURCES	= tabled.h		\
		  bucket.c cldu.c config.c metarep.c object.c replica.c \
		  server.c status.c storage.c storparse.c \
		  stor_chunk.c stor_fs.c stor_swift.c util.c
tabled_LDADD	= ../lib/libtdb.a		\
		  @HAIL_LIBS@ @PCRE_LIBS@ @GLIB_LIBS@ \
		  @CRYPTO_LIBS@ @DB4_LIBS@ @EVENT_LIBS@ @LIBCURL@ @SSL_LIBS@

tdbadm_SOURCES	= tdbadm.c
tdbadm_LDADD	= ../lib/libtdb.a @GLIB_LIBS@ @DB4_LIBS@

