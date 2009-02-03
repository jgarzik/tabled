
INCLUDES	= -I$(top_srcdir)/include @GLIB_CFLAGS@

sbin_PROGRAMS	= tabled

tabled_SOURCES	= tabled.h		\
		  bucket.c object.c server.c util.c
tabled_LDADD	= ../lib/libhttputil.a	\
		  @PCRE_LIBS@ @GLIB_LIBS@ @CRYPTO_LIBS@ @SQLITE_LIBS@

