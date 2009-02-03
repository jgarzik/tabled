
INCLUDES	= -I$(top_srcdir)/include	\
		  @LIBCURL_CPPFLAGS@ @GLIB_CFLAGS@ @XML_CPPFLAGS@

EXTRA_DIST =			\
	test.h			\
	prep-db			\
	start-daemon		\
	pid-exists		\
	daemon-running		\
	stop-daemon		\
	clean-db

TESTS =				\
	prep-db			\
	start-daemon		\
	pid-exists		\
	daemon-running		\
	it-works		\
	basic-bucket		\
	basic-object		\
	stop-daemon		\
	clean-db

check_PROGRAMS		= basic-bucket basic-object it-works

TESTLDADD		= ../lib/libs3c.a	\
			  ../lib/libhttputil.a	\
			  @LIBCURL@ @GLIB_LIBS@ @CRYPTO_LIBS@ @XML_LIBS@
basic_bucket_LDADD	= $(TESTLDADD)
basic_object_LDADD	= $(TESTLDADD)
it_works_LDADD		= $(TESTLDADD)

TESTS_ENVIRONMENT=top_srcdir=$(top_srcdir)
