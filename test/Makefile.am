
INCLUDES	= -I$(top_srcdir)/include	\
		  @LIBCURL_CPPFLAGS@ @GLIB_CFLAGS@ @XML_CPPFLAGS@

EXTRA_DIST =			\
	test.h			\
	users.data		\
	chunkd-test.conf	\
	tabled-test.conf	\
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
	wait-for-listen		\
	it-works		\
	basic-bucket		\
	basic-object		\
	large-object		\
	stop-daemon		\
	clean-db

check_PROGRAMS		= basic-bucket basic-object it-works large-object \
			  wait-for-listen

TESTLDADD		= ../lib/libhttpstor.la	\
			  ../lib/libhttputil.a	\
			  @LIBCURL@ @GLIB_LIBS@ @CRYPTO_LIBS@ @XML_LIBS@
basic_bucket_LDADD	= $(TESTLDADD)
basic_object_LDADD	= $(TESTLDADD)
large_object_LDADD	= $(TESTLDADD)
it_works_LDADD		= $(TESTLDADD)

wait_for_listen_LDADD	= ../lib/libhttputil.a

TESTS_ENVIRONMENT=top_srcdir=$(top_srcdir)
