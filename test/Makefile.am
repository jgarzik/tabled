
INCLUDES	= -I$(top_srcdir)/include	\
		  @LIBCURL_CPPFLAGS@ @GLIB_CFLAGS@ @XML_CPPFLAGS@

EXTRA_DIST =			\
	test.h			\
	users.data		\
	chunkd-test.conf	\
	be_fs-test.conf		\
	tabled-test.conf	\
	prep-db			\
	start-daemon		\
	pid-exists		\
	daemon-running		\
	combo-redux		\
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
	hdr-content-type	\
	hdr-meta		\
	list-keys		\
	combo-redux		\
	stop-daemon		\
	clean-db

check_PROGRAMS		= basic-bucket basic-object it-works large-object \
			  hdr-content-type hdr-meta list-keys wait-for-listen

noinst_LIBRARIES	= libtest.a

TESTLDADD		= libtest.a \
			  @HAIL_LIBS@ @GLIB_LIBS@ \
			  @LIBCURL@ @CRYPTO_LIBS@ @XML_LIBS@
basic_bucket_LDADD	= $(TESTLDADD)
basic_object_LDADD	= $(TESTLDADD)
large_object_LDADD	= $(TESTLDADD)
hdr_content_type_LDADD	= $(TESTLDADD)
hdr_meta_LDADD		= $(TESTLDADD)
it_works_LDADD		= $(TESTLDADD)
list_keys_LDADD		= $(TESTLDADD)

wait_for_listen_LDADD	= libtest.a

TESTS_ENVIRONMENT=top_srcdir=$(top_srcdir)
