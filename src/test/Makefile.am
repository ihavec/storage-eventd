noinst_LTLIBRARIES = libtest.la
libtest_la_SOURCES = test_log.c test_util.c
libtest_la_CFLAGS = -I..

check_PROGRAMS = test_subst test_mntscan
test_subst_SOURCES = test_subst.c
test_subst_CFLAGS = $(GLIB_CFLAGS)
test_subst_LDFLAGS = $(GLIB_LDFLAGS)
test_subst_LDADD = $(GLIB_LIBS) -ltest -lcore

test_mntscan_SOURCES = test_mntscan.c
test_mntscan_CFLAGS = $(UUID_CFLAGS) $(BLKID_CFLAGS)
test_mntscan_LDFLAGS = $(UUID_LDFLAGS) $(BLKID_LDFLAGS)
test_mntscan_LDADD = $(UUID_LIBS) $(BLKID_LIBS) -ltest
