SUBDIRS = src man config packaging build
EXTRA_DIST = autogen.sh
BUILT_SOURCES = $(top_srcdir)/version.m4

$(top_srcdir)/version.m4: FORCE
	$(AM_V_GEN)$(top_srcdir)/build/git-version-gen

FORCE:

rpm: dist
	rpmbuild -tb storage-eventd-@VERSION@.tar.xz
