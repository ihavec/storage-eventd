SUBDIRS = filters actions test
sbin_PROGRAMS = storage-eventd

systemdunitdir = $(SYSTEMD_UNITDIR)
systemdunit_DATA = storage-eventd.service

storage_eventd_CFLAGS  = -Wall -Werror -pthread
if DEVEL
storage_eventd_CFLAGS += -Wno-unused-variable -Wno-unused-function -DDEBUG
storage_eventd_CFLAGS += -DBASEDIR=\"$(abs_top_srcdir)\"
endif
storage_eventd_CFLAGS += $(GLIB_CFLAGS) $(UDEV_CFLAGS)
storage_eventd_CFLAGS += $(LIBCONFIG_CFLAGS) $(BLKID_CFLAGS)

storage_eventd_SOURCES = main.c \
			 common.h \
			 list.h \
			 assert.c \
			 config.c \
			 config.h \
			 uevent.c \
			 uevent.h \
			 log.c \
			 filter.c \
			 filter.h \
			 action.c \
			 action.h \
			 subst.c \
			 subst.h \
			 util.c \
			 util.h

storage_eventd_LDFLAGS  = $(UDEV_LDFLAGS) $(LIBCONFIG_LDFLAGS) $(GLIB_LDFLAGS)
storage_eventd_LDFLAGS += $(BLKID_LDFLAGS) $(UUID_LDFLAGS) -pthread
storage_eventd_LDFLAGS += -Lfilters -Lactions
storage_eventd_LDADD    = $(UDEV_LIBS) $(LIBCONFIG_LIBS) $(GLIB_LIBS)
storage_eventd_LDADD   += $(BLKID_LIBS) $(UUID_LIBS) -lfilters -lactions

noinst_LIBRARIES = libcore.a
libcore_a_SOURCES = subst.c util.c
libcore_a_CFLAGS  = $(GLIB_CFLAGS) $(UDEV_CFLAGS)
libcore_a_CFLAGS += $(LIBCONFIG_CFLAGS) $(BLKID_CFLAGS)

EXTRA_DIST = storage-eventd.service
