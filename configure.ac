AC_INIT(storage-eventd, 0.1)
LT_INIT
AM_INIT_AUTOMAKE

AC_ARG_ENABLE([devel],
[  --enable-devel    Turn on development mode, silences some build warnings that get in the way],
[case "${enableval}" in
  yes) devel=true ; CFLAGS="-O0 -ggdb" ;;
  no)  devel=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-devel]) ;;
esac],[devel=false])
AM_CONDITIONAL([DEVEL], [test x$devel = xtrue])

AC_PROG_CC
AM_PROG_CC_C_O
LT_INIT()

PKG_CHECK_MODULES(UDEV, libudev)
PKG_CHECK_MODULES(LIBCONFIG, libconfig)
PKG_CHECK_MODULES(GLIB, glib-2.0)
PKG_CHECK_MODULES(BLKID, blkid)
PKG_CHECK_MODULES(UUID, uuid)
PKG_CHECK_MODULES(SYSTEMD, systemd)
PKG_CHECK_VAR([SYSTEMD_UNITDIR], [systemd], [systemdsystemunitdir])

AC_OUTPUT(Makefile src/Makefile src/filters/Makefile \
	  src/actions/Makefile man/Makefile src/test/Makefile \
	  config/Makefile)
