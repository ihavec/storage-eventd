#
# spec file for package storage-eventd
#
# Copyright (c) 2016 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

Name:           storage-eventd
Version:	0.1
Release:	0
License:	GPL-2.0
Summary:	A daemon for responding to storage events
Url:		https://github.com/jeffmahoney/storage-eventd/
Group:		System/Daemons
Source:		%{name}.tar.xz
BuildRequires:	automake
BuildRequires:	autoconf
BuildRequires:	libtool
BuildRequires:	libudev-devel
BuildRequires:	libconfig-devel
BuildRequires:	glib2-devel
BuildRequires:	libblkid-devel
BuildRequires:	libuuid-devel
BuildRequires:	systemd-devel
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
A daemon that allows the system adminstrator to monitor storage events
and perform configurable actions based on a number of filters.

%prep
%setup -q -n %{name}

%build
autoreconf -fiv
%configure
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot} %{?_smp_mflags}
UNITDIR="$(pkg-config --variable=systemdsystemunitdir systemd)"
echo "$UNITDIR/storage-eventd.service" > systemd.files
mkdir -p $RPM_BUILD_ROOT/usr/sbin
ln -sf /sbin/service $RPM_BUILD_ROOT/usr/sbin/rcstorage-eventd

%pre
%service_add_pre storage-eventd.service

%post
[ -f /.buildenv ] && exit 0
%service_add_post storage-eventd.service

%preun
%service_del_preun storage-eventd.service

%postun
[ -f /.buildenv ] && exit 0
%service_del_postun storage-eventd.service


%files -f systemd.files
%defattr(-,root,root)
%doc config/example.conf
%{_sbindir}/storage-eventd
%{_sbindir}/rcstorage-eventd
%{_mandir}/man5/storage-eventd.conf.5.gz
%{_mandir}/man8/storage-eventd.8.gz
%dir %{_sysconfdir}/storage-eventd
%config(noreplace) %{_sysconfdir}/storage-eventd/storage-eventd.conf
%config(noreplace) %{_sysconfdir}/storage-eventd/email-template.txt
