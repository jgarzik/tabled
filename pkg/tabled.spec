Name:		tabled
Version:	0.3
Release:	0.8.g0b3ec75c%{?dist}
Summary:	Distributed key/value table service

Group:		System Environment/Base
License:	GPLv2
URL:		http://hail.wiki.kernel.org/

# pulled from upstream git, commit 0b3ec75c239e231ee2af8252466ec4fd9da2bd7c
# to recreate tarball, check out commit, then run "make dist"
Source0:	tabled-%{version}git.tar.gz
Source2:	tabled.init
Source3:	tabled.sysconf
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

# N.B. We need chunkd and cld to build, because our "make check" spawns
# private copies of infrastructure daemons.
BuildRequires:	db4-devel libevent-devel glib2-devel pcre-devel
BuildRequires:	chunkd chunkd-devel cld cld-devel libcurl-devel
BuildRequires:	procps

# chunkd is broken on big-endian... embarrassing!!!
# FIXME: remove this when chunkd is fixed
ExcludeArch:	ppc ppc64

%description
tabled provides an infinitely scalable, lexicographically sorted
key/value lookup table. Keys cannot exceed 1024 bytes; values can be
any size, including several gigabytes or more.

tabled user interface is HTTP REST, and is intended to be compatible with
existing Amazon S3 clients.

%package devel
Summary: Development files for %{name}
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}
Requires: pkgconfig

%description devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.

%prep
%setup -q -n %{name}-%{version}git


%build
%configure --disable-static
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

mkdir -p %{buildroot}%{_initddir}
install -m 755 %{SOURCE2} %{buildroot}%{_initddir}/tabled

mkdir -p %{buildroot}%{_sysconfdir}/sysconfig
install -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/sysconfig/tabled

find %{buildroot} -name '*.la' -exec rm -f {} ';'

%check
make -s check

%clean
rm -rf %{buildroot}

%post
/sbin/ldconfig
# must be in chkconfig on
/sbin/chkconfig --add tabled

%preun
if [ "$1" = 0 ] ; then
	/sbin/service tabled stop >/dev/null 2>&1 ||:
	/sbin/chkconfig --del tabled
fi

%postun
/sbin/ldconfig
if [ "$1" -ge "1" ]; then
	/sbin/service tabled condrestart >/dev/null 2>&1 ||:
fi

%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING LICENSE README NEWS doc/*.txt
%{_sbindir}/tabled
%{_sbindir}/tdbadm
%{_libdir}/*.so.*
%attr(0755,root,root)	%{_initddir}/tabled
%config(noreplace)	%{_sysconfdir}/sysconfig/tabled

%files devel
%defattr(-,root,root,-)
%{_libdir}/lib*.so
%{_libdir}/pkgconfig/*
%{_includedir}/*

%changelog
* Wed Jul 29 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.8.g0b3ec75c
- update to git commit 0b3ec75c239e231ee2af8252466ec4fd9da2bd7c

* Sun Jul 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.3-0.7.gebb1144c
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Thu Jul 23 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.6.gebb1144c
- update to git commit ebb1144ceefd7a936acafc79c6e274095bd0bb06
- BuildRequires: procps

* Tue Jul 21 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.5.g8102bcda
- rebuild for koji silliness

* Tue Jul 21 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.4.g8102bcda
- update to git commit 8102bcda428a9c2d9647d33f21ede6764a514c6e

* Tue Jul 21 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.3.g6f015fa5
- BuildRequires: libcurl-devel

* Sun Jul 19 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.2.g6f015fa5
- update to git commit 6f015fa5f920da809d66e57515672b26d0e82b89
- expanded description
- describe source tarball regen, per pkg guidelines

* Fri Jul 17 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.1.g2783d260
- new release version scheme

* Thu Jul 16 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-5
- chkconfig default off
- add docs: COPYING, LICENSE
- config(noreplace) sysconfig/tabled

* Thu Jul 16 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-4
- minor spec updates for review feedback, Fedora packaging guidelines

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-3
- rename lib to libhttpstor

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-2
- package and ship libs3c

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-1
- initial release

